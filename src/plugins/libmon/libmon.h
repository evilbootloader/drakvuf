#ifndef _INCLUDE_LIBMON
#define _INCLUDE_LIBMON

#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "plugins/plugins_ex.h"
#include "plugins/helpers/return_tracker.h"
#include "libusermode-linux/dl_rendezvous.hpp"
#include "libusermode-linux/utils.hpp"
#include "module_map.hpp"

struct libmon_config
{
    const char* so_hooks_list;
    bool print_no_addr;

    // Skip return hooks. Each is a second breakpoint per call, placed and torn
    // down as the call runs, so on a hot function the cost is real; without
    // them ReturnValue is absent and events are reported at entry instead.
    bool no_retval;
};

// Linux counterpart to apimon: logs calls to configured exported functions in
// shared objects loaded by guest processes. Library discovery is delegated to
// dl_rendezvous; libmon resolves the wanted symbols in each newly mapped .so
// and breakpoints them.
class libmon : public pluginex
{
public:
    libmon(drakvuf_t drakvuf, const libmon_config* c, output_format_t output);

    // Logs what arming cost, in debug builds only. The arming tick hooks
    // every user page fault in the guest while any process is waiting, so on
    // a guest that starts processes constantly it may be installed for most
    // of a run -- worth measuring on a real workload rather than guessing at,
    // but a diagnostic rather than something to put in the event stream.
    bool stop_impl() override;

private:
    // One process's hook on a function
    struct hooked_function
    {
        // Points into wanted_hooks, which is populated once at construction
        // and only read afterwards, so the entry never moves.
        const plugin_target_config_entry_t* config;
        std::string so_path;
        // The library's load address, not the hook's. Identifies which
        // library to tear down on dlclose, where the path cannot: a library
        // can be unloaded and another mapped at a different base under the
        // same path before we observe either.
        addr_t so_base;
        addr_t va;
    };

    // The breakpoint on one physical address and the hooks every process has
    // there. Library text is shared, so one breakpoint fires for all the
    // processes mapping the library, and the callback picks the hooks of the
    // process that hit it. A breakpoint per process would run as many
    // callbacks on every call, all but one of them for nothing.
    struct pa_hook
    {
        drakvuf_trap_t* trap;
        std::unordered_map<vmi_pid_t, std::vector<hooked_function>> by_pid;
    };

    // What is mapped in one process, and enough context to read it while a
    // different process is on the vCPU.
    struct process_libs
    {
        addr_t proc_base = 0;   // task_struct
        addr_t dtb = 0;         // its page tables
        so_map_t loaded;        // load address -> library
        std::map<addr_t, std::string> build_ids;   // load address -> GNU build ID, empty if unknown
        // The executable, which the dynamic linker lists without a name
        addr_t exe_start = 0;
        addr_t exe_end = 0;
    };

    // A hook that could not be completed yet, either because the symbol was
    // not resolvable (ld.so may not have read the library's .dynsym at the
    // point we armed) or because the function's page was not resident.
    struct deferred_hook
    {
        const plugin_target_config_entry_t* config;
        std::string so_path;
        addr_t so_base;         // link_map.l_addr, to retry resolution
        addr_t proc_base;       // task_struct, ditto
        addr_t dtb;             // to test residency without the process running
        addr_t va;              // 0 until resolved
        unsigned attempts;
        std::string build_id;   // of the library, empty if unknown
    };

    // A call in progress: its arguments, read at entry, and what to report
    // with its return value.
    struct pending_call
    {
        const plugin_target_config_entry_t* config;
        std::string so_path;
        std::vector<uint64_t> arguments;
    };

    void on_so_discovered(drakvuf_t drakvuf, drakvuf_trap_info_t* info, const so_view_t& so);

    // dlclose. The addresses resolved in this library are about to stop
    // meaning anything, and the range may be reused by a later mapping, so
    // the breakpoints have to come out with it.
    void on_so_removed(drakvuf_t drakvuf, drakvuf_trap_info_t* info, const so_view_t& so);

    void on_process_reset(vmi_pid_t pid);

    // A call to a hooked function: reports it at entry, or tracks it to its return
    void on_call(drakvuf_t drakvuf, drakvuf_trap_info_t* info, const hooked_function& target);

    void print_call(drakvuf_t drakvuf, drakvuf_trap_info_t* info,
        const plugin_target_config_entry_t& config, const std::string& so_path,
        const std::vector<uint64_t>& arguments, std::optional<uint64_t> return_value);

    // Which library an address lies in, or nothing if it lies in none. Tested
    // against each library's PT_LOAD extent, so an address in the heap or in
    // an anonymous mapping above the last library is not claimed by it.
    std::optional<std::string> resolve_module(vmi_pid_t pid, addr_t addr) const;

    // Whether an address lies in a library or the executable, i.e. in code
    // mapped from a file rather than in memory written at run time (JIT code)
    bool in_mapped_file(vmi_pid_t pid, addr_t addr) const;

    // The GNU build ID of a library as a hex string, empty if it has none or it can't be read
    std::string read_build_id(drakvuf_t drakvuf, addr_t proc_base, addr_t so_base);

    /*
     * The addresses of entries in one mapping of a library, in one pass over
     * its symbol table, or none if a library with the same build ID was
     * resolved before. 0: not resolvable yet, the symbol table could not be
     * read; ~0: the library doesn't define the symbol.
     */
    std::vector<addr_t> resolve_symbols(drakvuf_t drakvuf, addr_t proc_base, addr_t so_base,
        const std::string& build_id, const std::vector<const plugin_target_config_entry_t*>& entries);

    // Returns false if the page is not resident, in which case the caller
    // should defer the hook rather than treat it as failed. Pass a physical
    // address to breakpoint that frame directly, for a page the target itself
    // has not faulted in; the VA is still recorded, being where the target
    // will execute it and what the callback compares against.
    bool place_hook(drakvuf_t drakvuf, drakvuf_trap_info_t* info, vmi_pid_t pid, addr_t dtb,
        const plugin_target_config_entry_t& entry, const std::string& so_path,
        addr_t so_base, addr_t va, std::optional<addr_t> pa = std::nullopt);

    // Find the physical frame backing a library page through some other
    // process that has it resident. Library text is file-backed and shared,
    // so any process mapping the same file maps the same frames, even though
    // each faults them in separately. The same file: the same build ID.
    //
    // Returns nothing if no other process has that page, which is the case a
    // hook on a genuinely untouched library still cannot be placed in.
    std::optional<addr_t> find_shared_pa(drakvuf_t drakvuf, vmi_pid_t pid,
        const deferred_hook& target) const;

    // Remove the hooks of a process accepted by drop, and the breakpoints
    // with them once no process has a hook on them.
    template<typename Drop>
    void drop_hooks(vmi_pid_t pid, Drop drop);

    // Retry whatever could not be completed earlier, at most budget hooks.
    // Resolution and trap insertion both go through the target's own page
    // tables, so this does not require that process to be the one running.
    void flush_deferred(drakvuf_t drakvuf, drakvuf_trap_info_t* info, vmi_pid_t pid, unsigned& budget);

    // Drives the retries: without it a process whose every symbol failed
    // would never hook anything, having no hook left to fire.
    event_response_t cr3_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info);

    static event_response_t function_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info);

    wanted_so_hooks_t wanted_hooks;
    std::unique_ptr<dl_rendezvous> rendezvous;

    std::unordered_map<addr_t, pa_hook> pa_hooks;   // key: physical address

    // Which (pid, va) pairs are already hooked, to avoid placing a second
    // hook on one.
    std::set<std::pair<vmi_pid_t, addr_t>> hooked_keys;

    std::map<vmi_pid_t, std::vector<deferred_hook>> deferred;
    // When the retry tick last looked up symbols for a process, which is the expensive part
    std::map<vmi_pid_t, gint64> last_resolve;
    // The process the retry tick goes on with, so a long list is worked through in turns
    vmi_pid_t next_deferred = 0;

    // What every tracked process has mapped, so an address can be attributed
    // back to the library it lies in, and so a library's pages can be reached
    // through a process that has them resident.
    std::map<vmi_pid_t, process_libs> libs;

    // Symbol offsets from the load address per GNU build ID, so every other
    // mapping of the same file skips the symbol table. 0: not defined there.
    std::map<std::string, std::map<const plugin_target_config_entry_t*, addr_t>> symbol_offsets;

    // The calls in progress, matched to their returns
    return_tracker<pending_call> returns;

    bool no_retval;

    // stop_impl() is retried until it succeeds, so the summary is guarded
    // rather than logged once per attempt.
    bool stats_logged = false;

    // Held only while something is deferred; a CR3 hook fires on every
    // context switch.
    std::unique_ptr<libhook::Cr3Hook> cr3_hook;

#ifdef DRAKVUF_DEBUG
    // Debug builds: the pages return breakpoints were placed on, to match the
    // pages libdrakvuf copies again after guest writes (see trap_stats.c)
    struct return_page
    {
        vmi_pid_t pid;          // the first call returning there
        addr_t va;
        std::string where;      // library, executable or anonymous memory
        bool transient;
        uint64_t calls;
    };
    std::map<addr_t, return_page> return_pages;   // key: physical page
    void count_return_page(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t ret_addr, bool transient);
    void print_return_pages() const;

    // Calls whose [rsp] was no return address, per library and function
    std::map<std::string, uint64_t> refused_returns;
    // rsp and [rsp] when the hook callback started, before anything else ran
    addr_t hit_rsp = 0, hit_ret = 0;
    uint64_t hit_uid = 0;
    void log_refused_return(drakvuf_trap_info_t* info, const hooked_function& target, addr_t ret_addr);
#endif
};

#endif