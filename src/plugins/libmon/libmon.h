#ifndef _INCLUDE_LIBMON
#define _INCLUDE_LIBMON

#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "plugins/plugins_ex.h"
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
        vmi_pid_t pid;
        addr_t va;
        drakvuf_trap_t* trap;
    };

    // What is mapped in one process, and enough context to read it while a
    // different process is on the vCPU.
    struct process_libs
    {
        addr_t proc_base = 0;   // task_struct
        addr_t dtb = 0;         // its page tables
        so_map_t loaded;        // load address -> library
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
    };

    // Carries the call's arguments from the function's entry, where they are
    // readable, to its return, where the result is.
    struct return_data : public PluginResult
    {
        std::vector<uint64_t> arguments;
        const plugin_target_config_entry_t* config;
        std::string so_path;
    };

    void on_so_discovered(drakvuf_t drakvuf, drakvuf_trap_info_t* info, const so_view_t& so);

    // dlclose. The addresses resolved in this library are about to stop
    // meaning anything, and the range may be reused by a later mapping, so
    // the breakpoints have to come out with it.
    void on_so_removed(drakvuf_t drakvuf, drakvuf_trap_info_t* info, const so_view_t& so);

    void on_process_reset(vmi_pid_t pid);

    void print_call(drakvuf_t drakvuf, drakvuf_trap_info_t* info,
        const plugin_target_config_entry_t& config, const std::string& so_path,
        const std::vector<uint64_t>& arguments, std::optional<uint64_t> return_value);

    // Which library an address lies in, or nothing if it lies in none. Tested
    // against each library's PT_LOAD extent, so an address in the heap or in
    // an anonymous mapping above the last library is not claimed by it.
    std::optional<std::string> resolve_module(vmi_pid_t pid, addr_t addr) const;

    // Not static, unlike function_hook_cb: this goes through the RAII hook
    // API, which binds `this` itself. Recovering the plugin by hand here
    // would reach for trap->data, which for a RAII hook holds the Params
    // object rather than the legacy plugin_data.
    event_response_t function_return_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info);

    // Returns false if the page is not resident, in which case the caller
    // should defer the hook rather than treat it as failed. Pass a physical
    // address to breakpoint that frame directly, for a page the target itself
    // has not faulted in; the VA is still recorded, being where the target
    // will execute it and what the callback compares against.
    bool place_hook(drakvuf_t drakvuf, drakvuf_trap_info_t* info, vmi_pid_t pid,
        const plugin_target_config_entry_t& entry, const std::string& so_path,
        addr_t so_base, addr_t va, std::optional<addr_t> pa = std::nullopt);

    // Find the physical frame backing a library page through some other
    // process that has it resident. Library text is file-backed and shared,
    // so any process mapping the same library maps the same frames, even
    // though each faults them in separately.
    //
    // Returns nothing if no other process has that page, which is the case a
    // hook on a genuinely untouched library still cannot be placed in.
    std::optional<addr_t> find_shared_pa(drakvuf_t drakvuf, vmi_pid_t pid,
        const deferred_hook& target) const;

    // Remove one hook and forget it. Returns the iterator past it, so callers
    // sweeping `hooked` can erase as they go.
    std::map<const drakvuf_trap_t*, hooked_function>::iterator
    drop_hook(std::map<const drakvuf_trap_t*, hooked_function>::iterator it);

    // Retry whatever could not be completed earlier. Resolution and trap
    // insertion both go through the target's own page tables, so this does
    // not require that process to be the one running.
    void flush_deferred(drakvuf_t drakvuf, drakvuf_trap_info_t* info, vmi_pid_t pid);

    // Drives the retries: without it a process whose every symbol failed
    // would never hook anything, having no hook left to fire.
    event_response_t cr3_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info);

    static event_response_t function_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info);

    wanted_so_hooks_t wanted_hooks;
    std::unique_ptr<dl_rendezvous> rendezvous;

    // Keyed by the trap itself, which info->trap identifies exactly. Keying
    // on (pid, info->regs->rip) instead would depend on rip being the
    // breakpoint address rather than the instruction after it.
    std::map<const drakvuf_trap_t*, hooked_function> hooked;

    // Which (pid, va) pairs are already hooked, to avoid placing a second
    // breakpoint on one and to find a process's hooks when it goes away.
    std::set<std::pair<vmi_pid_t, addr_t>> hooked_keys;

    std::map<vmi_pid_t, std::vector<deferred_hook>> deferred;

    // What every tracked process has mapped, so an address can be attributed
    // back to the library it lies in, and so a library's pages can be reached
    // through a process that has them resident.
    std::map<vmi_pid_t, process_libs> libs;

    // Calls currently in flight, keyed by (pid, tid, rsp) so that recursive
    // or concurrent calls to the same function do not collide.
    std::map<std::pair<uint64_t, addr_t>, std::unique_ptr<libhook::ReturnHook>> ret_hooks;

    bool no_retval;

    // stop_impl() is retried until it succeeds, so the summary is guarded
    // rather than logged once per attempt.
    bool stats_logged = false;

    // Held only while something is deferred; a CR3 hook fires on every
    // context switch.
    std::unique_ptr<libhook::Cr3Hook> cr3_hook;
};

#endif
