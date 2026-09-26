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

private:
    struct hooked_function
    {
        // Points into wanted_hooks, which is populated once at construction
        // and only read afterwards, so the entry never moves.
        const plugin_target_config_entry_t* config;
        std::string so_path;
        vmi_pid_t pid;
        addr_t va;
        drakvuf_trap_t* trap;
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
    void on_process_reset(vmi_pid_t pid);

    void print_call(drakvuf_t drakvuf, drakvuf_trap_info_t* info,
        const plugin_target_config_entry_t& config, const std::string& so_path,
        const std::vector<uint64_t>& arguments, std::optional<uint64_t> return_value);

    // Which library an address lies in, by the nearest load address at or
    // below it. link_map gives no extents, so this is bounded by the next
    // library up and by a sanity cap rather than known section sizes.
    std::optional<std::string> resolve_module(vmi_pid_t pid, addr_t addr) const;

    // Not static, unlike function_hook_cb: this goes through the RAII hook
    // API, which binds `this` itself. Recovering the plugin by hand here
    // would reach for trap->data, which for a RAII hook holds the Params
    // object rather than the legacy plugin_data.
    event_response_t function_return_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info);

    // Returns false if the page is not resident, in which case the caller
    // should defer the hook rather than treat it as failed.
    bool place_hook(drakvuf_t drakvuf, drakvuf_trap_info_t* info, vmi_pid_t pid,
        const plugin_target_config_entry_t& entry, const std::string& so_path, addr_t va);

    // Retry whatever could not be completed earlier. Resolution and trap
    // insertion both go through the target's own page tables, so they do not
    // need that process to be running; in_context says whether it is, which
    // gates faulting a cold page in, since that acts on the current vCPU.
    void flush_deferred(drakvuf_t drakvuf, drakvuf_trap_info_t* info, vmi_pid_t pid,
        bool in_context);

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

    // Load address -> path for every library seen in a process, so an address
    // can be attributed back to the library it lies in.
    std::map<vmi_pid_t, std::map<addr_t, std::string>> libs;

    // Calls currently in flight, keyed by (pid, tid, rsp) so that recursive
    // or concurrent calls to the same function do not collide.
    std::map<std::pair<uint64_t, addr_t>, std::unique_ptr<libhook::ReturnHook>> ret_hooks;

    bool no_retval;

    // Held only while something is deferred; a CR3 hook fires on every
    // context switch.
    std::unique_ptr<libhook::Cr3Hook> cr3_hook;
};

#endif
