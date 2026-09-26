#ifndef _INCLUDE_LIBMON
#define _INCLUDE_LIBMON

#include <map>
#include <memory>
#include <string>
#include <utility>

#include "plugins/plugins_ex.h"
#include "libusermode-linux/dl_rendezvous.hpp"
#include "libusermode-linux/utils.hpp"

struct libmon_config
{
    const char* so_hooks_list;
    bool print_no_addr;
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
        drakvuf_trap_t* trap;
    };

    // A resolved function whose page was not resident, so no breakpoint could
    // be placed on it yet.
    struct deferred_hook
    {
        const plugin_target_config_entry_t* config;
        std::string so_path;
        addr_t va;
        unsigned attempts;
    };

    void on_so_discovered(drakvuf_t drakvuf, drakvuf_trap_info_t* info, const so_view_t& so);
    void on_process_reset(vmi_pid_t pid);

    // Returns false if the page is not resident, in which case the caller
    // should defer the hook rather than treat it as failed.
    bool place_hook(drakvuf_t drakvuf, drakvuf_trap_info_t* info, vmi_pid_t pid,
        const plugin_target_config_entry_t& entry, const std::string& so_path, addr_t va);

    // Retry deferred hooks, faulting in one cold page per call. Only safe
    // from a callback running in that process's own context.
    void flush_deferred(drakvuf_t drakvuf, drakvuf_trap_info_t* info, vmi_pid_t pid);

    static event_response_t function_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info);

    wanted_so_hooks_t wanted_hooks;
    std::unique_ptr<dl_rendezvous> rendezvous;

    // Keyed by (pid, entry VA). The breakpoint callback looks itself up by
    // info->regs->rip, which is the address the breakpoint was placed at.
    std::map<std::pair<vmi_pid_t, addr_t>, hooked_function> hooked;
    std::map<vmi_pid_t, std::vector<deferred_hook>> deferred;
};

#endif
