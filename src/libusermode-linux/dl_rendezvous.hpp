#ifndef _INCLUDE_DL_RENDEZVOUS
#define _INCLUDE_DL_RENDEZVOUS

#include <map>
#include <memory>
#include <string>
#include <utility>

#include <libdrakvuf/libdrakvuf.h>
#include "plugins/plugins_ex.h"

// Linux equivalent of libusermode's DLL-load detection, but for shared
// objects: bootstraps ld.so's rendezvous protocol per-process (the same
// _dl_debug_state()/r_debug/link_map technique gdb/lldb use) so that both
// the initial load set at process start and every runtime dlopen()/dlclose()
// can be observed. v1 scope: glibc/x86-64 only (see dl_rendezvous_abi.hpp).
class dl_rendezvous : public pluginex
{
public:
    explicit dl_rendezvous(drakvuf_t drakvuf);

    static bool is_supported(drakvuf_t drakvuf);

    // Registered via createSyscallHook/createReturnHook (RAII API), so these
    // run as ordinary bound member functions.
    event_response_t load_elf_binary_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info);
    event_response_t load_elf_binary_ret_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info);
    event_response_t do_exit_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info);

private:
    struct process_state
    {
        addr_t r_debug_va = 0;
        drakvuf_trap_t* rendezvous_trap = nullptr;
        std::map<addr_t, std::string> known_libs; // link_map base (l_addr) -> path (l_name), last known snapshot
    };

    // Registered via the legacy register_trap() API (no RAII helper exists
    // for "breakpoint at an arbitrary already-known VA scoped to one pid"),
    // so this must be a plain-function-pointer-compatible static, and
    // recovers `this` via get_trap_plugin() instead of being bound directly.
    static event_response_t dl_debug_state_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info);

    std::unique_ptr<libhook::SyscallHook> load_elf_hook;
    std::unique_ptr<libhook::SyscallHook> exit_hook;
    std::map<std::pair<uint64_t, addr_t>, std::unique_ptr<libhook::ReturnHook>> ret_hooks;
    std::map<vmi_pid_t, process_state> procs;
};

#endif
