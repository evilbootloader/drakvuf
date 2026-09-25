#ifndef _INCLUDE_DL_RENDEZVOUS
#define _INCLUDE_DL_RENDEZVOUS

#include <functional>
#include <map>
#include <memory>
#include <string>
#include <utility>

#include <libdrakvuf/libdrakvuf.h>
#include "plugins/plugins_ex.h"

// One shared object mapped into a guest process, as reported to consumers.
struct so_view_t
{
    vmi_pid_t pid;
    addr_t proc_base;   // task_struct, for drakvuf_exportsym_to_va()
    addr_t base;        // link_map.l_addr
    std::string path;   // link_map.l_name
};

// Consumers are called with the trap info of the _dl_debug_state hit that
// observed the change, so they can read guest memory in the right context.
using so_event_cb = std::function<void(drakvuf_t, drakvuf_trap_info_t*, const so_view_t&)>;
using proc_reset_cb = std::function<void(vmi_pid_t)>;

// register_trap()'s "init_breakpoint" functor for a permanent breakpoint at
// an already-known virtual address, scoped to one process. The RAII API has
// no equivalent (it covers only syscall/return/cr3/cpuid/catchall/memaccess),
// so this fills the same role as breakpoint_by_pid_searcher in
// plugins/plugins_ex.h, but for a fixed VA rather than a return address
// derived from the current stack.
struct breakpoint_at_va_for_pid
{
    breakpoint_at_va_for_pid(vmi_pid_t pid, addr_t va) : m_pid(pid), m_va(va) {}

    drakvuf_trap_t* operator()(drakvuf_t drakvuf, drakvuf_trap_info_t* /*info*/, drakvuf_trap_t* trap) const
    {
        if (!trap)
            return nullptr;

        trap->type = BREAKPOINT;
        trap->breakpoint.lookup_type = LOOKUP_PID;
        trap->breakpoint.pid = m_pid;
        trap->breakpoint.addr_type = ADDR_VA;
        trap->breakpoint.addr = m_va;

        if (!drakvuf_add_trap(drakvuf, trap))
            return nullptr;

        return trap;
    }

    vmi_pid_t m_pid;
    addr_t m_va;
};

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

    // Notified once per newly mapped / unmapped shared object, including the
    // set present at process startup and anything later dlopen()ed.
    void set_callbacks(so_event_cb on_discovered, so_event_cb on_removed);

    // Notified when a tracked process's address space goes away, by exit or
    // by a further exec() (which keeps the pid). Consumers must drop any
    // per-process state keyed off that pid: addresses resolved in the old
    // address space are meaningless afterwards.
    void set_process_reset_callback(proc_reset_cb on_reset);

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

    so_event_cb discovered_cb;
    so_event_cb removed_cb;
    proc_reset_cb reset_cb;

    std::unique_ptr<libhook::SyscallHook> load_elf_hook;
    std::unique_ptr<libhook::SyscallHook> exit_hook;
    std::map<std::pair<uint64_t, addr_t>, std::unique_ptr<libhook::ReturnHook>> ret_hooks;
    std::map<vmi_pid_t, process_state> procs;
};

#endif
