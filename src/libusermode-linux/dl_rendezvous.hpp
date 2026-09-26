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
    addr_t proc_base;   // task_struct, for drakvuf_exportsym_to_va_at_base()
    addr_t base;        // link_map.l_addr
    std::string path;   // link_map.l_name

    // True when this process is the one currently executing, i.e. the
    // callback came from its own rendezvous breakpoint rather than from the
    // CR3 retry tick. Anything that acts on the running vCPU -- injecting a
    // page fault, say -- is only safe when this holds.
    bool in_context;
};

// Consumers are called with the trap info of the _dl_debug_state hit that
// observed the change, so they can read guest memory in the right context.
using so_event_cb = std::function<void(drakvuf_t, drakvuf_trap_info_t*, const so_view_t&)>;
using proc_reset_cb = std::function<void(vmi_pid_t)>;

// Reports why tracking gave up on a process. Consumers should surface this:
// without it a failure to arm is indistinguishable from a quiet guest.
using status_cb = std::function<void(vmi_pid_t, const char* reason)>;

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

    void set_status_callback(status_cb on_status);

    // Registered via createSyscallHook (RAII API), so these run as ordinary
    // bound member functions.
    event_response_t finalize_exec_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info);
    event_response_t do_exit_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info);

private:
    struct process_state
    {
        addr_t ld_base = 0;         // AT_BASE: where the interpreter is mapped
        addr_t dtb = 0;             // its page tables, so we can read it while another process runs
        addr_t proc_base = 0;       // task_struct
        addr_t r_debug_va = 0;
        drakvuf_trap_t* rendezvous_trap = nullptr;  // permanent, at r_debug.r_brk
        unsigned attempts = 0;      // arming retries spent so far
        std::map<addr_t, std::string> known_libs; // link_map base (l_addr) -> path (l_name), last known snapshot

        bool armed() const
        {
            return rendezvous_trap != nullptr;
        }
    };

    // Stage two: a tick, not a real event. At finalize_exec the process has
    // not run yet, so nothing of it is paged in and no breakpoint can be
    // placed in it at all; r_debug is likewise still zeroed. Retry until
    // ld.so has initialised r_debug and we can read r_brk.
    //
    // Page faults are the better clock: a starting process takes a burst of
    // them as ld.so maps and reads what it needs, which is exactly the window
    // being waited on, so they arrive far more densely than context switches.
    // CR3 is the fallback if handle_mm_fault cannot be hooked.
    event_response_t fault_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info);
    event_response_t cr3_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info);

    event_response_t arming_tick(drakvuf_t drakvuf, drakvuf_trap_info_t* info);
    void start_arming_tick();
    void stop_arming_tick();

    // Returns true once the process is armed or has been given up on, i.e.
    // when it no longer needs retrying.
    bool try_arm(drakvuf_t drakvuf, drakvuf_trap_info_t* info, vmi_pid_t pid, process_state& state);

    // Stage three: fires at r_debug.r_brk, on every dlopen()/dlclose().
    // Registered via the legacy register_trap() API (no RAII helper exists
    // for "breakpoint at an arbitrary already-known VA scoped to one pid"),
    // so it must be a plain-function-pointer-compatible static, and recovers
    // `this` via get_trap_plugin() instead of being bound directly.
    static event_response_t rendezvous_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info);

    // Snapshot the link_map and report what changed since last time.
    // in_context says whether the process being walked is the one running.
    void diff_link_map(drakvuf_t drakvuf, drakvuf_trap_info_t* info, vmi_pid_t pid,
        process_state& state, bool in_context);

    void report(vmi_pid_t pid, const char* reason);

    so_event_cb discovered_cb;
    so_event_cb removed_cb;
    proc_reset_cb reset_cb;
    status_cb reported_cb;

    std::unique_ptr<libhook::SyscallHook> exec_hook;
    std::unique_ptr<libhook::SyscallHook> exit_hook;

    // Both are installed only while some process still needs arming: each
    // fires system-wide and is far too costly to leave running.
    std::unique_ptr<libhook::SyscallHook> fault_hook;
    std::unique_ptr<libhook::Cr3Hook> cr3_hook;
    std::map<vmi_pid_t, process_state> procs;
};

#endif
