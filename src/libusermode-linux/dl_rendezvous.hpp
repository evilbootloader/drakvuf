#ifndef _INCLUDE_DL_RENDEZVOUS
#define _INCLUDE_DL_RENDEZVOUS

#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include <libdrakvuf/libdrakvuf.h>
#include "plugins/plugins_ex.h"

#include "ld_so_cache.hpp"

// One shared object mapped into a guest process, as reported to consumers.
struct so_view_t
{
    vmi_pid_t pid;
    addr_t proc_base;   // task_struct, for drakvuf_exportsym_to_va_at_base()
    addr_t dtb;         // its page tables, usable while another process runs
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

// What waiting for ld.so has cost. Arming needs a clock to retry on, and the
// only one that is prompt enough is a hook on every user page fault in the
// guest -- system-wide, not per-process. It is installed only while some
// process is still waiting, so the question is what fraction of a run that
// is, which depends on how often the guest starts processes. Nobody has
// measured it on a busy guest yet, hence these counters.
struct arming_stats
{
    uint64_t execs = 0;         // processes taken up at exec
    uint64_t adopted = 0;       // ... and processes already running at startup
    uint64_t armed = 0;         // ... of which reached r_debug
    uint64_t fast_armed = 0;    // ... of which from an already-known ld.so layout
    uint64_t gave_up = 0;       // ... of which never did
    uint64_t ticks = 0;         // tick callbacks taken, i.e. VM exits caused
    uint64_t builds = 0;        // distinct ld.so builds whose layout is known
    uint64_t bootstrapped = 0;  // ... of which learned at startup, before any exec
    uint64_t mismatches = 0;    // cached layouts a process's own r_brk disproved
    uint64_t installed_ns = 0;  // total time the tick was installed; debug builds only
    bool used_cr3 = false;      // fell back from page faults to CR3 writes
};

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

// The same, for a physical address the caller has already resolved. Needed
// when the page is not resident in the process being hooked: a breakpoint
// scoped by pid and VA cannot be placed at all in that case, because there is
// no page table entry to translate. Library text is shared through the page
// cache, so the frame can be found through any other process that has faulted
// it in, and a trap placed on it covers the target once it gets there.
//
// Not a loss of scoping: DRAKVUF breakpoints are physical whichever way they
// are expressed, so a hook in libc already fires for every process mapping
// libc and callbacks already filter on pid.
struct breakpoint_at_pa
{
    explicit breakpoint_at_pa(addr_t pa) : m_pa(pa) {}

    drakvuf_trap_t* operator()(drakvuf_t drakvuf, drakvuf_trap_info_t* /*info*/, drakvuf_trap_t* trap) const
    {
        if (!trap)
            return nullptr;

        trap->type = BREAKPOINT;
        trap->breakpoint.lookup_type = LOOKUP_NONE;
        trap->breakpoint.addr_type = ADDR_PA;
        trap->breakpoint.addr = m_pa;

        if (!drakvuf_add_trap(drakvuf, trap))
            return nullptr;

        return trap;
    }

    addr_t m_pa;
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

    /*
     * Take up the processes that were already running when we started, which
     * the exec path cannot see: their finalize_exec happened before the hook
     * existed. That includes an injected sample, since main.cpp injects at
     * inject_cmd() and only then calls start_plugins().
     *
     * Everything arming needs is already true of a running process -- ld.so's
     * pages are resident and its r_debug was initialised when it started -- so
     * these are normally armed on the spot, with no tick and no waiting.
     *
     * Separate from the constructor on purpose: arming a process reports the
     * libraries it already has, and consumers wire their callbacks up after
     * construction, so doing this there would drop that set on the floor.
     */
    void adopt_running_processes(drakvuf_t drakvuf);

    // Snapshot of what arming has cost so far. Live while the tick is
    // installed, final once nothing is pending.
    arming_stats stats() const;

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
        addr_t r_brk_va = 0;        // the address breakpointed, kept to check the layout against
        uint64_t ld_key = 0;        // which ld.so build this is, per ld_so_key()
        // The frame the breakpoint went into, shared with every other process
        // running the same ld.so.
        addr_t trap_pa = 0;
        drakvuf_trap_t* rendezvous_trap = nullptr;  // permanent, at r_debug.r_brk
        unsigned attempts = 0;      // arming retries spent so far
        bool verified = false;      // this process's own r_brk agrees with where it was breakpointed
        bool needs_rearm = false;   // ... or disagreed, and the breakpoint must come back out
        bool abandoned = false;     // given up on; stop retrying and stop reporting it
        std::map<addr_t, std::string> known_libs; // link_map base (l_addr) -> path (l_name), last known snapshot

        bool armed() const
        {
            return rendezvous_trap != nullptr;
        }
    };

    // A process known to have ld.so's pages resident, kept per build. Arming
    // before the target has run needs somebody's page tables to translate
    // through, and the target's own will not do.
    struct ld_so_donor
    {
        addr_t proc_base = 0;
        addr_t dtb = 0;
        addr_t ld_base = 0;
    };

    // One breakpoint per physical frame rather than per process. Every process
    // running a given ld.so rendezvouses in the same shared frame, and a
    // breakpoint there is delivered for all of them whichever way it was
    // expressed -- LOOKUP_PID resolves the VA once at insertion and injects a
    // physical trap, it does not filter per hit. Registering one per process
    // would therefore multiply every dlopen() in the guest by the number of
    // processes tracked, for no extra coverage.
    struct shared_trap
    {
        drakvuf_trap_t* trap = nullptr;
        unsigned refs = 0;
    };

    // Stage two: a tick, not a real event. At finalize_exec the process has
    // not run yet, so nothing of it is paged in -- not even the ELF header
    // that says which ld.so this is. Retry until that one page arrives; ld.so
    // reads it itself while setting up its own link map, which is early.
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

    // Learn where _r_debug and the rendezvous function sit in one ld.so build,
    // by reading them out of a process that has already started. at_startup
    // only distinguishes the bootstrap pass from a live exec for the counters.
    bool learn_layout(drakvuf_t drakvuf, addr_t proc_base, addr_t dtb, addr_t ld_base,
        bool at_startup);

    // Read every running process's interpreter once, at startup, so the first
    // exec of the run is armed from a cached layout like every later one
    // instead of having to wait out ld.so to establish it.
    void bootstrap_layouts(drakvuf_t drakvuf);
    static void bootstrap_visitor(drakvuf_t drakvuf, addr_t process, void* visitor_ctx);
    static void adopt_visitor(drakvuf_t drakvuf, addr_t process, void* visitor_ctx);

    // The three things a task_struct has to give up before it can be tracked.
    // False for a kernel thread, which has no mm and so no aux vector, and for
    // a statically linked process, which has no interpreter.
    bool read_process(drakvuf_t drakvuf, addr_t process, vmi_pid_t* pid, addr_t* dtb,
        addr_t* ld_base);

    enum class ld_key_status
    {
        not_resident,   // ld.so's first page has not been faulted in yet: retry
        unusable,       // read fine, but not an x86-64 ELF64 shared object
        ok,
    };

    // Which ld.so build is mapped at ld_base in the address space dtb
    // describes. Waiting for this to become readable is the whole of what
    // arming waits for once a build is known, so the two failures are worth
    // telling apart: one is retried and the other never will be.
    ld_key_status read_ld_key(drakvuf_t drakvuf, addr_t dtb, addr_t ld_base, uint64_t* key);

    bool read_r_brk(drakvuf_t drakvuf, addr_t dtb, addr_t r_debug_va, addr_t* r_brk);

    void abandon(vmi_pid_t pid, process_state& state, const char* reason);

    // The frame behind an offset into ld.so: the target's own page tables if it
    // has got that far, otherwise those of any process that has.
    std::optional<addr_t> resolve_frame(drakvuf_t drakvuf, const process_state& state, addr_t off);

    bool attach_trap(drakvuf_trap_info_t* info, process_state& state, addr_t pa);
    void release_trap(process_state& state);

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

    ld_so_cache layouts;
    std::map<uint64_t, ld_so_donor> donors;
    std::map<addr_t, shared_trap> pa_traps;

    arming_stats arming;

    // Only read in a debug build, where the timings are collected.
    [[maybe_unused]] std::chrono::steady_clock::time_point tick_installed_at;
};

#endif
