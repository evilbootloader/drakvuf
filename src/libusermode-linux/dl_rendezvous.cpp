#include <glib.h>

#include <libdrakvuf/libdrakvuf.h>
#include "plugins/plugins_ex.h"
#include "plugins/helpers/hooks.h"

#include "dl_rendezvous.hpp"
#include "dl_rendezvous_abi.hpp"

// How many ticks to keep retrying before writing a process off. The tick is
// normally a page fault, and a process takes a few hundred of those while
// starting up, so this has to be well clear of that to avoid giving up on a
// heavy binary mid-start.
static constexpr unsigned ARM_MAX_ATTEMPTS = 5000;

dl_rendezvous::dl_rendezvous(drakvuf_t drakvuf)
    : pluginex(drakvuf, OUTPUT_DEFAULT)
{
    if (!is_supported(drakvuf))
        throw -1;

    // load_elf_binary() would be the obvious hook point, but a breakpoint on
    // it never fires: it is static in fs/binfmt_elf.c, and the address the
    // profile gives for it is not where the kernel actually executes. Global
    // symbols in fs/exec.c (begin_new_exec, do_exit) hook fine.
    //
    // finalize_exec() is global, and load_elf_binary() calls it after
    // create_elf_tables() has filled in mm->saved_auxv and before
    // START_THREAD(), so on entry the new process is current, the
    // interpreter is mapped, and the aux vector is readable -- everything
    // this needs, without a return hook.
    exec_hook = createSyscallHook("finalize_exec", &dl_rendezvous::finalize_exec_cb);
    if (!exec_hook)
    {
        PRINT_DEBUG("[DL_RENDEZVOUS] Method finalize_exec not found.\n");
        throw -1;
    }

    exit_hook = createSyscallHook("do_exit", &dl_rendezvous::do_exit_cb);
    if (!exit_hook)
    {
        PRINT_DEBUG("[DL_RENDEZVOUS] Method do_exit not found.\n");
        throw -1;
    }

    this->bootstrap_layouts(drakvuf);
}

struct walk_ctx
{
    dl_rendezvous* self;
    unsigned dynamic;       // processes with an interpreter to look at
    unsigned taken;         // ... of which are now tracked and armed
};

bool dl_rendezvous::read_process(drakvuf_t drakvuf, addr_t process, vmi_pid_t* pid, addr_t* dtb,
    addr_t* ld_base)
{
    *ld_base = drakvuf_get_auxv_value(drakvuf, process, AT_BASE_TYPE);
    if (!*ld_base)
        return false;

    if (!drakvuf_get_process_pid(drakvuf, process, pid) || *pid <= 0)
        return false;

    /*
     * Not drakvuf_get_process_dtb(): on Linux that is mm->pgd minus a
     * PAGE_OFFSET hardcoded to 0xffff800000000000 (linux-processes.c:121),
     * while x86-64 bases its direct map at page_offset_base, 0xffff888000000000
     * on a stock kernel and randomised under CONFIG_RANDOMIZE_MEMORY. The
     * difference is a physical address past the end of guest RAM, so every read
     * through it fails -- which is why adoption found 101 dynamic processes and
     * could read none of them.
     *
     * libvmi translates the pgd properly (vmi_translate_kv2p), and it is the
     * same call drakvuf.c:415 makes to place a LOOKUP_PID breakpoint, so it is
     * exercised on every guest that hooks anything by name.
     *
     * The exec path sidesteps all of this by taking regs->cr3 at finalize_exec.
     */
    {
        auto vmi = vmi_lock_guard(drakvuf);
        if (VMI_SUCCESS == vmi_pid_to_dtb(vmi, *pid, dtb) && *dtb)
            return true;
    }

    return drakvuf_get_process_dtb(drakvuf, process, dtb) && *dtb;
}

void dl_rendezvous::bootstrap_visitor(drakvuf_t drakvuf, addr_t process, void* visitor_ctx)
{
    auto ctx = static_cast<walk_ctx*>(visitor_ctx);

    vmi_pid_t pid = 0;
    addr_t dtb = 0, ld_base = 0;
    if (!ctx->self->read_process(drakvuf, process, &pid, &dtb, &ld_base))
        return;

    ctx->dynamic++;
    ctx->self->learn_layout(drakvuf, process, dtb, ld_base, true);
}

void dl_rendezvous::adopt_visitor(drakvuf_t drakvuf, addr_t process, void* visitor_ctx)
{
    auto ctx = static_cast<walk_ctx*>(visitor_ctx);
    auto self = ctx->self;

    vmi_pid_t pid = 0;
    addr_t dtb = 0, ld_base = 0;
    if (!self->read_process(drakvuf, process, &pid, &dtb, &ld_base))
        return;

    ctx->dynamic++;

    // Nothing should be tracked yet, since no exec can have been seen before
    // this runs. Leave anything that is alone rather than overwriting a state
    // that owns a trap.
    if (self->procs.count(pid))
        return;

    auto& state = self->procs[pid];
    state.ld_base = ld_base;
    state.dtb = dtb;
    state.proc_base = process;

    self->arming.adopted++;

    // No trap info to attribute this to: we are in start-up, not in a callback.
    // Nothing on either path needs one -- the breakpoint goes in by physical
    // address, and consumers are told the process is out of context.
    self->try_arm(drakvuf, nullptr, pid, state);

    if (state.armed())
    {
        ctx->taken++;
        return;
    }

    /*
     * One shot, and no retry tick. A process that has been running has
     * everything arming needs, so a failure here means we cannot read it
     * rather than that we are early, and retrying will not change that. The
     * tick is also the wrong tool at this scale: it hooks every page fault in
     * the guest, and leaving a whole task list pending on it -- 101 processes
     * on the guest this was written against -- would cost more than the
     * monitoring it was installed for.
     *
     * The cost is a process genuinely caught between its exec and ld.so
     * running, which is a window of microseconds and cannot be picked up later
     * either, since its finalize_exec is already past. It is reported rather
     * than dropped silently.
     */
    if (!state.abandoned)
    {
        self->abandon(pid, state,
            "already-running process could not be read at startup; not monitored");

        PRINT_DEBUG("[DL_RENDEZVOUS] pid %d: adoption failed, ld_base=0x%lx dtb=0x%lx\n",
            pid, ld_base, dtb);
    }

    self->procs.erase(pid);
}

void dl_rendezvous::adopt_running_processes(drakvuf_t drakvuf)
{
    walk_ctx ctx{ this, 0, 0 };

    if (!drakvuf_enumerate_processes(drakvuf, &dl_rendezvous::adopt_visitor, &ctx))
    {
        PRINT_DEBUG("[DL_RENDEZVOUS] could not walk the process list;"
            " only processes that exec from now on will be monitored\n");
        return;
    }

    PRINT_DEBUG("[DL_RENDEZVOUS] adopted %u of %u already-running dynamic process(es)\n",
        ctx.taken, ctx.dynamic);
}

/*
 * Everything a process is made to wait for at exec is a property of its ld.so
 * build, and the guest is already running processes that have those answers:
 * their ld.so pages were faulted in long ago and their r_debug has been
 * initialised since they started. Reading one of each build at startup means
 * the first exec of the run is armed from the cache like every later one.
 *
 * Cheap enough to do unconditionally: one aux-vector read per task (kernel
 * memory, always resident) and, only for the first process of each build, a
 * symbol resolution and one more read.
 *
 * A consumer that calls adopt_running_processes() gets this as a side effect of
 * arming those processes, making this walk redundant for it. It stays so the
 * class does not depend on the consumer doing that.
 */
void dl_rendezvous::bootstrap_layouts(drakvuf_t drakvuf)
{
    walk_ctx ctx{ this, 0, 0 };

    if (!drakvuf_enumerate_processes(drakvuf, &dl_rendezvous::bootstrap_visitor, &ctx))
    {
        PRINT_DEBUG("[DL_RENDEZVOUS] could not walk the process list;"
            " the first process of each ld.so build will wait for it instead\n");
        return;
    }

    PRINT_DEBUG("[DL_RENDEZVOUS] bootstrap: %u dynamic process(es), %zu ld.so build(s) known\n",
        ctx.dynamic, this->layouts.size());
}

void dl_rendezvous::set_callbacks(so_event_cb on_discovered, so_event_cb on_removed)
{
    this->discovered_cb = std::move(on_discovered);
    this->removed_cb = std::move(on_removed);
}

void dl_rendezvous::set_process_reset_callback(proc_reset_cb on_reset)
{
    this->reset_cb = std::move(on_reset);
}

void dl_rendezvous::set_status_callback(status_cb on_status)
{
    this->reported_cb = std::move(on_status);
}

// PRINT_DEBUG compiles to nothing in a release build, so a failure to arm
// would otherwise be indistinguishable from a guest that simply never called
// anything. Hand the reason to the consumer as well, so it can be surfaced.
void dl_rendezvous::report(vmi_pid_t pid, const char* reason)
{
    PRINT_DEBUG("[DL_RENDEZVOUS] pid %d: %s\n", pid, reason);

    if (this->reported_cb)
        this->reported_cb(pid, reason);
}

bool dl_rendezvous::is_supported(drakvuf_t drakvuf)
{
    // Unlike userhook.cpp's is_supported(), we don't need to check the guest
    // OS here: the plugin-os-support matrix already guarantees this class is
    // only ever instantiated on a Linux guest, the same way apimon is never
    // instantiated on Linux. What *is* worth checking is bitness, since v1
    // targets glibc/x86-64 only (32-bit link_map/r_debug field sizes and
    // offsets differ and aren't handled here).
    if (drakvuf_get_page_mode(drakvuf) != VMI_PM_IA32E)
    {
        PRINT_DEBUG("[DL_RENDEZVOUS] Only supported on x86-64 guests for now.\n");
        return false;
    }
    return true;
}

event_response_t dl_rendezvous::finalize_exec_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    // Logged unconditionally: if this never appears, the kernel hook is not
    // firing at all, which is a different problem from anything downstream.
    // begin_new_exec() has already run by now, so current -- and therefore
    // proc_data -- is the newly exec'd process, not the caller.
    PRINT_DEBUG("[DL_RENDEZVOUS] finalize_exec entered by pid %d (%s)\n",
        info->proc_data.pid, info->proc_data.name ?: "?");

    vmi_pid_t pid = info->proc_data.pid;
    addr_t eprocess_base = info->proc_data.base_addr;

    // AT_BASE is the interpreter's load address and AT_ENTRY the main
    // executable's entry point. Reading them from the aux vector avoids
    // searching the VMA list, whose mm_struct.mmap / vm_area_struct.vm_next
    // layout Linux 6.1 replaced with a maple tree -- a name-based lookup
    // silently finds nothing on any newer kernel.
    addr_t ld_base = drakvuf_get_auxv_value(drakvuf, eprocess_base, AT_BASE_TYPE);
    if (!ld_base)
    {
        // Statically linked binaries have no interpreter, and so no link_map
        // for a rendezvous breakpoint to observe. A profile without
        // mm_struct.saved_auxv lands here too.
        this->report(pid, "no AT_BASE: statically linked, or saved_auxv missing from the kernel profile");
        return VMI_EVENT_RESPONSE_NONE;
    }

    // exec() keeps the pid, so a process exec'ing more than once (shell
    // wrappers, interpreters re-exec'ing) lands here again for a pid we
    // already track. Drop the previous address space's trap and snapshot
    // instead of leaking it and leaving a stale breakpoint behind, and tell
    // consumers to do the same with anything they resolved back then.
    auto& state = this->procs[pid];
    if (state.rendezvous_trap)
    {
        this->release_trap(state);

        if (this->reset_cb)
            this->reset_cb(pid);
    }

    state = {};
    state.ld_base = ld_base;
    state.dtb = info->regs->cr3;            // begin_new_exec() already installed the new mm
    state.proc_base = eprocess_base;

    this->arming.execs++;

    // Nothing can be armed yet, and not for want of r_debug: the process has
    // not executed an instruction, so none of its pages are faulted in, down
    // to the ELF header that says which ld.so is mapped here. Retry on a tick
    // until that page arrives -- which is the whole of the wait when the
    // build's layout is already known, rather than waiting out ld.so.
    this->start_arming_tick();

    if (!this->fault_hook && !this->cr3_hook)
    {
        this->report(pid, "no tick available to wait for ld.so on");
        this->procs.erase(pid);
        return VMI_EVENT_RESPONSE_NONE;
    }

    PRINT_DEBUG("[DL_RENDEZVOUS] pid %d: exec'd, ld_base=0x%lx dtb=0x%lx, waiting for ld.so\n",
        pid, ld_base, state.dtb);

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t dl_rendezvous::fault_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    return this->arming_tick(drakvuf, info);
}

event_response_t dl_rendezvous::cr3_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    return this->arming_tick(drakvuf, info);
}

event_response_t dl_rendezvous::arming_tick(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    // Deliberately not keyed off the current process. At a CR3 write
    // `current` may still be the outgoing task, and a fault may well be in
    // some unrelated process. Every pending process is read through its own
    // stored dtb instead, which works no matter who is running, so this is
    // purely a retry clock.
    this->arming.ticks++;

    bool pending = false;

    for (auto& [pid, state] : this->procs)
    {
        // A cached layout this process has since disproved. The breakpoint
        // comes out here rather than in the callback that found the mismatch,
        // which is a hit on the very trap being destroyed.
        if (state.needs_rearm)
        {
            this->release_trap(state);
            state.needs_rearm = false;
            state.ld_key = 0;
            state.r_debug_va = 0;
            state.r_brk_va = 0;
            state.attempts = 0;
        }

        if (state.armed() || state.abandoned)
            continue;

        if (!this->try_arm(drakvuf, info, pid, state))
            pending = true;
    }

    if (!pending)
        this->stop_arming_tick();

    return VMI_EVENT_RESPONSE_NONE;
}

arming_stats dl_rendezvous::stats() const
{
    arming_stats out = this->arming;

#ifdef DRAKVUF_DEBUG
    // Include the stretch currently in progress, so a snapshot taken while
    // something is still pending is not an underestimate.
    if (this->fault_hook || this->cr3_hook)
    {
        out.installed_ns += std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now() - this->tick_installed_at).count();
    }
#endif

    return out;
}

void dl_rendezvous::start_arming_tick()
{
    if (this->fault_hook || this->cr3_hook)
        return;

#ifdef DRAKVUF_DEBUG
    this->tick_installed_at = std::chrono::steady_clock::now();
#endif

    // Every user page fault, so this is expensive -- but it only runs while a
    // process is waiting to be armed, and it collapses that wait from several
    // context switches to the next fault the process takes, which during
    // ld.so start-up is almost immediate.
    this->fault_hook = createSyscallHook("handle_mm_fault", &dl_rendezvous::fault_cb);
    if (this->fault_hook)
        return;

    PRINT_DEBUG("[DL_RENDEZVOUS] handle_mm_fault not hookable, falling back to CR3 ticks\n");
    this->cr3_hook = createCr3Hook(&dl_rendezvous::cr3_cb);
    if (this->cr3_hook)
        this->arming.used_cr3 = true;
}

void dl_rendezvous::stop_arming_tick()
{
#ifdef DRAKVUF_DEBUG
    if (this->fault_hook || this->cr3_hook)
    {
        this->arming.installed_ns += std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now() - this->tick_installed_at).count();
    }
#endif

    this->fault_hook.reset();
    this->cr3_hook.reset();
}

dl_rendezvous::ld_key_status dl_rendezvous::read_ld_key(drakvuf_t drakvuf, addr_t dtb,
    addr_t ld_base, uint64_t* key)
{
    uint8_t ehdr[LD_SO_EHDR_SIZE];
    size_t got = 0;

    {
        auto vmi = vmi_lock_guard(drakvuf);
        ACCESS_CONTEXT(ctx,
            .translate_mechanism = VMI_TM_PROCESS_DTB,
            .dtb = dtb,
            .addr = ld_base
        );

        if (VMI_FAILURE == vmi_read(vmi, &ctx, sizeof(ehdr), ehdr, &got) || got != sizeof(ehdr))
            return ld_key_status::not_resident;
    }

    *key = ld_so_key(ehdr);
    return *key ? ld_key_status::ok : ld_key_status::unusable;
}

// Stop retrying this process and say why, once. Without the flag the retry
// tick keeps calling try_arm() for as long as any other process is pending,
// which repeats the report on every tick.
void dl_rendezvous::abandon(vmi_pid_t pid, process_state& state, const char* reason)
{
    state.abandoned = true;
    this->arming.gave_up++;
    this->report(pid, reason);
}

bool dl_rendezvous::read_r_brk(drakvuf_t drakvuf, addr_t dtb, addr_t r_debug_va, addr_t* r_brk)
{
    auto vmi = vmi_lock_guard(drakvuf);
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = dtb,
        .addr = r_debug_va + R_DEBUG_BRK
    );

    return VMI_SUCCESS == vmi_read_addr(vmi, &ctx, r_brk) && *r_brk;
}

bool dl_rendezvous::learn_layout(drakvuf_t drakvuf, addr_t proc_base, addr_t dtb, addr_t ld_base,
    bool at_startup)
{
    uint64_t key = 0;
    if (ld_key_status::ok != this->read_ld_key(drakvuf, dtb, ld_base, &key))
        return false;

    // Worth recording whether or not the layout is new: arming a process that
    // has not run yet needs somebody's page tables to reach ld.so's frames
    // through, and this process has them.
    this->donors[key] = ld_so_donor{ proc_base, dtb, ld_base };

    if (this->layouts.find(key))
        return true;            // already known; nothing to read out of this one

    // Take the rendezvous function's address from r_debug.r_brk rather than
    // resolving _dl_debug_state by name: glibc marks that symbol rtld_hidden,
    // so it is absent from ld.so's .dynsym. r_brk is the field the protocol
    // provides for this, and is what gdb uses. _r_debug itself is exported
    // (GLIBC_2.2.5), so it does resolve.
    addr_t r_debug_va = drakvuf_exportsym_to_va_at_base(drakvuf, proc_base, ld_base, "_r_debug");
    if (!r_debug_va || r_debug_va == (addr_t)-1)
        return false;

    addr_t r_brk = 0;
    if (!this->read_r_brk(drakvuf, dtb, r_debug_va, &r_brk))
        return false;           // r_debug not initialised yet

    // Both symbols are ld.so's own, so both addresses are above its base. A
    // field that is not says we read something that is not an r_debug.
    if (r_debug_va <= ld_base || r_brk <= ld_base)
        return false;

    if (!this->layouts.learn(key, ld_so_layout{ r_debug_va - ld_base, r_brk - ld_base }))
        return false;

    this->arming.builds++;
    if (at_startup)
        this->arming.bootstrapped++;

    PRINT_DEBUG("[DL_RENDEZVOUS] ld.so build %016lx: _r_debug at +0x%lx, rendezvous at +0x%lx"
        " (learned %s)\n",
        key, r_debug_va - ld_base, r_brk - ld_base, at_startup ? "at startup" : "from an exec");

    return true;
}

std::optional<addr_t> dl_rendezvous::resolve_frame(drakvuf_t drakvuf, const process_state& state,
    addr_t off)
{
    auto translate = [&](addr_t dtb, addr_t base) -> std::optional<addr_t>
    {
        addr_t pa = 0;
        auto vmi = vmi_lock_guard(drakvuf);

        if (VMI_SUCCESS != vmi_pagetable_lookup(vmi, dtb, base + off, &pa) || !pa)
            return std::nullopt;

        return pa;
    };

    // The target itself, if ld.so has already run far enough to touch the
    // page. Usually it has not: the point of arming from a cached layout is to
    // be in place before the call that would fault this page in.
    if (auto pa = translate(state.dtb, state.ld_base))
        return pa;

    // Anyone else running the same build, then. Each candidate's ELF header is
    // re-read first: page tables outlive nothing in particular, and a dtb whose
    // process has gone can still translate, into whatever reused them.
    auto try_donor = [&](addr_t dtb, addr_t base) -> std::optional<addr_t>
    {
        uint64_t key = 0;
        if (ld_key_status::ok != this->read_ld_key(drakvuf, dtb, base, &key) || key != state.ld_key)
            return std::nullopt;

        return translate(dtb, base);
    };

    for (const auto& [other_pid, other] : this->procs)
    {
        if (other.dtb == state.dtb || other.ld_key != state.ld_key)
            continue;

        if (auto pa = try_donor(other.dtb, other.ld_base))
        {
            PRINT_DEBUG("[DL_RENDEZVOUS] reached ld.so+0x%lx through pid %d -> pa 0x%lx\n",
                off, other_pid, *pa);
            return pa;
        }
    }

    auto donor = this->donors.find(state.ld_key);
    if (donor != this->donors.end())
    {
        if (auto pa = try_donor(donor->second.dtb, donor->second.ld_base))
            return pa;

        // Its header no longer reads back as this build, so its page tables
        // are not its own any more. Stop trusting them.
        this->donors.erase(donor);
    }

    return std::nullopt;
}

bool dl_rendezvous::attach_trap(drakvuf_trap_info_t* info, process_state& state, addr_t pa)
{
    auto& entry = this->pa_traps[pa];

    if (!entry.trap)
    {
        entry.trap = register_trap(info, &dl_rendezvous::rendezvous_hook_cb,
                breakpoint_at_pa(pa), "r_brk", UNLIMITED_TTL);
        if (!entry.trap)
        {
            this->pa_traps.erase(pa);
            return false;
        }
    }

    entry.refs++;
    state.trap_pa = pa;
    state.rendezvous_trap = entry.trap;
    return true;
}

void dl_rendezvous::release_trap(process_state& state)
{
    if (!state.rendezvous_trap)
        return;

    auto it = this->pa_traps.find(state.trap_pa);
    if (it != this->pa_traps.end() && --it->second.refs == 0)
    {
        this->destroy_trap(it->second.trap);
        this->pa_traps.erase(it);
    }

    state.rendezvous_trap = nullptr;
    state.trap_pa = 0;
    state.verified = false;
}

bool dl_rendezvous::try_arm(drakvuf_t drakvuf, drakvuf_trap_info_t* info, vmi_pid_t pid, process_state& state)
{
    // ld.so start-up is quick, so a process that never gets there is stuck
    // or not what we assumed. Give up rather than hold the CR3 hook open.
    if (++state.attempts > ARM_MAX_ATTEMPTS)
    {
        this->abandon(pid, state, state.ld_key
            ? "ld.so did not initialise r_debug; giving up"
            : "ld.so's ELF header never became readable; giving up");
        return true;
    }

    // Which ld.so this is. This read is the whole of what arming waits for
    // once a build is known: it needs only the first page of the mapping,
    // which ld.so reads itself -- its own e_phoff and e_phnum, through
    // __ehdr_start -- while setting up its link map, long before any library
    // is in. Failure here is normal on the first tick or two.
    if (!state.ld_key)
    {
        switch (this->read_ld_key(drakvuf, state.dtb, state.ld_base, &state.ld_key))
        {
            case ld_key_status::ok:
                break;

            case ld_key_status::not_resident:
                return false;

            case ld_key_status::unusable:
                // Readable, and not an x86-64 ELF64 shared object: a 32-bit
                // interpreter under a compat process, or an AT_BASE that does
                // not point at one. Waiting changes nothing.
                this->abandon(pid, state, "the interpreter at AT_BASE is not an x86-64 ELF64 shared object");
                return true;
        }
    }

    const ld_so_layout* layout = this->layouts.find(state.ld_key);
    const bool from_cache = layout != nullptr;

    // Nothing known about this build: this is the first process seen running
    // it, so there is nothing to copy and r_debug has to be read out of this
    // process the slow way. What that establishes is kept for the next one.
    if (!layout)
    {
        if (!this->learn_layout(drakvuf, state.proc_base, state.dtb, state.ld_base, false))
            return false;

        layout = this->layouts.find(state.ld_key);
        if (!layout)
            return false;       // implausible offsets; wait and read again
    }

    state.r_debug_va = state.ld_base + layout->r_debug_off;
    state.r_brk_va = state.ld_base + layout->r_brk_off;

    auto pa = this->resolve_frame(drakvuf, state, layout->r_brk_off);
    if (!pa)
        return false;           // nobody has that page yet

    if (!this->attach_trap(info, state, *pa))
        return false;

    // A process armed the slow way had its r_brk read out of itself, so there
    // is nothing left to check it against. Only a layout taken from the cache
    // has to answer for itself at the first hit.
    state.verified = !from_cache;

    this->arming.armed++;
    if (from_cache)
        this->arming.fast_armed++;

    PRINT_DEBUG("[DL_RENDEZVOUS] pid %d: armed after %u attempt(s) from %s"
        " (r_debug=0x%lx r_brk=0x%lx pa=0x%lx)\n",
        pid, state.attempts, from_cache ? "a known layout" : "this process",
        state.r_debug_va, state.r_brk_va, *pa);

    // Whatever the program links against may already be mapped, so report that
    // set now rather than waiting for a dlopen() that may never come. Armed
    // early -- from the cache, before ld.so finished starting up -- r_debug is
    // still zeroed and this reads nothing; the startup _dl_debug_state() call
    // reports the initial set instead, which is the breakpoint doing its job
    // rather than this walk guessing at it.
    // Reached from the retry tick, so some other process is on the vCPU.
    this->diff_link_map(drakvuf, info, pid, state, false);
    return true;
}

event_response_t dl_rendezvous::rendezvous_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto plugin = get_trap_plugin<dl_rendezvous>(info);
    vmi_pid_t pid = info->proc_data.pid;

    auto it = plugin->procs.find(pid);
    if (it == plugin->procs.end())
        return VMI_EVENT_RESPONSE_NONE;

    process_state& state = it->second;

    // The breakpoint is physical and so fires for every process sharing the
    // frame, including ones still waiting to be armed, which have no r_debug
    // address to read yet.
    if (!state.armed())
        return VMI_EVENT_RESPONSE_NONE;

    // Already found to be breakpointed in the wrong place, and waiting for the
    // retry tick to take it back out. Hits until then say nothing new.
    if (state.needs_rearm)
        return VMI_EVENT_RESPONSE_NONE;

    uint32_t r_state;
    addr_t r_brk = 0;
    {
        auto vmi = vmi_lock_guard(drakvuf);
        ACCESS_CONTEXT(ctx,
            .translate_mechanism = VMI_TM_PROCESS_DTB,
            .dtb = state.dtb,
            .addr = state.r_debug_va + R_DEBUG_BRK
        );

        if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &r_brk))
            return VMI_EVENT_RESPONSE_NONE;

        ctx.addr = state.r_debug_va + R_DEBUG_STATE;
        if (VMI_FAILURE == vmi_read_32(vmi, &ctx, &r_state))
            return VMI_EVENT_RESPONSE_NONE;
    }

    // First hit from a process armed out of the cache. Its own r_debug can be
    // read by now, so this is where the offsets get checked against what the
    // process itself says. A mismatch means the breakpoint went in at an
    // address this build does not rendezvous at, in a page shared with every
    // other process running the same ld.so -- so drop the layout before
    // anything else is armed from it, and have this process start over.
    if (!state.verified && r_brk)
    {
        if (r_brk != state.r_brk_va)
        {
            plugin->arming.mismatches++;
            plugin->layouts.forget(state.ld_key);
            plugin->report(pid, "cached ld.so layout disagreed with r_debug.r_brk; re-learning");

            state.needs_rearm = true;
            plugin->start_arming_tick();
            return VMI_EVENT_RESPONSE_NONE;
        }

        state.verified = true;

        // A process that has reached its own rendezvous has ld.so's pages
        // resident and its r_debug filled in, which is exactly what arming the
        // next process needs to translate through. Nothing else refreshes this:
        // the layout is already known, so learn_layout() is not called again.
        plugin->donors[state.ld_key] = ld_so_donor{ state.proc_base, state.dtb, state.ld_base };
    }

    // ld.so calls this once before and once after each change to the list;
    // only the "after" hit (RT_CONSISTENT) has a walkable list.
    if (r_state != RT_CONSISTENT)
        return VMI_EVENT_RESPONSE_NONE;

    // The rendezvous breakpoint fires in ld.so, so this process is running.
    plugin->diff_link_map(drakvuf, info, pid, state, true);
    return VMI_EVENT_RESPONSE_NONE;
}

void dl_rendezvous::diff_link_map(drakvuf_t drakvuf, drakvuf_trap_info_t* info, vmi_pid_t pid,
    process_state& state, bool in_context)
{
    std::map<addr_t, std::string> current_libs;

    {
        auto vmi = vmi_lock_guard(drakvuf);
        ACCESS_CONTEXT(ctx,
            .translate_mechanism = VMI_TM_PROCESS_DTB,
            // Not info->regs->cr3: diff_link_map() is also called from the
            // CR3 retry tick, where the running process is whoever we just
            // switched to, not the one being armed.
            .dtb = state.dtb,
            .addr = state.r_debug_va + R_DEBUG_MAP
        );

        addr_t node;
        if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &node))
            return;

        // A partially-read snapshot is worse than none: it would report every
        // not-yet-walked library as removed and then persist the truncated
        // list, so a failed read abandons the whole update and leaves state
        // untouched until the next RT_CONSISTENT hit.
        for (int guard = 0; node && guard < 1024; guard++) // guard against a corrupt/cyclic list
        {
            addr_t l_addr, l_name_ptr, l_next;

            ctx.addr = node + LINK_MAP_ADDR;
            if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &l_addr))
                return;

            ctx.addr = node + LINK_MAP_NAME;
            if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &l_name_ptr))
                return;

            ctx.addr = node + LINK_MAP_NEXT;
            if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &l_next))
                return;

            if (l_name_ptr)
            {
                ctx.addr = l_name_ptr;
                char* name = vmi_read_str(vmi, &ctx);
                if (name && *name)
                    current_libs.emplace(l_addr, name);
                g_free(name);
            }

            node = l_next;
        }
    } // release vmi before calling out to consumers, which read guest memory

    for (auto& [base, path] : current_libs)
    {
        if (state.known_libs.count(base))
            continue;

        PRINT_DEBUG("[DL_RENDEZVOUS] pid %d: lib_discovered base=0x%lx path=%s\n", pid, base, path.c_str());

        if (this->discovered_cb)
        {
            so_view_t so{ pid, state.proc_base, state.dtb, base, path, in_context };
            this->discovered_cb(drakvuf, info, so);
        }
    }

    for (auto& [base, path] : state.known_libs)
    {
        if (current_libs.count(base))
            continue;

        PRINT_DEBUG("[DL_RENDEZVOUS] pid %d: lib_removed base=0x%lx path=%s\n", pid, base, path.c_str());

        if (this->removed_cb)
        {
            so_view_t so{ pid, state.proc_base, state.dtb, base, path, in_context };
            this->removed_cb(drakvuf, info, so);
        }
    }

    state.known_libs = std::move(current_libs);
}

event_response_t dl_rendezvous::do_exit_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    vmi_pid_t pid = info->proc_data.pid;
    auto it = this->procs.find(pid);
    if (it == this->procs.end())
        return VMI_EVENT_RESPONSE_NONE;

    if (this->reset_cb)
        this->reset_cb(pid);

    this->release_trap(it->second);

    // Its page tables are about to go away, so nothing may translate through
    // them again.
    auto donor = this->donors.find(it->second.ld_key);
    if (donor != this->donors.end() && donor->second.dtb == it->second.dtb)
        this->donors.erase(donor);

    this->procs.erase(it);
    return VMI_EVENT_RESPONSE_NONE;
}
