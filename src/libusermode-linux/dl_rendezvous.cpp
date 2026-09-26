#include <glib.h>

#include <libdrakvuf/libdrakvuf.h>
#include "plugins/plugins_ex.h"
#include "plugins/helpers/hooks.h"

#include "dl_rendezvous.hpp"
#include "dl_rendezvous_abi.hpp"

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

    addr_t entry_va = drakvuf_get_auxv_value(drakvuf, eprocess_base, AT_ENTRY_TYPE);
    if (!entry_va)
    {
        this->report(pid, "no AT_ENTRY in the aux vector");
        return VMI_EVENT_RESPONSE_NONE;
    }

    // exec() keeps the pid, so a process exec'ing more than once (shell
    // wrappers, interpreters re-exec'ing) lands here again for a pid we
    // already track. Drop the previous address space's traps and snapshot
    // instead of leaking them and leaving stale breakpoints behind, and tell
    // consumers to do the same with anything they resolved back then.
    auto& state = this->procs[pid];
    if (state.entry_trap || state.rendezvous_trap)
    {
        if (state.entry_trap)
            this->destroy_trap(state.entry_trap);
        if (state.rendezvous_trap)
            this->destroy_trap(state.rendezvous_trap);

        if (this->reset_cb)
            this->reset_cb(pid);
    }

    state = {};
    state.ld_base = ld_base;

    // r_debug lives in ld.so's data and is still zeroed here: the kernel has
    // only just mapped the interpreter, which has not executed an
    // instruction yet. Wait for the main executable's entry point, by which
    // time ld.so has initialised r_debug and mapped everything the program
    // links against.
    state.entry_trap = register_trap(info, &dl_rendezvous::main_entry_hook_cb,
            breakpoint_at_va_for_pid(pid, entry_va), "main_entry", UNLIMITED_TTL);
    if (!state.entry_trap)
    {
        this->report(pid, "failed to place a breakpoint on the executable entry point");
        this->procs.erase(pid);
        return VMI_EVENT_RESPONSE_NONE;
    }

    PRINT_DEBUG("[DL_RENDEZVOUS] pid %d: exec'd, ld_base=0x%lx entry=0x%lx, waiting for entry point\n",
        pid, ld_base, entry_va);

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t dl_rendezvous::main_entry_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto plugin = get_trap_plugin<dl_rendezvous>(info);
    vmi_pid_t pid = info->proc_data.pid;

    auto it = plugin->procs.find(pid);
    if (it == plugin->procs.end())
        return VMI_EVENT_RESPONSE_NONE;

    process_state& state = it->second;

    // One-shot: ld.so start-up happens once per address space.
    if (state.entry_trap)
    {
        plugin->destroy_trap(state.entry_trap);
        state.entry_trap = nullptr;
    }

    // Take the rendezvous function's address from r_debug.r_brk rather than
    // resolving _dl_debug_state by name. glibc marks that symbol rtld_hidden,
    // so it is absent from ld.so's .dynsym and cannot be looked up; r_brk is
    // the field the protocol provides for exactly this purpose, and is what
    // gdb uses. _r_debug itself is exported (GLIBC_2.2.5), so it resolves.
    addr_t r_debug_va = drakvuf_exportsym_to_va_at_base(drakvuf, info->proc_data.base_addr,
            state.ld_base, "_r_debug");
    if (!r_debug_va || r_debug_va == (addr_t)-1)
    {
        plugin->report(pid, "could not resolve _r_debug in the interpreter");
        return VMI_EVENT_RESPONSE_NONE;
    }

    addr_t r_brk = 0;
    {
        auto vmi = vmi_lock_guard(drakvuf);
        ACCESS_CONTEXT(ctx,
            .translate_mechanism = VMI_TM_PROCESS_DTB,
            .dtb = info->regs->cr3,
            .addr = r_debug_va + R_DEBUG_BRK
        );

        if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &r_brk) || !r_brk)
        {
            plugin->report(pid, "r_debug.r_brk is unset at the executable entry point");
            return VMI_EVENT_RESPONSE_NONE;
        }
    }

    state.r_debug_va = r_debug_va;
    state.rendezvous_trap = plugin->register_trap(info, &dl_rendezvous::rendezvous_hook_cb,
            breakpoint_at_va_for_pid(pid, r_brk), "r_brk", UNLIMITED_TTL);
    if (!state.rendezvous_trap)
    {
        plugin->report(pid, "failed to place the rendezvous breakpoint");
        return VMI_EVENT_RESPONSE_NONE;
    }

    PRINT_DEBUG("[DL_RENDEZVOUS] pid %d: armed (r_debug=0x%lx r_brk=0x%lx)\n", pid, r_debug_va, r_brk);

    // Everything the program links against was mapped before we got here, so
    // report that set now instead of waiting for a dlopen() that may never
    // come.
    plugin->diff_link_map(drakvuf, info, pid, state);

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t dl_rendezvous::rendezvous_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto plugin = get_trap_plugin<dl_rendezvous>(info);
    vmi_pid_t pid = info->proc_data.pid;

    auto it = plugin->procs.find(pid);
    if (it == plugin->procs.end())
        return VMI_EVENT_RESPONSE_NONE;

    process_state& state = it->second;

    uint32_t r_state;
    {
        auto vmi = vmi_lock_guard(drakvuf);
        ACCESS_CONTEXT(ctx,
            .translate_mechanism = VMI_TM_PROCESS_DTB,
            .dtb = info->regs->cr3,
            .addr = state.r_debug_va + R_DEBUG_STATE
        );

        if (VMI_FAILURE == vmi_read_32(vmi, &ctx, &r_state))
            return VMI_EVENT_RESPONSE_NONE;
    }

    // ld.so calls this once before and once after each change to the list;
    // only the "after" hit (RT_CONSISTENT) has a walkable list.
    if (r_state != RT_CONSISTENT)
        return VMI_EVENT_RESPONSE_NONE;

    plugin->diff_link_map(drakvuf, info, pid, state);
    return VMI_EVENT_RESPONSE_NONE;
}

void dl_rendezvous::diff_link_map(drakvuf_t drakvuf, drakvuf_trap_info_t* info, vmi_pid_t pid, process_state& state)
{
    std::map<addr_t, std::string> current_libs;

    {
        auto vmi = vmi_lock_guard(drakvuf);
        ACCESS_CONTEXT(ctx,
            .translate_mechanism = VMI_TM_PROCESS_DTB,
            .dtb = info->regs->cr3,
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
            so_view_t so{ pid, info->proc_data.base_addr, base, path };
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
            so_view_t so{ pid, info->proc_data.base_addr, base, path };
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

    if (it->second.entry_trap)
        this->destroy_trap(it->second.entry_trap);

    if (it->second.rendezvous_trap)
        this->destroy_trap(it->second.rendezvous_trap);

    this->procs.erase(it);
    return VMI_EVENT_RESPONSE_NONE;
}
