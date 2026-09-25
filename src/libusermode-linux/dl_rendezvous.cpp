#include <glib.h>

#include <libdrakvuf/libdrakvuf.h>
#include "plugins/plugins_ex.h"
#include "plugins/helpers/hooks.h"

#include "dl_rendezvous.hpp"
#include "dl_rendezvous_abi.hpp"

namespace
{

// linux_eprocess_sym2va() (src/libdrakvuf/linux-exports.c, reached here via
// the public drakvuf_exportsym_to_va() wrapper) prefix-matches the mapped
// file's basename against this string, so "ld-linux" alone matches both
// ld-linux-x86-64.so.2 (x86-64) and ld-linux.so.2 (i386 compat). musl's
// ld-musl-*.so.* is intentionally not matched (out of scope for v1).
const char* INTERP_NAME_PREFIX = "ld-linux";

} // namespace

dl_rendezvous::dl_rendezvous(drakvuf_t drakvuf)
    : pluginex(drakvuf, OUTPUT_DEFAULT)
{
    if (!is_supported(drakvuf))
        throw -1;

    // NOTE: needs empirical validation that "load_elf_binary" resolves as a
    // breakpoint target the same way "begin_new_exec" does for procmon
    // (src/plugins/procmon/linux.cpp) -- both are non-exported kernel
    // functions resolved via the debug-info profile, but confirm rather than
    // assume. Fallback if it doesn't: hook begin_new_exec-return instead and
    // defer the ld.so search to the first subsequent per-process event.
    load_elf_hook = createSyscallHook("load_elf_binary", &dl_rendezvous::load_elf_binary_cb);
    if (!load_elf_hook)
    {
        PRINT_DEBUG("[DL_RENDEZVOUS] Method load_elf_binary not found.\n");
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

event_response_t dl_rendezvous::load_elf_binary_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto hook = this->createReturnHook(info, &dl_rendezvous::load_elf_binary_ret_cb, info->trap->name);
    if (!hook)
        return VMI_EVENT_RESPONSE_NONE;

    auto params = libhook::GetTrapParams(hook->trap_);
    auto hook_id = make_hook_id(info, params->target_rsp);
    this->ret_hooks[hook_id] = std::move(hook);

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t dl_rendezvous::load_elf_binary_ret_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto params = libhook::GetTrapParams(info);
    if (!params->verifyResultCallParams(drakvuf, info))
        return VMI_EVENT_RESPONSE_NONE;

    auto hook_id = make_hook_id(info, params->target_rsp);
    this->ret_hooks.erase(hook_id);

    // By the time load_elf_binary() returns, both the main executable and
    // the interpreter (ld.so) are fully mapped into the new process's
    // address space (unlike at begin_new_exec-return, which is too early --
    // see the plan notes). proc_data already reflects the new process here.
    vmi_pid_t pid = info->proc_data.pid;
    addr_t eprocess_base = info->proc_data.base_addr;

    addr_t dl_debug_state_va = drakvuf_exportsym_to_va(drakvuf, eprocess_base, INTERP_NAME_PREFIX, "_dl_debug_state");
    if (dl_debug_state_va == (addr_t)-1)
    {
        // No interpreter found (or no _dl_debug_state in it) -- most likely
        // a statically-linked binary, which is out of scope for v1: there's
        // no link_map for a rendezvous breakpoint to observe.
        PRINT_DEBUG("[DL_RENDEZVOUS] pid %d: no interpreter/_dl_debug_state found (static binary?)\n", pid);
        return VMI_EVENT_RESPONSE_NONE;
    }

    // TODO(v2): resolve r_debug via DT_DEBUG in the main executable's own
    // PT_DYNAMIC instead (see dl_rendezvous_abi.hpp's dt_tag enum) -- that's
    // the libc/linker-vendor-agnostic approach gdb uses by default. This
    // _r_debug export lookup is a v1 shortcut: it reuses the existing
    // symbol resolver as-is instead of adding a new PT_DYNAMIC-tag-walk
    // helper, at the cost of depending on glibc exporting _r_debug (which it
    // does, but this is a secondary source of truth rather than the
    // universal one).
    addr_t r_debug_va = drakvuf_exportsym_to_va(drakvuf, eprocess_base, INTERP_NAME_PREFIX, "_r_debug");
    if (r_debug_va == (addr_t)-1)
    {
        PRINT_DEBUG("[DL_RENDEZVOUS] pid %d: found _dl_debug_state but not _r_debug\n", pid);
        return VMI_EVENT_RESPONSE_NONE;
    }

    // Permanent, per-process breakpoint. Not scoped by TTL defaults --
    // needs to keep firing for the whole lifetime of the process (once per
    // dlopen()/dlclose()), so pass UNLIMITED_TTL explicitly rather than
    // falling back to the 4-arg overload's default limited-traps ttl.
    auto trap = register_trap(info, &dl_rendezvous::dl_debug_state_hook_cb,
            breakpoint_at_va_for_pid(pid, dl_debug_state_va), "_dl_debug_state", UNLIMITED_TTL);
    if (!trap)
    {
        PRINT_DEBUG("[DL_RENDEZVOUS] pid %d: failed to place _dl_debug_state breakpoint\n", pid);
        return VMI_EVENT_RESPONSE_NONE;
    }

    // exec() keeps the pid, so a process exec'ing more than once (shell
    // wrappers, interpreters re-exec'ing) lands here again for a pid we
    // already track. Drop the previous address space's trap and snapshot
    // instead of leaking the trap and leaving a stale breakpoint behind, and
    // tell consumers to do the same with anything they resolved back then.
    auto& state = this->procs[pid];
    if (state.rendezvous_trap)
    {
        this->destroy_trap(state.rendezvous_trap);
        if (this->reset_cb)
            this->reset_cb(pid);
    }

    state = {};
    state.r_debug_va = r_debug_va;
    state.rendezvous_trap = trap;

    PRINT_DEBUG("[DL_RENDEZVOUS] pid %d: rendezvous armed (_dl_debug_state=0x%lx, r_debug=0x%lx)\n",
        pid, dl_debug_state_va, r_debug_va);

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t dl_rendezvous::dl_debug_state_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto plugin = get_trap_plugin<dl_rendezvous>(info);
    vmi_pid_t pid = info->proc_data.pid;

    auto it = plugin->procs.find(pid);
    if (it == plugin->procs.end())
        return VMI_EVENT_RESPONSE_NONE;

    process_state& state = it->second;

    auto vmi = vmi_lock_guard(drakvuf);
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = state.r_debug_va + R_DEBUG_STATE
    );

    uint32_t r_state;
    if (VMI_FAILURE == vmi_read_32(vmi, &ctx, &r_state))
        return VMI_EVENT_RESPONSE_NONE;

    // ld.so calls _dl_debug_state() once before and once after each
    // mutation; only the "after" hit (RT_CONSISTENT) has a walkable list.
    if (r_state != RT_CONSISTENT)
        return VMI_EVENT_RESPONSE_NONE;

    ctx.addr = state.r_debug_va + R_DEBUG_MAP;
    addr_t node;
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &node))
        return VMI_EVENT_RESPONSE_NONE;

    // A partially-read snapshot is worse than none: it would log every
    // not-yet-walked library as removed and then persist the truncated list,
    // so a failed read abandons the whole update and leaves state untouched
    // until the next RT_CONSISTENT hit.
    std::map<addr_t, std::string> current_libs;
    for (int guard = 0; node && guard < 1024; guard++) // guard against a corrupt/cyclic list
    {
        addr_t l_addr, l_name_ptr, l_next;

        ctx.addr = node + LINK_MAP_ADDR;
        if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &l_addr))
            return VMI_EVENT_RESPONSE_NONE;

        ctx.addr = node + LINK_MAP_NAME;
        if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &l_name_ptr))
            return VMI_EVENT_RESPONSE_NONE;

        ctx.addr = node + LINK_MAP_NEXT;
        if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &l_next))
            return VMI_EVENT_RESPONSE_NONE;

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

    // Diff against the previous snapshot for this process.
    for (auto& [base, path] : current_libs)
    {
        if (state.known_libs.count(base))
            continue;

        PRINT_DEBUG("[DL_RENDEZVOUS] pid %d: lib_discovered base=0x%lx path=%s\n", pid, base, path.c_str());

        if (plugin->discovered_cb)
        {
            so_view_t so{ pid, info->proc_data.base_addr, base, path };
            plugin->discovered_cb(drakvuf, info, so);
        }
    }

    for (auto& [base, path] : state.known_libs)
    {
        if (current_libs.count(base))
            continue;

        PRINT_DEBUG("[DL_RENDEZVOUS] pid %d: lib_removed base=0x%lx path=%s\n", pid, base, path.c_str());

        if (plugin->removed_cb)
        {
            so_view_t so{ pid, info->proc_data.base_addr, base, path };
            plugin->removed_cb(drakvuf, info, so);
        }
    }

    state.known_libs = std::move(current_libs);
    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t dl_rendezvous::do_exit_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    vmi_pid_t pid = info->proc_data.pid;
    auto it = this->procs.find(pid);
    if (it == this->procs.end())
        return VMI_EVENT_RESPONSE_NONE;

    if (this->reset_cb)
        this->reset_cb(pid);

    if (it->second.rendezvous_trap)
        this->destroy_trap(it->second.rendezvous_trap);

    this->procs.erase(it);
    return VMI_EVENT_RESPONSE_NONE;
}
