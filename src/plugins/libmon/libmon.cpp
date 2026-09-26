#include <algorithm>

#include <libdrakvuf/libdrakvuf.h>

#include "libmon.h"
#include "plugins/output_format.h"
#include "libusermode/printers/printers.hpp"

// How many times to retry a hook whose page was cold before writing it off.
// An attempt is just a failed trap insertion, so this can be generous; it
// exists to bound the list rather than to ration anything expensive.
static constexpr unsigned DEFERRED_MAX_ATTEMPTS = 1000;

libmon::libmon(drakvuf_t drakvuf, const libmon_config* c, output_format_t output)
    : pluginex(drakvuf, output)
    , no_retval(c->no_retval)
{
    load_so_hook_config(c->so_hooks_list, c->print_no_addr, this->wanted_hooks);

    if (this->wanted_hooks.empty())
    {
        PRINT_DEBUG("[LIBMON] No usable hooks configured, pass --so-hooks-list\n");
        throw -1;
    }

    this->rendezvous = std::make_unique<dl_rendezvous>(drakvuf);

    this->rendezvous->set_callbacks(
        [this](drakvuf_t d, drakvuf_trap_info_t* i, const so_view_t& so)
    {
        this->on_so_discovered(d, i, so);
    },
        [this](drakvuf_t d, drakvuf_trap_info_t* i, const so_view_t& so)
    {
        this->on_so_removed(d, i, so);
    });

    this->rendezvous->set_process_reset_callback([this](vmi_pid_t pid)
    {
        this->on_process_reset(pid);
    });

    // Surface give-up reasons as ordinary events. They would otherwise only
    // exist as PRINT_DEBUG, which a release build discards, leaving "armed
    // nothing" and "guest did nothing" looking identical.
    this->rendezvous->set_status_callback([this](vmi_pid_t pid, const char* reason)
    {
        fmt::print(m_output_format, "libmon", this->drakvuf, nullptr,
            keyval("Event", fmt::Rstr("not_tracked")),
            keyval("PID", fmt::Nval(pid)),
            keyval("Reason", fmt::Qstr(std::string(reason)))
        );
    });
}

std::optional<std::string> libmon::resolve_module(vmi_pid_t pid, addr_t addr) const
{
    auto proc = this->libs.find(pid);
    if (proc == this->libs.end())
        return std::nullopt;

    return resolve_module_in(proc->second.loaded, addr);
}

void libmon::on_so_discovered(drakvuf_t drakvuf, drakvuf_trap_info_t* info, const so_view_t& so)
{
    // Read once, here: the program headers sit in the first mapped page, which
    // ld.so has just read itself, so this is the cheapest moment to ask. A
    // failure is not fatal -- resolve_module() falls back to a size cap.
    addr_t span = drakvuf_get_module_span(drakvuf, so.proc_base, so.base);

    auto& proc = this->libs[so.pid];
    proc.proc_base = so.proc_base;
    proc.dtb = so.dtb;
    proc.loaded[so.base] = loaded_so{ so.path, span ? so.base + span : 0 };

    this->wanted_hooks.visit_hooks_for(so.path, [&](const plugin_target_config_entry_t& entry)
    {
        addr_t va;

        if (entry.type == HOOK_BY_OFFSET)
        {
            va = so.base + entry.offset;
        }
        else
        {
            // Resolve against this .so's own .dynsym, using the load address
            // the dynamic linker reported in link_map.l_addr. Looking the
            // library up by name instead would go through the VMA list, which
            // no longer exists in its old form on Linux 6.1 and newer.
            va = drakvuf_exportsym_to_va_at_base(drakvuf, so.proc_base, so.base,
                    entry.function_name.c_str());
            if (!va || va == (addr_t)-1)
            {
                // Not necessarily absent: we can arm before ld.so has read
                // this library's .dynsym, and an unreadable symbol table
                // fails every lookup in it at once. Retry later.
                this->deferred[so.pid].push_back(
                    deferred_hook{ &entry, so.path, so.base, so.proc_base, so.dtb, 0, 0 });

                PRINT_DEBUG("[LIBMON] pid %d: deferring %s!%s, symbol table not readable yet\n",
                    so.pid, entry.dll_name.c_str(), entry.function_name.c_str());
                return;
            }
        }

        if (this->place_hook(drakvuf, info, so.pid, entry, so.path, so.base, va))
            return;

        // A breakpoint can only be placed on a resident page, and this
        // function has simply never been called, so nothing has faulted its
        // page in. Defer it and fault the page in later, from a callback that
        // actually runs in this process.
        this->deferred[so.pid].push_back(
            deferred_hook{ &entry, so.path, so.base, so.proc_base, so.dtb, va, 0 });

        PRINT_DEBUG("[LIBMON] pid %d: deferring %s!%s at 0x%lx, page not resident\n", so.pid,
            entry.dll_name.c_str(), entry.function_name.c_str(), va);
    });

    // Retries are driven from the CR3 tick rather than from here, which runs
    // once per newly discovered library and would spend several of them in a
    // single event.
    if (!this->deferred.empty() && !this->cr3_hook)
        this->cr3_hook = createCr3Hook(&libmon::cr3_cb);
}

event_response_t libmon::cr3_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    // flush_deferred() erases from the map, so collect the keys first.
    std::vector<vmi_pid_t> pids;
    pids.reserve(this->deferred.size());
    for (const auto& [pid, targets] : this->deferred)
        pids.push_back(pid);

    for (auto pid : pids)
        this->flush_deferred(drakvuf, info, pid);

    if (this->deferred.empty())
        this->cr3_hook.reset();

    return VMI_EVENT_RESPONSE_NONE;
}

bool libmon::place_hook(drakvuf_t drakvuf, drakvuf_trap_info_t* info, vmi_pid_t pid,
    const plugin_target_config_entry_t& entry, const std::string& so_path,
    addr_t so_base, addr_t va, std::optional<addr_t> pa)
{
    auto key = std::make_pair(pid, va);
    if (this->hooked_keys.count(key))
        return true;

    drakvuf_trap_t* trap = pa
        ? register_trap(info, &libmon::function_hook_cb,
            breakpoint_at_pa(*pa), entry.function_name.c_str(), UNLIMITED_TTL)
        : register_trap(info, &libmon::function_hook_cb,
            breakpoint_at_va_for_pid(pid, va), entry.function_name.c_str(), UNLIMITED_TTL);
    if (!trap)
        return false;

    this->hooked.emplace(trap, hooked_function{ &entry, so_path, so_base, pid, va, trap });
    this->hooked_keys.insert(key);

    // Not attributed to `info`: this can run off the CR3 tick, where the
    // process executing is unrelated to the one being hooked. Pass no trap
    // info and name the target process explicitly.
    fmt::print(m_output_format, "libmon", drakvuf, nullptr,
        keyval("Event", fmt::Rstr("hook_placed")),
        keyval("PID", fmt::Nval(pid)),
        keyval("Library", fmt::Qstr(so_path)),
        keyval("Function", fmt::Qstr(entry.function_name)),
        keyval("Address", fmt::Xval(va))
    );

    return true;
}

std::optional<addr_t> libmon::find_shared_pa(drakvuf_t drakvuf, vmi_pid_t pid,
    const deferred_hook& target) const
{
    if (!target.va)
        return std::nullopt;

    const addr_t offset = target.va - target.so_base;

    for (const auto& [other_pid, other] : this->libs)
    {
        if (other_pid == pid)
            continue;

        for (const auto& [other_base, lib] : other.loaded)
        {
            if (lib.path != target.so_path)
                continue;

            // Same path, but not necessarily the same file: a library can be
            // replaced on disk while the old inode stays mapped, and then the
            // same offset is a different function. Resolving the symbol in
            // the donor and requiring the same offset settles it. An offset
            // hook has no name to check, and is taken on trust.
            if (target.config->type != HOOK_BY_OFFSET)
            {
                addr_t donor_va = drakvuf_exportsym_to_va_at_base(drakvuf, other.proc_base,
                        other_base, target.config->function_name.c_str());
                if (!donor_va || donor_va == (addr_t)-1 || donor_va - other_base != offset)
                    continue;
            }

            addr_t pa = 0;
            {
                auto vmi = vmi_lock_guard(drakvuf);
                if (VMI_SUCCESS != vmi_pagetable_lookup(vmi, other.dtb, other_base + offset, &pa))
                    continue;
            }

            PRINT_DEBUG("[LIBMON] pid %d: %s at 0x%lx is cold, reached via pid %d -> pa 0x%lx\n",
                pid, target.config->function_name.c_str(), target.va, other_pid, pa);

            return pa;
        }
    }

    return std::nullopt;
}

// Safe from anywhere: resolution and trap insertion both go through the
// target's own page tables, so it need not be the process running.
void libmon::flush_deferred(drakvuf_t drakvuf, drakvuf_trap_info_t* info, vmi_pid_t pid)
{
    auto it = this->deferred.find(pid);
    if (it == this->deferred.end())
        return;

    auto& targets = it->second;

    for (auto target = targets.begin(); target != targets.end(); )
    {
        // Still unresolved: the library's .dynsym was unreadable last time.
        if (!target->va)
        {
            addr_t va = drakvuf_exportsym_to_va_at_base(drakvuf, target->proc_base,
                    target->so_base, target->config->function_name.c_str());
            if (va && va != (addr_t)-1)
                target->va = va;
        }

        // Check residency ourselves before asking for the trap. Handing
        // drakvuf_add_trap() an address it cannot translate makes it log two
        // errors per attempt, and this retries on every hook hit, so a couple
        // of permanently cold pages otherwise bury the output.
        bool resident = false;
        if (target->va)
        {
            auto vmi = vmi_lock_guard(drakvuf);
            page_info_t pinfo;
            resident = (VMI_SUCCESS == vmi_pagetable_lookup_extended(vmi, target->dtb,
                            target->va, &pinfo));
        }

        if (resident && this->place_hook(drakvuf, info, pid, *target->config,
                target->so_path, target->so_base, target->va))
        {
            target = targets.erase(target);
            continue;
        }

        // Not resident in this process. The page may still exist, faulted in
        // by someone else mapping the same library, in which case breakpoint
        // the frame directly rather than waiting for this process to touch a
        // function it may never call.
        if (!resident)
        {
            if (auto pa = this->find_shared_pa(drakvuf, pid, *target))
            {
                if (this->place_hook(drakvuf, info, pid, *target->config,
                        target->so_path, target->so_base, target->va, pa))
                {
                    target = targets.erase(target);
                    continue;
                }
            }
        }

        if (++target->attempts > DEFERRED_MAX_ATTEMPTS)
        {
            PRINT_DEBUG("[LIBMON] pid %d: giving up on %s at 0x%lx\n", pid,
                target->config->function_name.c_str(), target->va);
            target = targets.erase(target);
            continue;
        }

        // No vmi_request_page_fault() here. It does fault the page in and the
        // hook then places, but it kills the monitored process: removing it
        // stopped the kills across several runs, restoring it brought them
        // back immediately, with the target dying between the injection and
        // its next event. Every call site is a breakpoint callback, and
        // DRAKVUF resumes a breakpoint by switching altp2m view and
        // single-stepping the original instruction, which an injected fault
        // plausibly derails. libusermode carries injection-in-progress
        // tracking and an exception-suppression hook for its own version of
        // this; faulting pages in deliberately needs an equivalent here first.
        //
        // So just retry, having already tried to reach the page through
        // another process above. What is left here is a library no other
        // process has touched at this offset either, which usually means a
        // dlopen()ed private .so rather than anything in libc.
        ++target;
    }

    if (targets.empty())
        this->deferred.erase(it);
}

std::map<const drakvuf_trap_t*, libmon::hooked_function>::iterator
libmon::drop_hook(std::map<const drakvuf_trap_t*, hooked_function>::iterator it)
{
    this->hooked_keys.erase(std::make_pair(it->second.pid, it->second.va));
    this->destroy_trap(it->second.trap);
    return this->hooked.erase(it);
}

// dlclose. The same reasoning as on_process_reset(), for one library rather
// than the whole address space: the range is unmapped and a later dlopen may
// reuse it, so a breakpoint left behind would sit over unrelated code.
void libmon::on_so_removed(drakvuf_t drakvuf, drakvuf_trap_info_t* info, const so_view_t& so)
{
    UNUSED(drakvuf);
    UNUSED(info);

    auto proc = this->libs.find(so.pid);
    if (proc != this->libs.end())
    {
        proc->second.loaded.erase(so.base);
        if (proc->second.loaded.empty())
            this->libs.erase(proc);
    }

    auto deferred_it = this->deferred.find(so.pid);
    if (deferred_it != this->deferred.end())
    {
        auto& targets = deferred_it->second;
        targets.erase(std::remove_if(targets.begin(), targets.end(),
                [&](const deferred_hook& target)
        {
            return target.so_base == so.base;
        }), targets.end());

        if (targets.empty())
            this->deferred.erase(deferred_it);
    }

    // Calls still in flight are deliberately left alone. Their return
    // addresses are in whoever called into this library, which is still
    // mapped, so they can still complete -- and a dlclose from inside a
    // hooked function is exactly the case that would lose an event here.

    [[maybe_unused]] unsigned dropped = 0;
    for (auto it = this->hooked.begin(); it != this->hooked.end(); )
    {
        if (it->second.pid != so.pid || it->second.so_base != so.base)
        {
            ++it;
            continue;
        }

        it = this->drop_hook(it);
        dropped++;
    }

    PRINT_DEBUG("[LIBMON] pid %d: %s unloaded, dropped %u hook(s)\n",
        so.pid, so.path.c_str(), dropped);
}

// The pid's address space is gone (exit, or a further exec), so every VA we
// resolved in it is now meaningless: remove the breakpoints rather than
// leaving them armed over whatever gets mapped there next.
void libmon::on_process_reset(vmi_pid_t pid)
{
    this->deferred.erase(pid);
    this->libs.erase(pid);

    // Drop any call still in flight: its return address belongs to an address
    // space that no longer exists.
    for (auto it = this->ret_hooks.begin(); it != this->ret_hooks.end(); )
    {
        if (static_cast<vmi_pid_t>(it->first.first >> 32) == pid)
            it = this->ret_hooks.erase(it);
        else
            ++it;
    }

    for (auto it = this->hooked.begin(); it != this->hooked.end(); )
    {
        if (it->second.pid != pid)
        {
            ++it;
            continue;
        }

        it = this->drop_hook(it);
    }
}

event_response_t libmon::function_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto plugin = get_trap_plugin<libmon>(info);

    auto it = plugin->hooked.find(info->trap);
    if (it == plugin->hooked.end())
    {
        PRINT_DEBUG("[LIBMON] hook hit for an unknown trap, ignoring\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    const auto& target = it->second;

    // The breakpoint lives in a physical page of libc, which every process
    // mapping the library shares, so this fires for processes we never hooked
    // -- and would fire once per hooked process if several share the page.
    // Report only for the process this hook was placed for.
    if (info->proc_data.pid != target.pid)
        return VMI_EVENT_RESPONSE_NONE;

    PRINT_DEBUG("[LIBMON] hook hit: pid %d rip=0x%lx (%s)\n",
        info->proc_data.pid, info->regs->rip,
        info->trap && info->trap->name ? info->trap->name : "?");

    // A hook firing is proof this process is on the vCPU, which is the one
    // condition page-fault injection needs.
    plugin->flush_deferred(drakvuf, info, info->proc_data.pid);

    // Read the arguments here, at entry: by the time the function returns its
    // stack frame is gone and the argument registers have been reused.
    const auto& config = *target.config;

    std::vector<uint64_t> arguments;
    arguments.reserve(config.argument_printers.size());
    for (size_t i = 1; i <= config.argument_printers.size(); i++)
        arguments.push_back(drakvuf_get_function_argument(drakvuf, info, i));

    if (plugin->no_retval || config.no_retval)
    {
        plugin->print_call(drakvuf, info, config, target.so_path, arguments, std::nullopt);
        return VMI_EVENT_RESPONSE_NONE;
    }

    auto hook = plugin->createReturnHook<return_data>(info, &libmon::function_return_hook_cb,
            info->trap->name, drakvuf_get_limited_traps_ttl(drakvuf));
    if (!hook)
    {
        // Report the call anyway, without a return value: losing one field
        // beats losing the event. Logged because the two look identical in
        // the output otherwise.
        PRINT_DEBUG("[LIBMON] pid %d: no return hook for %s, reporting at entry\n",
            info->proc_data.pid, config.function_name.c_str());

        plugin->print_call(drakvuf, info, config, target.so_path, arguments, std::nullopt);
        return VMI_EVENT_RESPONSE_NONE;
    }

    auto params = libhook::GetTrapParams<return_data>(hook->trap_);
    params->arguments = std::move(arguments);
    params->config = &config;
    params->so_path = target.so_path;

    plugin->ret_hooks[make_hook_id(info, params->target_rsp)] = std::move(hook);

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t libmon::function_return_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto params = libhook::GetTrapParams<return_data>(info);

    // The return address is shared by every call that reaches it, so check
    // this is the call instance we armed for rather than a recursive or
    // concurrent one.
    if (!params->verifyResultCallParams(drakvuf, info))
    {
        // Logged because a rejected return is indistinguishable in the output
        // from one that never fired, and the two mean very different things.
        PRINT_DEBUG("[LIBMON] return rejected: pid %d/%d tid %d/%d rip 0x%lx/0x%lx\n",
            info->proc_data.pid, params->target_pid,
            info->proc_data.tid, params->target_tid,
            info->regs->rip, params->target_rsp);

        return VMI_EVENT_RESPONSE_NONE;
    }

    PRINT_DEBUG("[LIBMON] return hit: pid %d %s -> 0x%lx\n",
        info->proc_data.pid, params->config->function_name.c_str(), info->regs->rax);

    this->print_call(drakvuf, info, *params->config, params->so_path,
        params->arguments, info->regs->rax);

    // Erasing destroys the ReturnHook, whose destructor removes the trap.
    // Safe from inside its own callback: libhook defers the deletion.
    this->ret_hooks.erase(make_hook_id(info, params->target_rsp));
    return VMI_EVENT_RESPONSE_NONE;
}

void libmon::print_call(drakvuf_t drakvuf, drakvuf_trap_info_t* info,
    const plugin_target_config_entry_t& config, const std::string& so_path,
    const std::vector<uint64_t>& arguments, std::optional<uint64_t> return_value)
{
    const auto& printers = config.argument_printers;

    std::vector<fmt::Rstr<std::string>> fmt_args;
    fmt_args.reserve(arguments.size());

    for (size_t i = 0; i < arguments.size() && i < printers.size(); i++)
        fmt_args.push_back(fmt::Rstr(printers[i]->print(drakvuf, info, arguments[i])));

    std::optional<fmt::Xval<uint64_t>> fmt_retval;
    if (return_value)
        fmt_retval = fmt::Xval(*return_value);

    // rip is the hooked function when reporting at entry, and the caller's
    // return address when reporting at return -- so with return values on,
    // FromModule names whoever made the call, as it does in apimon.
    std::optional<fmt::Qstr<std::string>> fmt_module;
    if (auto module = this->resolve_module(info->proc_data.pid, info->regs->rip))
        fmt_module = fmt::Qstr(*module);

    // No Function field: the output formatters already emit the trap's name
    // as Method, and the trap is named after the function.
    fmt::print(m_output_format, "libmon", drakvuf, info,
        keyval("Event", fmt::Rstr("api_called")),
        keyval("Library", fmt::Qstr(so_path)),
        keyval("CalledFrom", fmt::Xval(info->regs->rip)),
        keyval("ReturnValue", fmt_retval),
        keyval("FromModule", fmt_module),
        keyval("Arguments", fmt_args)
    );
}
