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
        nullptr);

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

void libmon::on_so_discovered(drakvuf_t drakvuf, drakvuf_trap_info_t* info, const so_view_t& so)
{
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
                    deferred_hook{ &entry, so.path, so.base, so.proc_base, 0, 0 });

                PRINT_DEBUG("[LIBMON] pid %d: deferring %s!%s, symbol table not readable yet\n",
                    so.pid, entry.dll_name.c_str(), entry.function_name.c_str());
                return;
            }
        }

        if (this->place_hook(drakvuf, info, so.pid, entry, so.path, va))
            return;

        // A breakpoint can only be placed on a resident page, and this
        // function has simply never been called, so nothing has faulted its
        // page in. Defer it and fault the page in later, from a callback that
        // actually runs in this process.
        this->deferred[so.pid].push_back(
            deferred_hook{ &entry, so.path, so.base, so.proc_base, va, 0 });

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
    const plugin_target_config_entry_t& entry, const std::string& so_path, addr_t va)
{
    auto key = std::make_pair(pid, va);
    if (this->hooked_keys.count(key))
        return true;

    auto trap = register_trap(info, &libmon::function_hook_cb,
            breakpoint_at_va_for_pid(pid, va), entry.function_name.c_str(), UNLIMITED_TTL);
    if (!trap)
        return false;

    this->hooked.emplace(trap, hooked_function{ &entry, so_path, pid, va, trap });
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

// The caller must be running in this process's own context:
// vmi_request_page_fault injects into the current vCPU, so doing this from the
// CR3 tick would fault an address in whatever address space happens to be live.
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

        if (target->va && this->place_hook(drakvuf, info, pid, *target->config,
                target->so_path, target->va))
        {
            target = targets.erase(target);
            continue;
        }

        if (++target->attempts > DEFERRED_MAX_ATTEMPTS)
        {
            PRINT_DEBUG("[LIBMON] pid %d: giving up on %s at 0x%lx\n", pid,
                target->config->function_name.c_str(), target->va);
            target = targets.erase(target);
            continue;
        }

        // No vmi_request_page_fault() here, deliberately. Injecting one does
        // fault the page in and the hook then places -- but it kills the
        // guest process. Every caller of this function is a breakpoint
        // callback, and DRAKVUF resumes from a breakpoint by switching altp2m
        // view and single-stepping the original instruction; taking an
        // injected fault instead derails that and execution returns to the
        // int3. libusermode carries injection-in-progress tracking and an
        // exception-suppression hook for exactly this, and a Linux equivalent
        // has to exist before injection can be done safely.
        //
        // So just retry: a cold page often becomes resident on its own,
        // because a neighbouring function in it gets called.
        ++target;
    }

    if (targets.empty())
        this->deferred.erase(it);
}

// The pid's address space is gone (exit, or a further exec), so every VA we
// resolved in it is now meaningless: remove the breakpoints rather than
// leaving them armed over whatever gets mapped there next.
void libmon::on_process_reset(vmi_pid_t pid)
{
    this->deferred.erase(pid);

    for (auto it = this->hooked.begin(); it != this->hooked.end(); )
    {
        if (it->second.pid != pid)
        {
            ++it;
            continue;
        }

        this->hooked_keys.erase(std::make_pair(it->second.pid, it->second.va));
        this->destroy_trap(it->second.trap);
        it = this->hooked.erase(it);
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

    const auto& printers = target.config->argument_printers;

    std::vector<fmt::Rstr<std::string>> fmt_args;
    fmt_args.reserve(printers.size());

    for (size_t i = 0; i < printers.size(); i++)
    {
        uint64_t arg = drakvuf_get_function_argument(drakvuf, info, i + 1);
        fmt_args.push_back(fmt::Rstr(printers[i]->print(drakvuf, info, arg)));
    }

    fmt::print(plugin->m_output_format, "libmon", drakvuf, info,
        keyval("Event", fmt::Rstr("api_called")),
        keyval("Library", fmt::Qstr(target.so_path)),
        keyval("CalledFrom", fmt::Xval(info->regs->rip)),
        keyval("Arguments", fmt_args)
    );

    return VMI_EVENT_RESPONSE_NONE;
}
