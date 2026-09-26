#include <libdrakvuf/libdrakvuf.h>

#include "libmon.h"
#include "plugins/output_format.h"
#include "libusermode/printers/printers.hpp"

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
                PRINT_DEBUG("[LIBMON] pid %d: failed to resolve %s!%s\n", so.pid,
                    entry.dll_name.c_str(), entry.function_name.c_str());
                return;
            }
        }

        auto key = std::make_pair(so.pid, va);
        if (this->hooked.find(key) != this->hooked.end())
            return;

        auto trap = register_trap(info, &libmon::function_hook_cb,
                breakpoint_at_va_for_pid(so.pid, va), entry.function_name.c_str(), UNLIMITED_TTL);
        if (!trap)
        {
            PRINT_DEBUG("[LIBMON] pid %d: failed to hook %s!%s at 0x%lx\n", so.pid,
                entry.dll_name.c_str(), entry.function_name.c_str(), va);
            return;
        }

        this->hooked.emplace(key, hooked_function{ &entry, so.path, trap });

        fmt::print(m_output_format, "libmon", drakvuf, info,
            keyval("Event", fmt::Rstr("hook_placed")),
            keyval("Library", fmt::Qstr(so.path)),
            keyval("Function", fmt::Qstr(entry.function_name)),
            keyval("Address", fmt::Xval(va))
        );
    });
}

// The pid's address space is gone (exit, or a further exec), so every VA we
// resolved in it is now meaningless: remove the breakpoints rather than
// leaving them armed over whatever gets mapped there next.
void libmon::on_process_reset(vmi_pid_t pid)
{
    for (auto it = this->hooked.begin(); it != this->hooked.end(); )
    {
        if (it->first.first != pid)
        {
            ++it;
            continue;
        }

        this->destroy_trap(it->second.trap);
        it = this->hooked.erase(it);
    }
}

event_response_t libmon::function_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto plugin = get_trap_plugin<libmon>(info);

    auto it = plugin->hooked.find(std::make_pair(info->proc_data.pid, info->regs->rip));
    if (it == plugin->hooked.end())
        return VMI_EVENT_RESPONSE_NONE;

    const auto& target = it->second;
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
