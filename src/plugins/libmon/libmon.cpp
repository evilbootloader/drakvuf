#include <algorithm>
#include <cinttypes>
#include <cstdio>

#include <libdrakvuf/libdrakvuf.h>

#include "libmon.h"
#include "plugins/output_format.h"
#include "plugins/helpers/vmi_lock_guard.h"
#include "libusermode/printers/printers.hpp"

// How many times to retry a hook whose page was cold before writing it off.
// An attempt is just a failed trap insertion, so this can be generous; it
// exists to bound the list rather than to ration anything expensive.
static constexpr unsigned DEFERRED_MAX_ATTEMPTS = 1000;

// Deferred hooks retried per CR3 tick and per hook hit. The tick is every
// context switch and stalls all vCPUs while it runs, so it works through a
// long list in turns rather than all of it each time.
static constexpr unsigned DEFERRED_TICK_BUDGET = 64;
static constexpr unsigned DEFERRED_HIT_BUDGET = 16;

// How often the retries look up symbols of a process whose symbol table could
// not be read: that reads the whole table.
static constexpr gint64 RESOLVE_INTERVAL_US = 50 * 1000;

// resolve_symbols(): the library doesn't define the symbol
static constexpr addr_t SYMBOL_ABSENT = ~(addr_t)0;

// Aux vector entry with the address of the executable's program headers
static constexpr uint64_t AUXV_AT_PHDR = 3;

/*
 * The guest changes page tables under us: a fork makes the stack copy-on-write,
 * and the kernel moves pages. A translation cached by an earlier event can then
 * point at a frame the process no longer uses, and reading [rsp] or an argument
 * through it returns old data. Drop the process's translations before reading
 * its memory, in the vCPU's reader instance and in the main one, which the
 * argument printers read through.
 */
static void flush_translations(drakvuf_t drakvuf, addr_t dtb)
{
    {
        vmi_reader_guard vmi(drakvuf);
        vmi_v2pcache_flush(vmi, dtb);
    }
    vmi_lock_guard vmi(drakvuf);
    vmi_v2pcache_flush(vmi, dtb);
}

libmon::libmon(drakvuf_t drakvuf, const libmon_config* c, output_format_t output)
    : pluginex(drakvuf, output)
    , returns(*this, return_tracker_mode::user, "libmon return",
          [this](drakvuf_t drakvuf_, drakvuf_trap_info_t* info, pending_call& call)
{
    flush_translations(drakvuf_, info->regs->cr3);
    this->print_call(drakvuf_, info, *call.config, call.so_path, call.arguments, info->regs->rax);
},
// Serialized like the other callbacks of libmon, which share its state
false)
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

    // Last, with the callbacks in place, since this reports the libraries those
    // processes already have. It has to happen at all because an injected
    // sample is one of them: main.cpp runs inject_cmd() before start_plugins(),
    // so the sample's exec is over before the hook above exists.
    this->rendezvous->adopt_running_processes(drakvuf);
}

bool libmon::stop_impl()
{
    if (!this->stats_logged)
    {
        this->stats_logged = true;

        // PRINT_DEBUG compiles to nothing in a release build, which would
        // leave this set and never read.
        [[maybe_unused]] auto s = this->rendezvous->stats();
        PRINT_DEBUG("[LIBMON] arming: %lu exec(s) + %lu adopted at startup,"
            " %lu armed (%lu from a known ld.so layout),"
            " %lu gave up, %lu tick(s) on %s, tick installed %.3f s\n",
            s.execs, s.adopted, s.armed, s.fast_armed, s.gave_up, s.ticks,
            s.used_cr3 ? "CR3 writes" : "page faults",
            s.installed_ns / 1e9);
        PRINT_DEBUG("[LIBMON] ld.so: %lu build(s) known (%lu at startup), %lu layout mismatch(es)\n",
            s.builds, s.bootstrapped, s.mismatches);
#ifdef DRAKVUF_DEBUG
        this->print_return_pages();
#endif
    }

    return pluginex::stop_impl();
}

std::optional<std::string> libmon::resolve_module(vmi_pid_t pid, addr_t addr) const
{
    auto proc = this->libs.find(pid);
    if (proc == this->libs.end())
        return std::nullopt;

    return resolve_module_in(proc->second.loaded, addr);
}

#ifdef DRAKVUF_DEBUG
void libmon::count_return_page(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t ret_addr, bool transient)
{
    addr_t pa = 0;
    {
        vmi_reader_guard vmi(drakvuf);
        if (VMI_SUCCESS != vmi_pagetable_lookup(vmi, info->regs->cr3, ret_addr, &pa))
            return;
    }

    auto [page, added] = this->return_pages.try_emplace(pa >> 12);
    if (added)
    {
        vmi_pid_t pid = info->proc_data.pid;
        std::string where = "anonymous";
        auto proc = this->libs.find(pid);
        if (auto module = this->resolve_module(pid, ret_addr))
            where = *module;
        else if (proc != this->libs.end() && ret_addr >= proc->second.exe_start && ret_addr < proc->second.exe_end)
            where = "executable";

        const char* name = info->proc_data.name;
        page->second = return_page{ pid, ret_addr, where + " (" + (name ? name : "?") + ")", transient, 0 };
    }
    page->second.calls++;
}

// On stderr with the trap statistics, which name the same pages
void libmon::print_return_pages() const
{
    std::vector<std::pair<addr_t, const return_page*>> pages;
    for (const auto& [page, info] : this->return_pages)
        pages.emplace_back(page, &info);
    std::sort(pages.begin(), pages.end(), [](const auto& a, const auto& b)
    {
        return a.second->calls > b.second->calls;
    });

    size_t transient = std::count_if(pages.begin(), pages.end(), [](const auto& page)
    {
        return page.second->transient;
    });
    fprintf(stderr, "[TRAP-STATS] libmon return pages: %zu, %zu of them transient (outside mapped files)\n",
        pages.size(), transient);
    fprintf(stderr, "[TRAP-STATS] %-16s %10s %-9s %7s %-18s  %s\n", "page", "calls", "transient", "pid", "address", "in");
    for (size_t i = 0; i < pages.size(); i++)
    {
        const auto& [page, info] = pages[i];
        fprintf(stderr, "[TRAP-STATS] 0x%-14" PRIx64 " %10" PRIu64 " %-9s %7d 0x%-16" PRIx64 "  %s\n",
            (uint64_t)(page << 12), info->calls, info->transient ? "yes" : "no", info->pid,
            (uint64_t)info->va, info->where.c_str());
    }
}
#endif

bool libmon::in_mapped_file(vmi_pid_t pid, addr_t addr) const
{
    auto proc = this->libs.find(pid);
    if (proc == this->libs.end())
        return false;

    if (addr >= proc->second.exe_start && addr < proc->second.exe_end)
        return true;

    return resolve_module_in(proc->second.loaded, addr).has_value();
}

std::string libmon::read_build_id(drakvuf_t drakvuf, addr_t proc_base, addr_t so_base)
{
    uint8_t id[64];
    size_t length = drakvuf_get_module_build_id(drakvuf, proc_base, so_base, id, sizeof(id));

    std::string hex;
    hex.reserve(length * 2);
    for (size_t i = 0; i < length; i++)
    {
        char byte[3];
        snprintf(byte, sizeof(byte), "%02x", id[i]);
        hex += byte;
    }
    return hex;
}

std::vector<addr_t> libmon::resolve_symbols(drakvuf_t drakvuf, addr_t proc_base, addr_t so_base,
    const std::string& build_id, const std::vector<const plugin_target_config_entry_t*>& entries)
{
    std::vector<addr_t> vas(entries.size(), 0);
    std::vector<size_t> lookup;
    auto known = build_id.empty() ? this->symbol_offsets.end() : this->symbol_offsets.find(build_id);

    for (size_t i = 0; i < entries.size(); i++)
    {
        if (entries[i]->type == HOOK_BY_OFFSET)
        {
            vas[i] = so_base + entries[i]->offset;
            continue;
        }

        if (known != this->symbol_offsets.end())
        {
            auto offset = known->second.find(entries[i]);
            if (offset != known->second.end())
            {
                vas[i] = offset->second ? so_base + offset->second : SYMBOL_ABSENT;
                continue;
            }
        }

        lookup.push_back(i);
    }

    if (lookup.empty())
        return vas;

    // Resolve against this .so's own .dynsym, using the load address the
    // dynamic linker reported in link_map.l_addr. Looking the library up by
    // name instead would go through the VMA list, which no longer exists in
    // its old form on Linux 6.1 and newer.
    std::vector<const char*> names;
    names.reserve(lookup.size());
    for (size_t i : lookup)
        names.push_back(entries[i]->function_name.c_str());

    std::vector<addr_t> found(lookup.size(), 0);
    bool complete = drakvuf_exportsyms_to_va_at_base(drakvuf, proc_base, so_base,
            names.data(), names.size(), found.data());

    for (size_t k = 0; k < lookup.size(); k++)
    {
        size_t i = lookup[k];
        if (found[k])
            vas[i] = found[k];
        else if (complete)
            vas[i] = SYMBOL_ABSENT;
        else
            // Not necessarily absent: we can arm before ld.so has read this
            // library's .dynsym, and an unreadable symbol table fails every
            // lookup in it at once. Retry later.
            continue;

        if (!build_id.empty())
            this->symbol_offsets[build_id][entries[i]] = found[k] ? found[k] - so_base : 0;
    }

    return vas;
}

void libmon::on_so_discovered(drakvuf_t drakvuf, drakvuf_trap_info_t* info, const so_view_t& so)
{
    // Read once, here: the program headers sit in the first mapped page, which
    // ld.so has just read itself, so this is the cheapest moment to ask. A
    // failure is not fatal -- resolve_module() falls back to a size cap.
    addr_t span = drakvuf_get_module_span(drakvuf, so.proc_base, so.base);
    std::string build_id = this->read_build_id(drakvuf, so.proc_base, so.base);

    auto [proc_it, new_process] = this->libs.try_emplace(so.pid);
    auto& proc = proc_it->second;
    proc.proc_base = so.proc_base;
    proc.dtb = so.dtb;

    // The program headers sit right behind the ELF header, in the first page of the executable
    if (new_process)
    {
        addr_t phdr = drakvuf_get_auxv_value(drakvuf, so.proc_base, AUXV_AT_PHDR);
        addr_t exe_base = phdr & ~(addr_t)(VMI_PS_4KB - 1);
        addr_t exe_span = phdr ? drakvuf_get_module_span(drakvuf, so.proc_base, exe_base) : 0;
        if (exe_span)
        {
            proc.exe_start = exe_base;
            proc.exe_end = exe_base + exe_span;
        }
    }

    proc.loaded[so.base] = loaded_so{ so.path, span ? so.base + span : 0 };
    proc.build_ids[so.base] = build_id;

    std::vector<const plugin_target_config_entry_t*> entries;
    this->wanted_hooks.visit_hooks_for(so.path, [&](const plugin_target_config_entry_t& entry)
    {
        entries.push_back(&entry);
    });
    if (entries.empty())
        return;

    auto vas = this->resolve_symbols(drakvuf, so.proc_base, so.base, build_id, entries);

    for (size_t i = 0; i < entries.size(); i++)
    {
        const auto& entry = *entries[i];
        addr_t va = vas[i];

        if (va == SYMBOL_ABSENT)
        {
            PRINT_DEBUG("[LIBMON] pid %d: %s doesn't define %s\n", so.pid, so.path.c_str(),
                entry.function_name.c_str());
            continue;
        }

        if (!va)
        {
            this->deferred[so.pid].push_back(
                deferred_hook{ &entry, so.path, so.base, so.proc_base, so.dtb, 0, 0, build_id });

            PRINT_DEBUG("[LIBMON] pid %d: deferring %s!%s, symbol table not readable yet\n",
                so.pid, entry.dll_name.c_str(), entry.function_name.c_str());
            continue;
        }

        if (this->place_hook(drakvuf, info, so.pid, so.dtb, entry, so.path, so.base, va))
            continue;

        // A breakpoint can only be placed on a resident page, and this
        // function has simply never been called, so nothing has faulted its
        // page in. Defer it and fault the page in later, from a callback that
        // actually runs in this process.
        this->deferred[so.pid].push_back(
            deferred_hook{ &entry, so.path, so.base, so.proc_base, so.dtb, va, 0, build_id });

        PRINT_DEBUG("[LIBMON] pid %d: deferring %s!%s at 0x%lx, page not resident\n", so.pid,
            entry.dll_name.c_str(), entry.function_name.c_str(), va);
    }

    // Retries are driven from the CR3 tick rather than from here, which runs
    // once per newly discovered library and would spend several of them in a
    // single event.
    if (!this->deferred.empty() && !this->cr3_hook)
        this->cr3_hook = createCr3Hook(&libmon::cr3_cb);
}

event_response_t libmon::cr3_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    // Every process with deferred hooks in turn, from where the last tick stopped
    std::vector<vmi_pid_t> pids;
    pids.reserve(this->deferred.size());
    for (auto it = this->deferred.lower_bound(this->next_deferred); it != this->deferred.end(); ++it)
        pids.push_back(it->first);
    for (auto it = this->deferred.begin(); it != this->deferred.end() && it->first < this->next_deferred; ++it)
        pids.push_back(it->first);

    unsigned budget = DEFERRED_TICK_BUDGET;
    for (auto pid : pids)
    {
        if (!budget)
        {
            this->next_deferred = pid;
            break;
        }
        this->flush_deferred(drakvuf, info, pid, budget);
    }

    if (this->deferred.empty())
        this->cr3_hook.reset();

    return VMI_EVENT_RESPONSE_NONE;
}

bool libmon::place_hook(drakvuf_t drakvuf, drakvuf_trap_info_t* info, vmi_pid_t pid, addr_t dtb,
    const plugin_target_config_entry_t& entry, const std::string& so_path,
    addr_t so_base, addr_t va, std::optional<addr_t> pa)
{
    auto key = std::make_pair(pid, va);
    if (this->hooked_keys.count(key))
        return true;

    addr_t hook_pa;
    if (pa)
        hook_pa = *pa;
    else
    {
        vmi_lock_guard vmi(drakvuf);
        if (VMI_SUCCESS != vmi_pagetable_lookup(vmi, dtb, va, &hook_pa))
            return false;
    }

    // Another process may have hooked the function in the same frame of the library already
    auto it = this->pa_hooks.find(hook_pa);
    if (it == this->pa_hooks.end())
    {
        drakvuf_trap_t* trap = register_trap(info, &libmon::function_hook_cb,
                breakpoint_at_pa(hook_pa), entry.function_name.c_str(), UNLIMITED_TTL);
        if (!trap)
            return false;

        it = this->pa_hooks.emplace(hook_pa, pa_hook{ trap, {} }).first;
    }

    it->second.by_pid[pid].push_back(hooked_function{ &entry, so_path, so_base, va });
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
    // Same path, but not necessarily the same file: a library can be replaced
    // on disk while the old inode stays mapped, and then the same offset is a
    // different function. Only a mapping with the same build ID is the same
    // file, a library without one is not reached through other processes.
    if (!target.va || target.build_id.empty())
        return std::nullopt;

    const addr_t offset = target.va - target.so_base;

    for (const auto& [other_pid, other] : this->libs)
    {
        if (other_pid == pid)
            continue;

        for (const auto& [other_base, build_id] : other.build_ids)
        {
            if (build_id != target.build_id)
                continue;

            addr_t pa = 0;
            {
                vmi_lock_guard vmi(drakvuf);
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
void libmon::flush_deferred(drakvuf_t drakvuf, drakvuf_trap_info_t* info, vmi_pid_t pid, unsigned& budget)
{
    auto it = this->deferred.find(pid);
    if (it == this->deferred.end() || !budget)
        return;

    auto& targets = it->second;

    // Still unresolved: the library's .dynsym was unreadable last time. One
    // lookup per library for all of them, and not more often than every
    // RESOLVE_INTERVAL_US, since that reads the whole symbol table.
    gint64 now = g_get_monotonic_time();
    auto& last = this->last_resolve[pid];
    if (now - last >= RESOLVE_INTERVAL_US)
    {
        last = now;

        std::map<addr_t, std::vector<deferred_hook*>> unresolved;   // by load address
        for (auto& target : targets)
            if (!target.va)
                unresolved[target.so_base].push_back(&target);

        for (auto& [so_base, hooks] : unresolved)
        {
            std::vector<const plugin_target_config_entry_t*> entries;
            for (auto hook : hooks)
                entries.push_back(hook->config);

            auto vas = this->resolve_symbols(drakvuf, hooks[0]->proc_base, so_base, hooks[0]->build_id, entries);
            for (size_t i = 0; i < hooks.size(); i++)
                hooks[i]->va = vas[i];
        }
    }

    for (auto target = targets.begin(); target != targets.end() && budget; )
    {
        if (target->va == SYMBOL_ABSENT)
        {
            PRINT_DEBUG("[LIBMON] pid %d: %s doesn't define %s\n", pid, target->so_path.c_str(),
                target->config->function_name.c_str());
            target = targets.erase(target);
            continue;
        }

        budget--;

        // Check residency ourselves before asking for the trap. Handing
        // drakvuf_add_trap() an address it cannot translate makes it log two
        // errors per attempt, and this retries on every hook hit, so a couple
        // of permanently cold pages otherwise bury the output.
        bool resident = false;
        if (target->va)
        {
            vmi_lock_guard vmi(drakvuf);
            page_info_t pinfo;
            resident = (VMI_SUCCESS == vmi_pagetable_lookup_extended(vmi, target->dtb,
                            target->va, &pinfo));
        }

        if (resident && this->place_hook(drakvuf, info, pid, target->dtb, *target->config,
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
                if (this->place_hook(drakvuf, info, pid, target->dtb, *target->config,
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
    {
        this->deferred.erase(it);
        this->last_resolve.erase(pid);
    }
}

template<typename Drop>
void libmon::drop_hooks(vmi_pid_t pid, Drop drop)
{
    for (auto it = this->pa_hooks.begin(); it != this->pa_hooks.end(); )
    {
        auto by_pid = it->second.by_pid.find(pid);
        if (by_pid != it->second.by_pid.end())
        {
            auto& hooks = by_pid->second;
            hooks.erase(std::remove_if(hooks.begin(), hooks.end(), [&](const hooked_function& hook)
            {
                if (!drop(hook))
                    return false;
                this->hooked_keys.erase(std::make_pair(pid, hook.va));
                return true;
            }), hooks.end());

            if (hooks.empty())
                it->second.by_pid.erase(by_pid);
        }

        // The last process with a hook here is gone
        if (it->second.by_pid.empty())
        {
            this->destroy_trap(it->second.trap);
            it = this->pa_hooks.erase(it);
        }
        else
            ++it;
    }
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
        proc->second.build_ids.erase(so.base);
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
        {
            this->deferred.erase(deferred_it);
            this->last_resolve.erase(so.pid);
        }
    }

    // Calls still in flight are deliberately left alone. Their return
    // addresses are in whoever called into this library, which is still
    // mapped, so they can still complete -- and a dlclose from inside a
    // hooked function is exactly the case that would lose an event here.

    [[maybe_unused]] unsigned dropped = 0;
    this->drop_hooks(so.pid, [&](const hooked_function& hook)
    {
        if (hook.so_base != so.base)
            return false;
        dropped++;
        return true;
    });

    PRINT_DEBUG("[LIBMON] pid %d: %s unloaded, dropped %u hook(s)\n",
        so.pid, so.path.c_str(), dropped);
}

// The pid's address space is gone (exit, or a further exec), so every VA we
// resolved in it is now meaningless: remove the breakpoints rather than
// leaving them armed over whatever gets mapped there next.
void libmon::on_process_reset(vmi_pid_t pid)
{
    this->deferred.erase(pid);
    this->last_resolve.erase(pid);
    this->libs.erase(pid);

    // Drop any call still in flight: its return address belongs to an address
    // space that no longer exists.
    this->returns.forget_process(pid);

    this->drop_hooks(pid, [](const hooked_function&)
    {
        return true;
    });
}

event_response_t libmon::function_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto plugin = get_trap_plugin<libmon>(info);

    auto it = plugin->pa_hooks.find(info->trap_pa);
    if (it == plugin->pa_hooks.end() || it->second.trap != info->trap)
    {
        PRINT_DEBUG("[LIBMON] hook hit for an unknown trap, ignoring\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    // The breakpoint lives in a physical page of libc, which every process
    // mapping the library shares, so this fires for processes we never hooked.
    // Report only the hooks of the process running.
    auto hooks = it->second.by_pid.find(info->proc_data.pid);
    if (hooks == it->second.by_pid.end())
        return VMI_EVENT_RESPONSE_NONE;

    // Copied: retrying the deferred hooks below may add to this breakpoint's
    std::vector<hooked_function> targets = hooks->second;

    flush_translations(drakvuf, info->regs->cr3);

    PRINT_DEBUG("[LIBMON] hook hit: pid %d rip=0x%lx (%s)\n",
        info->proc_data.pid, info->regs->rip,
        info->trap && info->trap->name ? info->trap->name : "?");

    // A hook firing is proof this process is on the vCPU, which is the one
    // condition page-fault injection needs.
    unsigned budget = DEFERRED_HIT_BUDGET;
    plugin->flush_deferred(drakvuf, info, info->proc_data.pid, budget);

    for (const auto& target : targets)
        plugin->on_call(drakvuf, info, target);

    return VMI_EVENT_RESPONSE_NONE;
}

void libmon::on_call(drakvuf_t drakvuf, drakvuf_trap_info_t* info, const hooked_function& target)
{
    // Read the arguments here, at entry: by the time the function returns its
    // stack frame is gone and the argument registers have been reused.
    const auto& config = *target.config;

    std::vector<uint64_t> arguments;
    arguments.reserve(config.argument_printers.size());
    for (size_t i = 1; i <= config.argument_printers.size(); i++)
        arguments.push_back(drakvuf_get_function_argument(drakvuf, info, i));

    if (this->no_retval || config.no_retval)
    {
        this->print_call(drakvuf, info, config, target.so_path, arguments, std::nullopt);
        return;
    }

    // One breakpoint per return address, shared by the calls returning there.
    // Kept between calls only in code mapped from a file: writing to the page
    // of a breakpoint pauses the VM to copy it again, which JIT code does a lot.
    addr_t ret_addr = drakvuf_get_function_return_address(drakvuf, info);
    bool transient = !this->in_mapped_file(info->proc_data.pid, ret_addr);
#ifdef DRAKVUF_DEBUG
    if (ret_addr)
        this->count_return_page(drakvuf, info, ret_addr, transient);
#endif
    auto result = ret_addr
        ? this->returns.track(drakvuf, info, ret_addr, pending_call{ &config, target.so_path, arguments }, transient)
        : return_track_result::untranslated;
    if (result != return_track_result::tracked)
    {
        // Report the call anyway, without a return value: losing one field
        // beats losing the event. Logged because the two look identical in
        // the output otherwise.
        PRINT_DEBUG("[LIBMON] pid %d: no return hook for %s, reporting at entry\n",
            info->proc_data.pid, config.function_name.c_str());

        this->print_call(drakvuf, info, config, target.so_path, arguments, std::nullopt);
    }
}

void libmon::print_call(drakvuf_t drakvuf, drakvuf_trap_info_t* info,
    const plugin_target_config_entry_t& config, const std::string& so_path,
    const std::vector<uint64_t>& arguments, std::optional<uint64_t> return_value)
{
    // The output formatters emit the trap's name as Method, and both the hook
    // and the return breakpoint are shared, so name a copy after the function.
    drakvuf_trap_t trap = *info->trap;
    trap.name = config.function_name.c_str();
    drakvuf_trap_info_t call_info = *info;
    call_info.trap = &trap;

    const auto& printers = config.argument_printers;

    std::vector<fmt::Rstr<std::string>> fmt_args;
    fmt_args.reserve(arguments.size());

    for (size_t i = 0; i < arguments.size() && i < printers.size(); i++)
        fmt_args.push_back(fmt::Rstr(printers[i]->print(drakvuf, &call_info, arguments[i])));

    std::optional<fmt::Xval<uint64_t>> fmt_retval;
    if (return_value)
        fmt_retval = fmt::Xval(*return_value);

    // rip is the hooked function when reporting at entry, and the caller's
    // return address when reporting at return -- so with return values on,
    // FromModule names whoever made the call, as it does in apimon.
    std::optional<fmt::Qstr<std::string>> fmt_module;
    if (auto module = this->resolve_module(call_info.proc_data.pid, call_info.regs->rip))
        fmt_module = fmt::Qstr(*module);

    // No Function field: the output formatters already emit the trap's name
    // as Method.
    fmt::print(m_output_format, "libmon", drakvuf, &call_info,
        keyval("Event", fmt::Rstr("api_called")),
        keyval("Library", fmt::Qstr(so_path)),
        keyval("CalledFrom", fmt::Xval(call_info.regs->rip)),
        keyval("ReturnValue", fmt_retval),
        keyval("FromModule", fmt_module),
        keyval("Arguments", fmt_args)
    );
}