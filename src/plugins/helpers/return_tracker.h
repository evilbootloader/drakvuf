/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF (C) 2014-2024 Tamas K Lengyel.                                  *
 * Tamas K Lengyel is hereinafter referred to as the author.               *
 * This program is free software; you may redistribute and/or modify it    *
 * under the terms of the GNU General Public License as published by the   *
 * Free Software Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE   *
 * CLARIFICATIONS AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your   *
 * right to use, modify, and redistribute this software under certain      *
 * conditions.  If you wish to embed DRAKVUF technology into proprietary   *
 * software, alternative licenses can be acquired from the author.         *
 *                                                                         *
 * Note that the GPL places important restrictions on "derivative works",  *
 * yet it does not provide a detailed definition of that term.  To avoid   *
 * misunderstandings, we interpret that term as broadly as copyright law   *
 * allows.  For example, we consider an application to constitute a        *
 * derivative work for the purpose of this license if it does any of the   *
 * following with any software or content covered by this license          *
 * ("Covered Software"):                                                   *
 *                                                                         *
 * o Integrates source code from Covered Software.                         *
 *                                                                         *
 * o Reads or includes copyrighted data files.                             *
 *                                                                         *
 * o Is designed specifically to execute Covered Software and parse the    *
 * results (as opposed to typical shell or execution-menu apps, which will *
 * execute anything you tell them to).                                     *
 *                                                                         *
 * o Includes Covered Software in a proprietary executable installer.  The *
 * installers produced by InstallShield are an example of this.  Including *
 * DRAKVUF with other software in compressed or archival form does not     *
 * trigger this provision, provided appropriate open source decompression  *
 * or de-archiving software is widely available for no charge.  For the    *
 * purposes of this license, an installer is considered to include Covered *
 * Software even if it actually retrieves a copy of Covered Software from  *
 * another source during runtime (such as by downloading it from the       *
 * Internet).                                                              *
 *                                                                         *
 * o Links (statically or dynamically) to a library which does any of the  *
 * above.                                                                  *
 *                                                                         *
 * o Executes a helper program, module, or script to do any of the above.  *
 *                                                                         *
 * This list is not exclusive, but is meant to clarify our interpretation  *
 * of derived works with some common examples.  Other people may interpret *
 * the plain GPL differently, so we consider this a special exception to   *
 * the GPL that we apply to Covered Software.  Works which meet any of     *
 * these conditions must conform to all of the terms of this license,      *
 * particularly including the GPL Section 3 requirements of providing      *
 * source code and allowing free redistribution of the work as a whole.    *
 *                                                                         *
 * Any redistribution of Covered Software, including any derived works,    *
 * must obey and carry forward all of the terms of this license, including *
 * obeying all GPL rules and restrictions.  For example, source code of    *
 * the whole work must be provided and free redistribution must be         *
 * allowed.  All GPL references to "this License", are to be treated as    *
 * including the terms and conditions of this license text as well.        *
 *                                                                         *
 * Because this license imposes special exceptions to the GPL, Covered     *
 * Work may not be combined (even as part of a larger work) with plain GPL *
 * software.  The terms, conditions, and exceptions of this license must   *
 * be included as well.  This license is incompatible with some other open *
 * source licenses as well.  In some cases we can relicense portions of    *
 * DRAKVUF or grant special permissions to use it in other open source     *
 * software.  Please contact tamas.k.lengyel@gmail.com with any such       *
 * requests.  Similarly, we don't incorporate incompatible open source     *
 * software into Covered Software without special permission from the      *
 * copyright holders.                                                      *
 *                                                                         *
 * If you have any questions about the licensing restrictions on using     *
 * DRAKVUF in other works, are happy to help.  As mentioned above,         *
 * alternative license can be requested from the author to integrate       *
 * DRAKVUF into proprietary applications and appliances.  Please email     *
 * tamas.k.lengyel@gmail.com for further information.                      *
 *                                                                         *
 * If you have received a written license agreement or contract for        *
 * Covered Software stating terms other than these, you may choose to use  *
 * and redistribute Covered Software under those terms instead of these.   *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes.          *
 *                                                                         *
 * Source code also allows you to port DRAKVUF to new platforms, fix bugs, *
 * and add new features.  You are highly encouraged to submit your changes *
 * on https://github.com/tklengyel/drakvuf, or by other methods.           *
 * By sending these changes, it is understood (unless you specify          *
 * otherwise) that you are offering unlimited, non-exclusive right to      *
 * reuse, modify, and relicense the code.  DRAKVUF will always be          *
 * available Open Source, but this is important because the inability to   *
 * relicense code has caused devastating problems for other Free Software  *
 * projects (such as KDE and NASM).                                        *
 * To specify special license conditions of your contributions, just say   *
 * so when you send them.                                                  *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the DRAKVUF   *
 * license file for more details (it's in a COPYING file included with     *
 * DRAKVUF, and also available from                                        *
 * https://github.com/tklengyel/drakvuf/COPYING)                           *
 *                                                                         *
 ***************************************************************************/

#pragma once

#include <algorithm>
#include <functional>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <utility>
#include <vector>

#include <glib.h>
#include <libdrakvuf/libdrakvuf.h>
#include "plugins/plugins_ex.h"
#include "plugins/helpers/vmi_lock_guard.h"

/*
 * Catches the returns of hooked calls without a breakpoint per call, like
 * sysret mode kernel of the syscalls plugin: one breakpoint per return
 * address, shared by all calls returning through it, and the calls in
 * progress per thread to match the returns hitting it. The tracker locks its
 * own state and calls back without its locks, so the breakpoints can be
 * mt_safe.
 *
 * Kernel return addresses are few and stay mapped, their breakpoints stay
 * until the plugin is destroyed. User mode ones are many, and their pages can
 * be unmapped and reused: a breakpoint is removed when no call returned
 * through it for a while. A return address in memory that is written, such as
 * JIT code, is tracked as transient instead: each write to a page with a
 * breakpoint pauses the VM to copy the page again, so its breakpoint is removed
 * as soon as no call is returning through it.
 */
enum class return_tracker_mode
{
    kernel,
    user,
};

// Whether a call is tracked to its return, and why not
enum class return_track_result
{
    tracked,
    untranslated,       // the return address is not mapped
    no_trap,            // the breakpoint could not be added
};

// Return breakpoint params, the tracker the breakpoint belongs to
struct return_tracker_params : public call_result_t
{
    void* tracker = nullptr;
};

template<typename Payload>
class return_tracker
{
public:
    // The return of a call, info is that of the return breakpoint
    using return_cb_t = std::function<void(drakvuf_t, drakvuf_trap_info_t*, Payload&)>;

    // Calls a thread can have in progress, more are only left behind by calls that never return
    static constexpr size_t max_pending_per_thread = 64;
    // User mode: how long a breakpoint no call returns through stays, and how many there can be
    static constexpr gint64 idle_us = 2 * G_USEC_PER_SEC;
    static constexpr size_t max_user_traps = 4096;

    // mt_safe: cb may run on several vCPU threads at once, otherwise it is serialized like other callbacks
    return_tracker(pluginex& plugin, return_tracker_mode mode, const char* trap_name, return_cb_t cb, bool mt_safe = true)
        : plugin{ plugin }, mode{ mode }, trap_name{ trap_name }, cb{ std::move(cb) }, mt_safe{ mt_safe },
          os{ drakvuf_get_os_type(plugin.drakvuf) }
    {
    }

    return_tracker(const return_tracker&) = delete;
    return_tracker& operator=(const return_tracker&) = delete;

    /*
     * At the entry of a hooked call, which returns to ret_addr. The thread is
     * paused until the callback returns, so the call is recorded before it can
     * return. With parallel events this can run on several vCPU threads.
     * User mode: transient for a return address outside file-backed code, and
     * always for one in memory that is not executable.
     */
    return_track_result track(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t ret_addr, Payload payload,
        bool transient = false)
    {
        addr_t ret_pa = 0;
        bool executable = true;
        if (auto result = translate(drakvuf, info, ret_addr, &ret_pa, &executable); result != return_track_result::tracked)
            return result;

        // The call itself may make it executable, as a ROP chain does that has
        // VirtualProtect or mprotect return into its shellcode. Or the function
        // was not called and [rsp] is data, maybe on the stack: a breakpoint kept
        // there would copy the page again on every write to it, with the VM paused.
        if (!executable)
        {
            PRINT_DEBUG("[RETURN-TRACKER] Return address 0x%lx is not executable, tracked as transient\n", ret_addr);
            transient = true;
        }

        if (!reserve_trap(ret_pa, transient && mode == return_tracker_mode::user))
            return return_track_result::no_trap;

        std::vector<addr_t> dropped;
        {
            addr_t target_rsp = info->regs->rsp;
            std::lock_guard<std::mutex> lock(pending_mtx);
            auto& calls = pending[thread_key(info)];

            // A call that entered at or below this stack position has been left without returning,
            // for example by an exception. Calls further up are in progress, this one is nested in them.
            calls.erase(std::remove_if(calls.begin(), calls.end(), [&](const pending_call& call)
            {
                if (call.target_rsp > target_rsp)
                    return false;
                dropped.push_back(call.ret_pa);
                return true;
            }), calls.end());

            if (calls.size() >= max_pending_per_thread)
            {
                dropped.push_back(calls.front().ret_pa);
                calls.erase(calls.begin());
            }

            calls.push_back(pending_call{ ret_pa, target_rsp, std::move(payload) });
        }
        release_traps(dropped);
        return return_track_result::tracked;
    }

    // Drops the calls of a process that never returned
    void forget_process(vmi_pid_t pid)
    {
        std::vector<addr_t> dropped;
        {
            std::lock_guard<std::mutex> lock(pending_mtx);
            for (auto it = pending.begin(); it != pending.end();)
            {
                if (static_cast<vmi_pid_t>(it->first >> 32) != pid)
                {
                    ++it;
                    continue;
                }
                for (const auto& call : it->second)
                    dropped.push_back(call.ret_pa);
                it = pending.erase(it);
            }
        }
        release_traps(dropped);
    }

private:
    struct pending_call
    {
        addr_t ret_pa;
        addr_t target_rsp;      // stack pointer at entry, the return is matched against it
        Payload payload;
    };

    struct return_trap
    {
        drakvuf_trap_t* trap;
        unsigned pending;       // calls in progress returning through it
        gint64 idle_since;      // user mode: when pending dropped to 0
        bool transient;         // user mode: removed when pending drops to 0
    };

    pluginex& plugin;
    const return_tracker_mode mode;
    const char* const trap_name;
    const return_cb_t cb;
    const bool mt_safe;
    const os_t os;

    std::mutex pending_mtx;
    std::unordered_map<uint64_t, std::vector<pending_call>> pending; // key: pid << 32 | tid

    std::mutex traps_mtx;
    std::unordered_map<addr_t, return_trap> traps;      // key: physical address
    std::unordered_map<addr_t, addr_t> kernel_pa;       // kernel mode: virtual to physical address
    gint64 last_sweep = 0;

    // The thread as each OS identifies it for return context checks
    const proc_data_t& thread_proc(const drakvuf_trap_info_t* info) const
    {
        return os == VMI_OS_WINDOWS ? info->attached_proc_data : info->proc_data;
    }

    uint64_t thread_key(const drakvuf_trap_info_t* info) const
    {
        const proc_data_t& proc = thread_proc(info);
        return (uint64_t)(uint32_t)proc.pid << 32 | proc.tid;
    }

    // No level of the 64-bit page tables sets the no-execute bit. Other paging modes are taken as executable.
    static bool is_executable(drakvuf_t drakvuf, const page_info_t& page)
    {
        if (drakvuf_get_page_mode(drakvuf) != VMI_PM_IA32E)
            return true;

        // VMI_GET_BIT doesn't parenthesize its argument, so combine the entries first
        const auto& entries = page.x86_ia32e;
        addr_t levels = entries.pml4e_value | entries.pdpte_value | entries.pgd_value | entries.pte_value;
        return !VMI_GET_BIT(levels, 63);
    }

    // Kernel addresses translate the same in every process, so they are looked up once
    return_track_result translate(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t va, addr_t* pa, bool* executable)
    {
        if (mode == return_tracker_mode::kernel)
        {
            std::lock_guard<std::mutex> lock(traps_mtx);
            auto it = kernel_pa.find(va);
            if (it != kernel_pa.end())
            {
                *pa = it->second;
                return return_track_result::tracked;
            }
        }

        {
            vmi_reader_guard vmi(drakvuf);
            page_info_t page = {};
            if (VMI_SUCCESS != vmi_pagetable_lookup_extended(vmi, info->regs->cr3, va, &page))
            {
                PRINT_DEBUG("[RETURN-TRACKER] Failed to translate return address 0x%lx\n", va);
                return return_track_result::untranslated;
            }
            *pa = page.paddr;

            if (mode == return_tracker_mode::user)
                *executable = is_executable(drakvuf, page);
        }

        if (mode == return_tracker_mode::kernel)
        {
            std::lock_guard<std::mutex> lock(traps_mtx);
            kernel_pa.emplace(va, *pa);
        }
        return return_track_result::tracked;
    }

    // Counts a call returning through the breakpoint at pa, adding it first if needed
    bool reserve_trap(addr_t pa, bool transient)
    {
        if (reserve_existing(pa, transient))
            return true;

        // Added without traps_mtx held: adding takes the VMI lock, which callers may already hold
        auto trap = plugin.register_prepared_trap<return_tracker_params>(nullptr, return_hit,
                [pa](drakvuf_t drakvuf, drakvuf_trap_info_t*, drakvuf_trap_t* new_trap) -> drakvuf_trap_t*
        {
            new_trap->type = BREAKPOINT;
            new_trap->breakpoint.lookup_type = LOOKUP_NONE;
            new_trap->breakpoint.addr_type = ADDR_PA;
            new_trap->breakpoint.addr = pa;
            return drakvuf_add_trap(drakvuf, new_trap) ? new_trap : nullptr;
        },
        trap_name,
        [this](drakvuf_trap_t* new_trap, return_tracker_params* params)
        {
            // Every return through this address hits it, it must not be unhooked as api-hammering
            new_trap->ttl = UNLIMITED_TTL;
            new_trap->mt_safe = this->mt_safe;
            params->tracker = this;
        });

        if (!trap)
        {
            PRINT_DEBUG("[RETURN-TRACKER] Failed to trap returns at PA 0x%lx\n", pa);
            return false;
        }

        std::vector<drakvuf_trap_t*> evicted;
        bool duplicate = false;
        {
            std::lock_guard<std::mutex> lock(traps_mtx);
            // Another vCPU thread may have added one for this address meanwhile
            auto [it, added] = traps.try_emplace(pa, return_trap{ trap, 0, 0, transient });
            duplicate = !added;
            count_call(it->second, transient);
            if (added)
                sweep(evicted);
        }

        if (duplicate)
            plugin.destroy_trap(trap);
        for (auto old : evicted)
            plugin.destroy_trap(old);
        return true;
    }

    bool reserve_existing(addr_t pa, bool transient)
    {
        std::lock_guard<std::mutex> lock(traps_mtx);
        auto it = traps.find(pa);
        if (it == traps.end())
            return false;
        count_call(it->second, transient);
        return true;
    }

    // Call with traps_mtx held. A breakpoint stays once a call needs it to.
    void count_call(return_trap& entry, bool transient)
    {
        entry.pending++;
        if (!transient)
            entry.transient = false;
    }

    // The calls returning through these breakpoints are gone
    void release_traps(const std::vector<addr_t>& pas)
    {
        if (pas.empty())
            return;

        std::vector<drakvuf_trap_t*> evicted;
        {
            std::lock_guard<std::mutex> lock(traps_mtx);
            gint64 now = g_get_monotonic_time();
            for (addr_t pa : pas)
            {
                auto it = traps.find(pa);
                if (it == traps.end() || !it->second.pending || --it->second.pending)
                    continue;

                if (it->second.transient)
                {
                    evicted.push_back(it->second.trap);
                    traps.erase(it);
                }
                else
                    it->second.idle_since = now;
            }
        }

        for (auto trap : evicted)
            plugin.destroy_trap(trap);
    }

    /*
     * User mode: collects the breakpoints that were idle long enough, and the
     * longest idle ones above the limit. At most every 100 ms. Call with
     * traps_mtx held, destroy the collected traps without it.
     */
    void sweep(std::vector<drakvuf_trap_t*>& evicted)
    {
        if (mode != return_tracker_mode::user)
            return;

        gint64 now = g_get_monotonic_time();
        if (now - last_sweep < G_USEC_PER_SEC / 10 && traps.size() <= max_user_traps)
            return;
        last_sweep = now;

        for (auto it = traps.begin(); it != traps.end();)
        {
            if (!it->second.pending && now - it->second.idle_since >= idle_us)
            {
                evicted.push_back(it->second.trap);
                it = traps.erase(it);
            }
            else
                ++it;
        }

        while (traps.size() > max_user_traps)
        {
            auto oldest = traps.end();
            for (auto it = traps.begin(); it != traps.end(); ++it)
                if (!it->second.pending && (oldest == traps.end() || it->second.idle_since < oldest->second.idle_since))
                    oldest = it;
            if (oldest == traps.end())
                break;
            evicted.push_back(oldest->second.trap);
            traps.erase(oldest);
        }
    }

    // The innermost call of the thread returning through this breakpoint, with the deeper ones dropped
    std::optional<Payload> take(drakvuf_trap_info_t* info)
    {
        addr_t rsp = info->regs->rsp;
        std::optional<Payload> found;
        std::vector<addr_t> dropped;
        {
            std::lock_guard<std::mutex> lock(pending_mtx);
            auto it = pending.find(thread_key(info));
            if (it == pending.end())
                return {};

            // The one that entered at the highest stack position not above the current one.
            // Calls further up are still in progress.
            auto& calls = it->second;
            auto match = calls.end();
            for (auto call = calls.begin(); call != calls.end(); ++call)
            {
                if (call->ret_pa != info->trap_pa || call->target_rsp > rsp)
                    continue;
                if (match == calls.end() || call->target_rsp > match->target_rsp)
                    match = call;
            }
            if (match == calls.end())
                return {};

            addr_t match_rsp = match->target_rsp;
            found = std::move(match->payload);

            // Drop it, and the calls that entered deeper on the stack: their frames are gone
            calls.erase(std::remove_if(calls.begin(), calls.end(), [&](const pending_call& call)
            {
                if (call.target_rsp > match_rsp)
                    return false;
                dropped.push_back(call.ret_pa);
                return true;
            }), calls.end());

            if (calls.empty())
                pending.erase(it);
        }
        release_traps(dropped);
        return found;
    }

    static event_response_t return_hit(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
    {
        auto params = get_trap_params<return_tracker_params>(info);
        if (!params || !params->tracker)
            return VMI_EVENT_RESPONSE_NONE;

        auto tracker = static_cast<return_tracker<Payload>*>(params->tracker);

        // Returns of calls we didn't see entering, or of other threads, are ignored
        auto payload = tracker->take(info);
        if (payload)
            tracker->cb(drakvuf, info, *payload);

        return VMI_EVENT_RESPONSE_NONE;
    }
};
