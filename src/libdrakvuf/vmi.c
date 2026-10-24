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

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <inttypes.h>
#include <glib.h>
#include <err.h>
#include <errno.h>

#include <libvmi/libvmi.h>
#include <libvmi/peparse.h>
#include <libvmi/slat.h>

#include "../xen_helper/xen_helper.h"

#include "private.h"
#include "libdrakvuf.h"
#include "vmi.h"
#include "trap_stats.h"

static uint8_t bp = TRAP;

__thread vmi_instance_t drakvuf_tls_reader;

static inline void flush_caches(vmi_instance_t vmi)
{
    vmi_v2pcache_flush(vmi, ~0ull);
    vmi_pidcache_flush(vmi);
    vmi_rvacache_flush(vmi);
    vmi_symcache_flush(vmi);
}

/* Call with the VMI lock held */
static inline void flush_vmi(drakvuf_t drakvuf)
{
    drakvuf->flush_counter++;

    if ( !(drakvuf->flush_counter % VMI_FLUSH_RATE) )
    {
        flush_caches(drakvuf->vmi);
        drakvuf->flush_counter = 0;
    }
}

/*
 * Start and end of a LibVMI callback. With parallel events the thread reads
 * guest memory with the reader instance of the event's vCPU, which no other
 * thread uses because LibVMI runs all events of a vCPU on the same thread.
 */
static inline void reader_enter(drakvuf_t drakvuf, vmi_event_t* event)
{
    if ( !drakvuf->parallel_events || event->vcpu_id >= MAX_DRAKVUF_VCPU )
        return;

    drakvuf_tls_reader = drakvuf->reader_vmi[event->vcpu_id];
    if ( !drakvuf_tls_reader )
        return;

    if ( !(++drakvuf->reader_flush_counter[event->vcpu_id] % VMI_FLUSH_RATE) )
    {
        flush_caches(drakvuf_tls_reader);
        drakvuf->reader_flush_counter[event->vcpu_id] = 0;
    }
}

static inline void reader_exit(void)
{
    drakvuf_tls_reader = NULL;
}

/*
 * Callbacks other than breakpoints hold the VMI lock throughout. With
 * parallel events they are also serialized against the callbacks of traps
 * that aren't mt_safe on other vCPU threads.
 */
static inline void serial_callback_enter(drakvuf_t drakvuf, vmi_event_t* event)
{
    if ( drakvuf->parallel_events )
    {
        gint64 start = trap_stats_now();
        g_mutex_lock(&drakvuf->serial_cb_lock);
        trap_stats_serial_event_wait(trap_stats_now() - start);
        reader_enter(drakvuf, event);
    }
    drakvuf_lock_and_get_vmi(drakvuf);
}

/*
 * Runs the callback of a trap. Debug builds count it in the trap statistics,
 * for the plugin that added the trap, which also owns the traps added by the
 * callback.
 */
static inline event_response_t call_trap_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info, gint64 serial_wait_ns)
{
#ifdef DRAKVUF_DEBUG
    return trap_stats_call(drakvuf, info, serial_wait_ns);
#else
    UNUSED(serial_wait_ns);
    return info->trap->cb(drakvuf, info);
#endif
}

static inline void serial_callback_exit(drakvuf_t drakvuf)
{
    drakvuf_release_vmi(drakvuf);
    if ( drakvuf->parallel_events )
    {
        reader_exit();
        g_mutex_unlock(&drakvuf->serial_cb_lock);
    }
}

/* With parallel events a removed trap stays listed until all vCPU threads are idle */
static inline bool trap_is_removed(drakvuf_trap_t* trap)
{
    return g_atomic_int_get(&trap->removed);
}

static void free_proc_data_priv_2(proc_data_priv_t* proc_data, proc_data_priv_t* attached_proc_data)
{
    if (proc_data)
        g_free((gpointer)proc_data->name);
    if (attached_proc_data)
        g_free((gpointer)attached_proc_data->name);
}

static void copy_proc_data_from_priv(proc_data_t* proc_data, proc_data_priv_t* proc_data_priv)
{
    proc_data->base_addr = proc_data_priv->base_addr;
    proc_data->name      = proc_data_priv->name;
    proc_data->pid       = proc_data_priv->pid;
    proc_data->ppid      = proc_data_priv->ppid;
    proc_data->userid    = proc_data_priv->userid;
    proc_data->tid       = proc_data_priv->tid;
    proc_data->bitness   = proc_data_priv->bitness;
}

/*
 * This function gets called from the singlestep event
 * after an int3 or a read event happens.
 */
static event_response_t vmi_reset_trap(vmi_instance_t vmi, vmi_event_t* event)
{
    UNUSED(vmi);
    drakvuf_t drakvuf = (drakvuf_t)event->data;
    uint16_t view = drakvuf->altp2m_idx;

    if (drakvuf->enable_cr3_based_interception && !drakvuf->vcpu_monitor[event->vcpu_id])
        view = drakvuf->altp2m_idrx;

    PRINT_DEBUG("reset trap on vCPU %u, switching altp2m %u->%u\n", event->vcpu_id, event->slat_id, view);
    event->slat_id = view;

    return VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP | // Turn off singlestep
        VMI_EVENT_RESPONSE_SLAT_ID;
}

/*
 * Loop through the table, call the free_routine (if any)
 * any free the wrapper.
 */
void drakvuf_free_removed_traps(drakvuf_t drakvuf)
{
    GHashTableIter i;
    addr_t* key = NULL;
    struct free_trap_wrapper* free_wrapper = NULL;

    ghashtable_foreach(drakvuf->remove_traps, i, key, free_wrapper)
    {
        remove_trap(drakvuf, free_wrapper->trap);
        if (free_wrapper->free_routine)
            free_wrapper->free_routine(free_wrapper->trap);
        g_slice_free(struct free_trap_wrapper, free_wrapper);
    }

    g_hash_table_destroy(drakvuf->remove_traps);
    drakvuf->remove_traps = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);
}

/*
 * At the end of a callback. With parallel events other vCPU threads may still
 * run callbacks of the removed traps, they are freed in
 * drakvuf_vmi_event_callback instead.
 */
static inline
void process_free_requests(drakvuf_t drakvuf)
{
    if ( !drakvuf->parallel_events )
        drakvuf_free_removed_traps(drakvuf);
}

static bool refresh_shadow_copy(vmi_instance_t vmi, struct memcb_pass* pass)
{
    drakvuf_t drakvuf = pass->drakvuf;

    PRINT_DEBUG("Re-copying remapped gfn\n");

    if (!drakvuf_pause(drakvuf))
        return 0;

    uint8_t backup[VMI_PS_4KB];

    if ( VMI_FAILURE == vmi_read_pa(vmi, pass->remapped_gfn->o<<12, VMI_PS_4KB, &backup, NULL) )
    {
        fprintf(stderr, "Critical error in re-copying remapped gfn\n");
        drakvuf->interrupted = -1;
        return 0;
    }

    if ( VMI_FAILURE == vmi_write_pa(vmi, pass->remapped_gfn->r<<12, VMI_PS_4KB, &backup, NULL) )
    {
        fprintf(stderr, "Critical error in re-copying remapped gfn\n");
        drakvuf->interrupted = -1;
        return 0;
    }

    GSList* loop = (GSList*)pass->traps;
#ifdef DRAKVUF_DEBUG
    if (loop)
    {
        struct wrapper* first = (struct wrapper*)g_hash_table_lookup(drakvuf->breakpoint_lookup_pa, loop->data);
        trap_stats_page_copy(pass->remapped_gfn->o, first && first->traps ? first->traps->data : NULL);
    }
#endif
    while (loop)
    {
        uint8_t test = 0;
        addr_t pa = GPOINTER_TO_SIZE(loop->data);
        struct wrapper* s = (struct wrapper*)g_hash_table_lookup(drakvuf->breakpoint_lookup_pa, loop->data);

#ifdef DRAKVUF_DEBUG
        for (GSList* t = s ? s->traps : NULL; t; t = t->next)
            trap_stats_shadow_copy(t->data);
#endif

        if ( VMI_FAILURE == vmi_read_8_pa(vmi, pa, &test) )
        {
            fprintf(stderr, "Critical error in re-copying remapped gfn\n");
            drakvuf->interrupted = -1;
            return 0;
        }

        if ( test == bp )
        {
            PRINT_DEBUG("Double-trap at 0x%lx\n", pa);
            s->breakpoint.doubletrap = 1;
        }
        else
        {
            s->breakpoint.doubletrap = 0;

            /*
             * If a write was observed near or at a breakpoint we automatically
             * fall back to memory access permission based monitoring.
             */
            if ( pass->pa < pa && pass->pa >= pa-14 )
            {
                PRINT_DEBUG("Write happened near a breakpoint at 0x%lx, switching to mem X-based monitoring\n", pa);
                remove_trap(drakvuf, &s->breakpoint.guard);
                s->breakpoint.guard.memaccess.access |= VMI_MEMACCESS_X;
                if ( !inject_trap_mem(drakvuf, &s->breakpoint.guard, 0) )
                    drakvuf->interrupted = -1;

            }
            else if ( VMI_FAILURE == vmi_write_8_pa(vmi, (pass->remapped_gfn->r << 12) + (pa & VMI_BIT_MASK(0, 11)), &bp) )
            {
                fprintf(stderr, "Failed to set breakpoint in post_mem_cb!\n");
                drakvuf->interrupted = -1;
                return 0;
            }
        }

        loop = loop->next;
    }

    if (!drakvuf_resume(drakvuf))
        return 0;

    return 1;
}

/* Here we are in singlestep mode already and this is a singlstep cb */
static event_response_t _post_mem_cb(drakvuf_t drakvuf, vmi_event_t* event)
{
    event_response_t rsp = 0;
    struct memcb_pass* pass = (struct memcb_pass*)event->data;

    flush_vmi(drakvuf);

    /*
     * The trap may have been removed since in another callback,
     * in which case we have nothing to do.
     */
    struct wrapper* s = (struct wrapper*)g_hash_table_lookup(drakvuf->memaccess_lookup_gfn, GSIZE_TO_POINTER(pass->gfn));
    if (!s)
    {
        PRINT_DEBUG("Post mem cb @ 0x%lx has been cleared\n", pass->gfn);
        goto done;
    }

    PRINT_DEBUG("Post mem cb @ 0x%lx vCPU %u altp2m %u\n", pass->pa, event->vcpu_id, event->slat_id);

    vmi_pid_t pid = (drakvuf->os == VMI_OS_WINDOWS) ? pass->attached_proc_data.pid : pass->proc_data.pid;
    if (!drakvuf_is_ignored_process(drakvuf, pid))
    {
        drakvuf->in_callback = 1;
        GSList* loop = s->traps;
        while (loop)
        {
            drakvuf_trap_t* trap = (drakvuf_trap_t*)loop->data;

            if (trap->cb && !trap_is_removed(trap) && trap->memaccess.type == POST &&
                (trap->memaccess.access & pass->access))
            {
                drakvuf_trap_info_t trap_info =
                {
                    .trap = trap,
                    .trap_pa = pass->pa,
                    .regs = event->x86_regs,
                    .vcpu = event->vcpu_id,
                    .timestamp = g_get_real_time(),
                };
                copy_proc_data_from_priv(&trap_info.proc_data, &pass->proc_data);
                copy_proc_data_from_priv(&trap_info.attached_proc_data, &pass->attached_proc_data);

                rsp |= call_trap_cb(drakvuf, &trap_info, 0);
            }

            loop = loop->next;
        }
        drakvuf->in_callback = 0;
    }

    /*
     * We don't need to pause the VM here because mem events
     * are safely cleared by LibVMI.
     */
    process_free_requests(drakvuf);

    /*
     * We need to copy the newly written page to the remapped gfn
     * and reapply all traps
     */
    if ( pass->traps && !refresh_shadow_copy(drakvuf->vmi, pass) )
    {
        fprintf(stderr, "Failed to refresh shadow copy\n");
        drakvuf->interrupted = 1;
        goto done;
    }

done:
    free_proc_data_priv_2(&pass->proc_data, &pass->attached_proc_data);
    g_slice_free(struct memcb_pass, pass);

    uint16_t view = drakvuf->altp2m_idx;

    // Switch to RX view if context based views enabled and the VCPU is excuting a process we are NOT interested in
    if (drakvuf->enable_cr3_based_interception && !drakvuf->vcpu_monitor[event->vcpu_id])
        view = drakvuf->altp2m_idrx;

    /* We switch back to the altp2m view no matter what */
    event->slat_id = view;

    drakvuf->step_event[event->vcpu_id]->callback = vmi_reset_trap;
    drakvuf->step_event[event->vcpu_id]->data = drakvuf;
    return rsp |
        VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP | // Turn off singlestep
        VMI_EVENT_RESPONSE_SLAT_ID;
}

static event_response_t post_mem_cb(vmi_instance_t vmi, vmi_event_t* event)
{
    UNUSED(vmi);
    struct memcb_pass* pass = (struct memcb_pass*)event->data;
    drakvuf_t drakvuf = (drakvuf_t)pass->drakvuf;
    serial_callback_enter(drakvuf, event);
    event_response_t ret = _post_mem_cb(drakvuf, event);
    serial_callback_exit(drakvuf);
    return ret;
}

/*
 * Refresh the shadow copy of a remapped page when in idrx view.
 */
static event_response_t post_mem_idrx_cb(vmi_instance_t vmi, vmi_event_t* event)
{
    struct memcb_pass* pass = (struct memcb_pass*)event->data;
    drakvuf_t drakvuf = pass->drakvuf;
    serial_callback_enter(drakvuf, event);

    if ( !refresh_shadow_copy(vmi, pass) )
    {
        fprintf(stderr, "Failed to refresh shadow copy in IDRX cb\n");
        drakvuf->interrupted = -1;
    }

    serial_callback_exit(drakvuf);

    g_slice_free(struct memcb_pass, pass);

    event->slat_id = drakvuf->altp2m_idrx;

    return VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP | // Turn off singlestep
        VMI_EVENT_RESPONSE_SLAT_ID;
}

static void fill_common_event_trap_info(drakvuf_t drakvuf, drakvuf_trap_info_t* trap_info,
    proc_data_priv_t* proc_data, proc_data_priv_t* attached_proc_data,
    vmi_event_t* event)
{
    memset(proc_data, 0, sizeof(proc_data_priv_t));
    memset(attached_proc_data, 0, sizeof(proc_data_priv_t));
    memset(trap_info, 0, sizeof(drakvuf_trap_info_t));

    trap_info->regs = event->x86_regs;
    trap_info->vcpu = event->vcpu_id;

    addr_t process_base = drakvuf_get_current_process(drakvuf, trap_info);
    addr_t attached_proc = drakvuf_get_current_attached_process(drakvuf, trap_info);
    uint32_t thread_id;
    if (!drakvuf_get_current_thread_id(drakvuf, trap_info, &thread_id))
    {
#ifdef DRAKVUF_DEBUG
        if ( drakvuf->json_kernel_path )
            PRINT_DEBUG("[TRAP_INFO] Failed to get TID\n");
#endif
        thread_id = 0;
        return;
    }

    drakvuf_get_process_data_priv(drakvuf, process_base, proc_data);
    proc_data->tid = thread_id;

    if (attached_proc)
    {
        drakvuf_get_process_data_priv(drakvuf, attached_proc, attached_proc_data);
        attached_proc_data->tid = thread_id;
    }

    trap_info->timestamp = g_get_real_time();
    copy_proc_data_from_priv(&trap_info->proc_data, proc_data);
    copy_proc_data_from_priv(&trap_info->attached_proc_data, attached_proc_data);
}

/* This hits on the first access on a page, so not in singlestep yet */
static event_response_t _pre_mem_cb(drakvuf_t drakvuf, vmi_event_t* event)
{
    event_response_t rsp = 0;
    addr_t pa = (event->mem_event.gfn<<12) + event->mem_event.offset;

    flush_vmi(drakvuf);

    if (event->mem_event.gfn == drakvuf->sink_page_gfn)
    {
        PRINT_DEBUG("Somebody try to do something to the empty page, let's emulate it\n");
        return VMI_EVENT_RESPONSE_EMULATE_NOWRITE;
    }

    if (event->slat_id == drakvuf->altp2m_idrx)
    {
        PRINT_DEBUG("Pre mem cb with vCPU %u @ 0x%lx in the IDRX view %u: %c%c%c\n",
            event->vcpu_id, pa, event->slat_id,
            (event->mem_event.out_access & VMI_MEMACCESS_R) ? 'r' : '-',
            (event->mem_event.out_access & VMI_MEMACCESS_W) ? 'w' : '-',
            (event->mem_event.out_access & VMI_MEMACCESS_X) ? 'x' : '-'
        );

        struct memcb_pass* pass = (struct memcb_pass*)g_slice_alloc0(sizeof(struct memcb_pass));
        pass->drakvuf = drakvuf;
        pass->gfn = event->mem_event.gfn;
        pass->pa = pa;
        pass->traps = (GSList*)g_hash_table_lookup(drakvuf->breakpoint_lookup_gfn, GSIZE_TO_POINTER(pass->gfn));
        pass->remapped_gfn = (struct remapped_gfn*)g_hash_table_lookup(drakvuf->remapped_gfns, GSIZE_TO_POINTER(pass->gfn));

        event->slat_id = 0;

        drakvuf->step_event[event->vcpu_id]->callback = post_mem_idrx_cb;
        drakvuf->step_event[event->vcpu_id]->data = pass;

        return VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP | // Turn on singlestep
            VMI_EVENT_RESPONSE_SLAT_ID;
    }

    struct wrapper* s = (struct wrapper*)g_hash_table_lookup(drakvuf->memaccess_lookup_gfn,
            GSIZE_TO_POINTER(event->mem_event.gfn));
    if (!s)
    {
        PRINT_DEBUG("Event has been cleared for GFN 0x%lx but we are still in view %u\n",
            event->mem_event.gfn, event->slat_id);
        return 0;
    }

    PRINT_DEBUG("Pre mem cb with vCPU %u @ 0x%lx in view %u: %c%c%c\n",
        event->vcpu_id, pa, event->slat_id,
        (event->mem_event.out_access & VMI_MEMACCESS_R) ? 'r' : '-',
        (event->mem_event.out_access & VMI_MEMACCESS_W) ? 'w' : '-',
        (event->mem_event.out_access & VMI_MEMACCESS_X) ? 'x' : '-'
    );

    drakvuf_trap_info_t trap_info;
    proc_data_priv_t proc_data;
    proc_data_priv_t attached_proc_data;
    fill_common_event_trap_info(drakvuf, &trap_info, &proc_data, &attached_proc_data, event);
    trap_info.trap_pa = pa;

    if (s->traps)
        trap_info.event_uid = ++drakvuf->event_counter;

    vmi_pid_t pid = (drakvuf->os == VMI_OS_WINDOWS) ? attached_proc_data.pid : proc_data.pid;
    if (!drakvuf_is_ignored_process(drakvuf, pid))
    {
        GSList* loop = s->traps;
        drakvuf->in_callback = 1;
        while (loop)
        {
            drakvuf_trap_t* trap = (drakvuf_trap_t*)loop->data;

            if (trap->cb && !trap_is_removed(trap) && trap->memaccess.type == PRE &&
                (trap->memaccess.access & event->mem_event.out_access))
            {
                trap_info.trap = trap;
                rsp |= call_trap_cb(drakvuf, &trap_info, 0);
            }

            loop = loop->next;
        }

        /* We need to call breakpoint handlers registered for this physical address */
        if (event->mem_event.out_access & VMI_MEMACCESS_X)
        {
            struct wrapper* sbp = (struct wrapper*)g_hash_table_lookup(drakvuf->breakpoint_lookup_pa,
                    GSIZE_TO_POINTER(pa));
            if (sbp)
            {
                PRINT_DEBUG("Simulated INT3 event vCPU %u altp2m:%u CR3: 0x%"PRIx64" PA=0x%"PRIx64" RIP=0x%"PRIx64"\n",
                    event->vcpu_id, event->slat_id, event->x86_regs->cr3, pa, event->x86_regs->rip);

                loop = sbp->traps;
                while (loop)
                {
                    trap_info.trap = (drakvuf_trap_t*)loop->data;

                    loop = loop->next;
                    if (!trap_is_removed(trap_info.trap))
                        rsp |= call_trap_cb(drakvuf, &trap_info, 0);
                }
            }
        }
        drakvuf->in_callback = 0;
    }

    /*
     * We don't need to pause the VM here because mem events
     * are safely cleared by LibVMI.
     */
    process_free_requests(drakvuf);

    // Check if we have traps still active on this page
    s = (struct wrapper*)g_hash_table_lookup(drakvuf->memaccess_lookup_gfn, GSIZE_TO_POINTER(event->mem_event.gfn));
    if (s)
    {
        /*
         * There seems to be another trap still active
         * but it may already have another event queued that will clear it.
         */
        struct memcb_pass* pass = (struct memcb_pass*)g_slice_alloc0(sizeof(struct memcb_pass));
        pass->drakvuf = drakvuf;
        pass->gfn = event->mem_event.gfn;
        pass->pa = pa;
        pass->access = event->mem_event.out_access;
        pass->proc_data = proc_data;
        pass->attached_proc_data = attached_proc_data;

        if (!s->memaccess.guard2)
        {
            event->slat_id = 0;

            /*
             * If this is a remapped gfn and the page is getting written, the remapped copy needs to be updated
             */
            if ( event->mem_event.out_access & VMI_MEMACCESS_W )
            {
                pass->traps = (GSList*)g_hash_table_lookup(drakvuf->breakpoint_lookup_gfn, GSIZE_TO_POINTER(pass->gfn));
                if ( pass->traps )
                    pass->remapped_gfn = (struct remapped_gfn*)g_hash_table_lookup(drakvuf->remapped_gfns,
                            GSIZE_TO_POINTER(pass->gfn));
            }
        }
        else
        {
            event->slat_id = drakvuf->altp2m_idr;
            if (event->mem_event.out_access & VMI_MEMACCESS_W)
            {
                g_slice_free(struct memcb_pass, pass);
                free_proc_data_priv_2(&proc_data, &attached_proc_data);
                PRINT_DEBUG("Somebody try to write to the shadow page, let's emulate it instead\n");
                return rsp | VMI_EVENT_RESPONSE_EMULATE_NOWRITE;
            }
        }

        if ( drakvuf->step_event[event->vcpu_id]->callback == post_mem_cb )
        {
            fprintf(stderr, "Error, post_mem_cb wasn't called when expected!\n");
            drakvuf->interrupted = -1;
            g_slice_free(struct memcb_pass, pass);
            free_proc_data_priv_2(&proc_data, &attached_proc_data);
            return 0;
        }

        PRINT_DEBUG("Switching to altp2m view %u on vCPU %u and waiting for post_mem cb\n",
            event->slat_id, event->vcpu_id);

        drakvuf->step_event[event->vcpu_id]->callback = post_mem_cb;
        drakvuf->step_event[event->vcpu_id]->data = pass;
        return rsp |
            VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP | // Turn on singlestep
            VMI_EVENT_RESPONSE_SLAT_ID;
    }

    free_proc_data_priv_2(&proc_data, &attached_proc_data);
    return rsp;
}

static event_response_t pre_mem_cb(vmi_instance_t vmi, vmi_event_t* event)
{
    UNUSED(vmi);
    drakvuf_t drakvuf = (drakvuf_t)event->data;
    serial_callback_enter(drakvuf, event);
    event_response_t ret = _pre_mem_cb(drakvuf, event);
    serial_callback_exit(drakvuf);
    return ret;
}

/*
 * The traps of a breakpoint, taken with the VMI lock held. With parallel
 * events the callbacks run without the lock, so other vCPU threads may add
 * and remove traps of the same breakpoint meanwhile. Removed traps are freed
 * only once all vCPU threads are idle, so the pointers stay valid.
 */
struct trap_snapshot
{
    drakvuf_trap_t** traps;
    size_t count;
    size_t catchall; // the first traps are catchall breakpoints
    bool limited_ttl; // a trap after the catchall ones has a TTL, which takes the VMI lock to count down
    drakvuf_trap_t* inline_traps[16];
};

static void trap_snapshot_take(drakvuf_t drakvuf, struct wrapper* s, struct trap_snapshot* snapshot)
{
    snapshot->traps = snapshot->inline_traps;
    snapshot->count = 0;
    snapshot->catchall = 0;

    // catchall breakpoint will not be fired
    // if there are no "normal" subscribers for this trap
    if ( !s->traps )
        return;

    size_t total = g_slist_length(drakvuf->catchall_breakpoint) + g_slist_length(s->traps);
    if ( total > G_N_ELEMENTS(snapshot->inline_traps) )
        snapshot->traps = g_new(drakvuf_trap_t*, total);

    for (GSList* loop = drakvuf->catchall_breakpoint; loop; loop = loop->next)
        if ( !trap_is_removed(loop->data) )
            snapshot->traps[snapshot->count++] = loop->data;

    snapshot->catchall = snapshot->count;
    snapshot->limited_ttl = false;

    for (GSList* loop = s->traps; loop; loop = loop->next)
    {
        drakvuf_trap_t* trap = loop->data;
        if ( trap_is_removed(trap) )
            continue;
        snapshot->traps[snapshot->count++] = trap;
        if ( trap->ttl != UNLIMITED_TTL )
            snapshot->limited_ttl = true;
    }
}

static void trap_snapshot_free(struct trap_snapshot* snapshot)
{
    if ( snapshot->traps != snapshot->inline_traps )
        g_free(snapshot->traps);
}

/*
 * Breakpoint callbacks of mt_safe traps run concurrently with parallel
 * events, the others are serialized.
 */
static event_response_t run_trap_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    if ( !drakvuf->parallel_events || info->trap->mt_safe )
        return call_trap_cb(drakvuf, info, 0);

    gint64 start = trap_stats_now();
    g_mutex_lock(&drakvuf->serial_cb_lock);
    event_response_t rsp = call_trap_cb(drakvuf, info, trap_stats_now() - start);
    g_mutex_unlock(&drakvuf->serial_cb_lock);
    return rsp;
}

static inline void call_trap_ah_cb(drakvuf_t drakvuf, drakvuf_trap_t* trap)
{
#ifdef DRAKVUF_DEBUG
    trap_stats_ah_call(drakvuf, trap);
#else
    trap->ah_cb(drakvuf, trap);
#endif
}

static void run_trap_ah_cb(drakvuf_t drakvuf, drakvuf_trap_t* trap)
{
    if ( !drakvuf->parallel_events || trap->mt_safe )
    {
        call_trap_ah_cb(drakvuf, trap);
        return;
    }

    g_mutex_lock(&drakvuf->serial_cb_lock);
    call_trap_ah_cb(drakvuf, trap);
    g_mutex_unlock(&drakvuf->serial_cb_lock);
}

/*
 * Without parallel events this runs with the VMI lock held throughout. With
 * parallel events the lock is only taken to access the trap tables, the
 * callbacks take it when they need it.
 */
static event_response_t _int3_cb(drakvuf_t drakvuf, vmi_event_t* event)
{
    event_response_t rsp = 0;
    addr_t pa = (event->interrupt_event.gfn << 12)
        + event->interrupt_event.offset + event->interrupt_event.insn_length - 1;

    drakvuf_lock_and_get_vmi(drakvuf);

    flush_vmi(drakvuf);

#ifdef DEBUG
    reg_t cr3 = event->x86_regs->cr3;
    PRINT_DEBUG("INT3 event vCPU %u altp2m:%u CR3: 0x%"PRIx64" PA=0x%"PRIx64" RIP=0x%"PRIx64". Insn_length: %u\n",
        event->vcpu_id, event->slat_id, cr3, pa,
        event->interrupt_event.gla, event->interrupt_event.insn_length);
#endif

    struct wrapper* s = (struct wrapper*)g_hash_table_lookup(drakvuf->breakpoint_lookup_pa,
            GSIZE_TO_POINTER(pa));
    if (!s)
    {
        /*
         * No trap is currently registered for this location
         * but this event may have been triggered by one we just
         * removed.
         */
        uint8_t test = 0;

        if ( VMI_FAILURE == vmi_read_8_pa(drakvuf->vmi, pa, &test) )
        {
            fprintf(stderr, "Critical error in int3 callback, can't read page\n");
            drakvuf->interrupted = -1;
            drakvuf_release_vmi(drakvuf);
            return 0;
        }

        if (test == bp)
        {
            // There is a breakpoint instruction in memory here
            // so we need to reinject this to the guest.
            PRINT_DEBUG("Reinjecting breakpoint into the guest\n");
            event->interrupt_event.reinject = 1;
        }
        else
        {
            // This was an event for an old breakpoint no longer set
            PRINT_DEBUG("Ignoring old breakpoint event found in the queue\n");
            event->interrupt_event.reinject = 0;
        }
        drakvuf_release_vmi(drakvuf);
        return 0;
    }

    if ( s->breakpoint.doubletrap )
        event->interrupt_event.reinject = 1;
    else
        event->interrupt_event.reinject = 0;

    struct trap_snapshot snapshot;
    trap_snapshot_take(drakvuf, s, &snapshot);

    uint64_t event_uid = 0;
    if (s->traps)
        event_uid = ++drakvuf->event_counter;

    drakvuf_release_vmi(drakvuf);

    drakvuf_trap_info_t trap_info;
    proc_data_priv_t proc_data;
    proc_data_priv_t attached_proc_data;
    fill_common_event_trap_info(drakvuf, &trap_info, &proc_data, &attached_proc_data, event);
    trap_info.trap_pa = pa;
    trap_info.event_uid = event_uid;
    /* Used to optimize "single stepping" during injection.
     *
     * If the execution flow changed from the address trapped then there is no
     * need to perform single stepping because the INT3 at the hooked address
     * would not be executed until injection finish.
     */
    bool avoid_singlestep = false;

    vmi_pid_t pid = (drakvuf->os == VMI_OS_WINDOWS) ? attached_proc_data.pid : proc_data.pid;
    if (!drakvuf_is_ignored_process(drakvuf, pid))
    {
        if (!drakvuf->parallel_events)
            drakvuf->in_callback = 1;

        for (size_t i = 0; i < snapshot.count; i++)
        {
            trap_info.trap = snapshot.traps[i];

            // Removed since by a callback on this or another vCPU
            if ( trap_is_removed(trap_info.trap) )
                continue;

            if ( drakvuf_is_active_callback(drakvuf, &trap_info) )
                rsp |= run_trap_cb(drakvuf, &trap_info);
        }

        if (drakvuf->vmi_response_set_registers[trap_info.vcpu])
        {
            if (VMI_EVENT_RESPONSE_SET_REGISTERS & rsp)
                PRINT_DEBUG("[LIBDRAKVUF] FATAL ERROR! Undefined behavior on invalid VM state!\n");

            /* Check that RIP has changed.
             *
             * During injection this is normal to change the RIP to function other than hooked.
             * Though it is possible that just the same function been injected.
             * In this case the single step is essential to be able to run this function.
             */
            avoid_singlestep = trap_info.regs->rip != drakvuf->regs_modified[trap_info.vcpu].rip;

            drakvuf->vmi_response_set_registers[trap_info.vcpu] = false;
            drakvuf_copy_gpr_registers(trap_info.regs, &drakvuf->regs_modified[trap_info.vcpu]);
            rsp |= VMI_EVENT_RESPONSE_SET_REGISTERS;
        }

        // Iterate over traps updating ttl. The same trap may be hit on other vCPUs.
        size_t expired = 0;

        if (snapshot.limited_ttl)
        {
            time_t cur_time = time(NULL);

            drakvuf_lock_and_get_vmi(drakvuf);
            for (size_t i = snapshot.catchall; i < snapshot.count; i++)
            {
                drakvuf_trap_t* trap = snapshot.traps[i];
                if (trap->ttl == UNLIMITED_TTL || trap_is_removed(trap))
                    continue;

                if (cur_time - trap->last_ttl_rst >= TRAP_TTL_RESET_INTERVAL_SEC)
                {
                    trap->last_ttl_rst = cur_time;
                    trap->ttl = drakvuf_get_limited_traps_ttl(drakvuf);
                }

                if (--trap->ttl == 0)
                {
                    trap->ttl = drakvuf_get_limited_traps_ttl(drakvuf);
                    // Reuse the snapshot, we are done with the earlier entries
                    snapshot.traps[expired++] = trap;
                }
            }
            drakvuf_release_vmi(drakvuf);
        }

        for (size_t i = 0; i < expired; i++)
            run_trap_ah_cb(drakvuf, snapshot.traps[i]);

        if (!drakvuf->parallel_events)
            drakvuf->in_callback = 0;
    }

    free_proc_data_priv_2(&proc_data, &attached_proc_data);
    trap_snapshot_free(&snapshot);

    drakvuf_lock_and_get_vmi(drakvuf);

    process_free_requests(drakvuf);

    // Check if we have traps still active on this breakpoint. With parallel
    // events removed traps are only freed later, until then the breakpoint
    // stays in memory and has to be stepped over.
    bool still_trapped = g_hash_table_lookup(drakvuf->breakpoint_lookup_pa, GSIZE_TO_POINTER(pa));

    drakvuf_release_vmi(drakvuf);

    if ( !avoid_singlestep && still_trapped )
    {
        PRINT_DEBUG("Switching altp2m and to singlestep on vcpu %u\n", event->vcpu_id);
        event->slat_id = 0;
        event->next_slat_id = drakvuf->altp2m_idx;

        // TODO: once support for Xen versions before 4.14 is dropped remove these lines
        drakvuf->step_event[event->vcpu_id]->callback = vmi_reset_trap;
        drakvuf->step_event[event->vcpu_id]->data = drakvuf;

        return rsp | drakvuf->int3_response_flags;
    }

    return rsp;
}

static event_response_t int3_cb(vmi_instance_t vmi, vmi_event_t* event)
{
    UNUSED(vmi);
    drakvuf_t drakvuf = (drakvuf_t)event->data;
    gint64 start = trap_stats_now();
    event_response_t ret;

    if ( drakvuf->parallel_events )
    {
        reader_enter(drakvuf, event);
        ret = _int3_cb(drakvuf, event);
        reader_exit();
    }
    else
    {
        drakvuf_lock_and_get_vmi(drakvuf);
        ret = _int3_cb(drakvuf, event);
        drakvuf_release_vmi(drakvuf);
    }

    trap_stats_int3(trap_stats_now() - start);
    return ret;
}

static event_response_t _cr3_cb(drakvuf_t drakvuf, vmi_event_t* event)
{
    event_response_t rsp = 0;

    flush_vmi(drakvuf);

#ifdef DRAKVUF_DEBUG
    /* This is very verbose and always on so we only print debug information
     * when there is a subscriber trap */
    if (drakvuf->cr3)
        PRINT_DEBUG("CR3 cb on vCPU %u: 0x%" PRIx64 "\n", event->vcpu_id, event->reg_event.value);
#endif

    event->x86_regs->cr3 = event->reg_event.value;

    drakvuf_trap_info_t trap_info;
    proc_data_priv_t proc_data;
    proc_data_priv_t attached_proc_data;
    fill_common_event_trap_info(drakvuf, &trap_info, &proc_data, &attached_proc_data, event);

    vmi_pid_t pid = (drakvuf->os == VMI_OS_WINDOWS) ? attached_proc_data.pid : proc_data.pid;
    if (!drakvuf_is_ignored_process(drakvuf, pid))
    {
        drakvuf->in_callback = 1;
        GSList* loop = drakvuf->cr3;
        while (loop)
        {
            trap_info.trap = (drakvuf_trap_t*)loop->data;

            if (!trap_is_removed(trap_info.trap))
                rsp |= call_trap_cb(drakvuf, &trap_info, 0);
            loop = loop->next;
        }
        drakvuf->in_callback = 0;
    }

    if (drakvuf->enable_cr3_based_interception)
    {
        char* process_name = drakvuf_get_current_process_name(drakvuf, &trap_info, false);
        GSList* process = drakvuf->context_switch_intercept_processes;

        drakvuf->vcpu_monitor[event->vcpu_id] = false;
        event->slat_id = drakvuf->altp2m_idrx;
        rsp |= VMI_EVENT_RESPONSE_SLAT_ID;

        while (process != NULL)
        {
            intercept_process_t* process_obj = (intercept_process_t*) process->data;
            bool switch_to_idx = false;
            switch (process_obj->strict)
            {
                case MATCH_NAME:
                    if (!strcmp(process_obj->name, process_name))
                        switch_to_idx = true;
                    break;
                case MATCH_PID:
                    if (process_obj->pid == trap_info.proc_data.pid)
                        switch_to_idx = true;
                    break;
                case MATCH_PID_NAME:
                    if (!strcmp(process_obj->name, process_name) && (process_obj->pid == trap_info.proc_data.pid))
                        switch_to_idx = true;
                    break;
            }

            if (switch_to_idx)
            {
                drakvuf->vcpu_monitor[event->vcpu_id] = true;
                event->slat_id = drakvuf->altp2m_idx;
            }

            process = process->next;
        }

        g_free(process_name);
    }

    free_proc_data_priv_2(&proc_data, &attached_proc_data);

    process_free_requests(drakvuf);

    return rsp;
}

static event_response_t cr3_cb(vmi_instance_t vmi, vmi_event_t* event)
{
    UNUSED(vmi);
    drakvuf_t drakvuf = (drakvuf_t)event->data;
    serial_callback_enter(drakvuf, event);
    event_response_t ret = _cr3_cb(drakvuf, event);
    serial_callback_exit(drakvuf);
    return ret;
}

static event_response_t _cr4_cb(drakvuf_t drakvuf, vmi_event_t* event)
{
    event_response_t rsp = 0;

    flush_vmi(drakvuf);
#ifdef DRAKVUF_DEBUG
    if (drakvuf->cr4)
        PRINT_DEBUG("CR4 cb on vCPU %u: 0x%" PRIx64 "\n", event->vcpu_id, event->reg_event.value);
#endif

    drakvuf_trap_info_t trap_info;
    proc_data_priv_t proc_data;
    proc_data_priv_t attached_proc_data;
    fill_common_event_trap_info(drakvuf, &trap_info, &proc_data, &attached_proc_data, event);
    trap_info.reg = &event->reg_event;
    drakvuf->in_callback = 1;
    GSList* loop = drakvuf->cr4;
    while (loop)
    {
        trap_info.trap = (drakvuf_trap_t*)loop->data;
        if (!trap_is_removed(trap_info.trap))
            rsp |= call_trap_cb(drakvuf, &trap_info, 0);
        loop = loop->next;
    }
    drakvuf->in_callback = 0;

    free_proc_data_priv_2(&proc_data, &attached_proc_data);

    process_free_requests(drakvuf);

    return rsp;
}

static event_response_t cr4_cb(vmi_instance_t vmi, vmi_event_t* event)
{
    UNUSED(vmi);
    drakvuf_t drakvuf = (drakvuf_t)event->data;
    serial_callback_enter(drakvuf, event);
    event_response_t ret = _cr4_cb(drakvuf, event);
    serial_callback_exit(drakvuf);
    return ret;
}

static event_response_t _debug_cb(drakvuf_t drakvuf, vmi_event_t* event)
{
    event_response_t rsp = 0;

    flush_vmi(drakvuf);

#ifdef DEBUG
    addr_t pa = (event->debug_event.gfn << 12) + event->debug_event.offset;
    PRINT_DEBUG("Debug event vCPU %u altp2m:%u CR3: 0x%"PRIx64" PA=0x%"PRIx64" RIP=0x%"PRIx64". Insn_length: %u\n",
        event->vcpu_id, event->slat_id, event->x86_regs->cr3, pa,
        event->debug_event.gla, event->debug_event.insn_length);
#endif

    drakvuf_trap_info_t trap_info;
    proc_data_priv_t proc_data;
    proc_data_priv_t attached_proc_data;
    fill_common_event_trap_info(drakvuf, &trap_info, &proc_data, &attached_proc_data, event);
    trap_info.debug = &event->debug_event;

    vmi_pid_t pid = (drakvuf->os == VMI_OS_WINDOWS) ? attached_proc_data.pid : proc_data.pid;
    if (!drakvuf_is_ignored_process(drakvuf, pid))
    {
        drakvuf->in_callback = 1;
        GSList* loop = drakvuf->debug;
        while (loop)
        {
            trap_info.trap = (drakvuf_trap_t*)loop->data;
            if (!trap_is_removed(trap_info.trap))
                rsp |= call_trap_cb(drakvuf, &trap_info, 0);
            loop = loop->next;
        }
        drakvuf->in_callback = 0;
    }

    free_proc_data_priv_2(&proc_data, &attached_proc_data);

    process_free_requests(drakvuf);

    event->debug_event.reinject = 1;

    return rsp;
}

static event_response_t debug_cb(vmi_instance_t vmi, vmi_event_t* event)
{
    UNUSED(vmi);
    drakvuf_t drakvuf = (drakvuf_t)event->data;
    serial_callback_enter(drakvuf, event);
    event_response_t ret = _debug_cb(drakvuf, event);
    serial_callback_exit(drakvuf);
    return ret;
}

static event_response_t _msr_cb(drakvuf_t drakvuf, vmi_event_t* event)
{
    event_response_t rsp = 0;

    flush_vmi(drakvuf);
#ifdef DEBUG
    PRINT_DEBUG("MSR event vCPU %u altp2m:%u MSR=0x%"PRIx32" Value=0x%"PRIx64"\n",
        event->vcpu_id, event->slat_id, event->reg_event.msr, event->reg_event.value);
#endif
    drakvuf_trap_info_t trap_info;
    proc_data_priv_t proc_data;
    proc_data_priv_t attached_proc_data;
    fill_common_event_trap_info(drakvuf, &trap_info, &proc_data, &attached_proc_data, event);
    trap_info.reg = &event->reg_event;

    vmi_pid_t pid = (drakvuf->os == VMI_OS_WINDOWS) ? attached_proc_data.pid : proc_data.pid;
    if (!drakvuf_is_ignored_process(drakvuf, pid))
    {
        drakvuf->in_callback = 1;
        GSList* loop = drakvuf->msr;
        while (loop)
        {
            trap_info.trap = (drakvuf_trap_t*)loop->data;
            if (!trap_is_removed(trap_info.trap))
                rsp |= call_trap_cb(drakvuf, &trap_info, 0);
            loop = loop->next;
        }
        drakvuf->in_callback = 0;
    }

    free_proc_data_priv_2(&proc_data, &attached_proc_data);

    process_free_requests(drakvuf);

    return rsp;
}

static event_response_t msr_cb(vmi_instance_t vmi, vmi_event_t* event)
{
    UNUSED(vmi);
    drakvuf_t drakvuf = (drakvuf_t)event->data;
    serial_callback_enter(drakvuf, event);
    event_response_t ret = _msr_cb(drakvuf, event);
    serial_callback_exit(drakvuf);
    return ret;
}

static event_response_t _cpuid_cb(drakvuf_t drakvuf, vmi_event_t* event)
{
    event_response_t rsp = 0;

    flush_vmi(drakvuf);

    PRINT_DEBUG("CPUID event vCPU %u altp2m:%u CR3: 0x%"PRIx64" RIP=0x%"PRIx64". Insn_length: %u\n",
        event->vcpu_id, event->slat_id, event->x86_regs->cr3,
        event->x86_regs->rip, event->cpuid_event.insn_length);

    reg_t rip = event->x86_regs->rip;

    drakvuf_trap_info_t trap_info;
    proc_data_priv_t proc_data;
    proc_data_priv_t attached_proc_data;
    fill_common_event_trap_info(drakvuf, &trap_info, &proc_data, &attached_proc_data, event);
    trap_info.cpuid = &event->cpuid_event;

    vmi_pid_t pid = (drakvuf->os == VMI_OS_WINDOWS) ? attached_proc_data.pid : proc_data.pid;
    if (!drakvuf_is_ignored_process(drakvuf, pid))
    {
        drakvuf->in_callback = 1;
        GSList* loop = drakvuf->cpuid;
        while (loop)
        {
            trap_info.trap = (drakvuf_trap_t*)loop->data;
            if (!trap_is_removed(trap_info.trap))
                rsp |= call_trap_cb(drakvuf, &trap_info, 0);
            loop = loop->next;
        }
        drakvuf->in_callback = 0;
    }

    free_proc_data_priv_2(&proc_data, &attached_proc_data);

    process_free_requests(drakvuf);

    if ( event->x86_regs->rip == rip )
        event->x86_regs->rip += event->cpuid_event.insn_length;

    return rsp | VMI_EVENT_RESPONSE_SET_REGISTERS;
}

static event_response_t cpuid_cb(vmi_instance_t vmi, vmi_event_t* event)
{
    UNUSED(vmi);
    drakvuf_t drakvuf = (drakvuf_t)event->data;
    serial_callback_enter(drakvuf, event);
    event_response_t ret = _cpuid_cb(drakvuf, event);
    serial_callback_exit(drakvuf);
    return ret;
}

static event_response_t _io_cb(drakvuf_t drakvuf, vmi_event_t* event)
{
    event_response_t rsp = 0;

    flush_vmi(drakvuf);

    PRINT_DEBUG("I/O event vCPU %u altp2m:%u CR3: 0x%"PRIx64" RIP=0x%"PRIx64". Port: %u\n",
        event->vcpu_id, event->slat_id, event->x86_regs->cr3,
        event->x86_regs->rip, event->io_event.port);

    drakvuf_trap_info_t trap_info;
    proc_data_priv_t proc_data;
    proc_data_priv_t attached_proc_data;
    fill_common_event_trap_info(drakvuf, &trap_info, &proc_data, &attached_proc_data, event);
    trap_info.io = &event->io_event;

    drakvuf->in_callback = 1;
    GSList* loop = drakvuf->io;
    while (loop)
    {
        trap_info.trap = (drakvuf_trap_t*)loop->data;
        if (!trap_is_removed(trap_info.trap))
            rsp |= call_trap_cb(drakvuf, &trap_info, 0);
        loop = loop->next;
    }
    drakvuf->in_callback = 0;

    free_proc_data_priv_2(&proc_data, &attached_proc_data);

    process_free_requests(drakvuf);

    return rsp;
}

static event_response_t io_cb(vmi_instance_t vmi, vmi_event_t* event)
{
    UNUSED(vmi);
    drakvuf_t drakvuf = (drakvuf_t)event->data;
    serial_callback_enter(drakvuf, event);
    event_response_t ret = _io_cb(drakvuf, event);
    serial_callback_exit(drakvuf);
    return ret;
}

void remove_trap(drakvuf_t drakvuf,
    const drakvuf_trap_t* trap)
{
    vmi_instance_t vmi = drakvuf->vmi;

    switch (trap->type)
    {
        case BREAKPOINT:
        {
            struct wrapper* container = (struct wrapper*)g_hash_table_lookup(drakvuf->breakpoint_lookup_trap, trap);

            if ( !container )
                return;

            xen_pfn_t current_gfn = container->breakpoint.pa >> 12;

            PRINT_DEBUG("Removing breakpoint trap from 0x%lx.\n",
                container->breakpoint.pa);

            trap_stats_remove(trap);
            g_hash_table_remove(drakvuf->breakpoint_lookup_trap, trap);
            container->traps = g_slist_remove(container->traps, trap);

            /*
             * The list of breakpoints on this gfn holds each breakpoint once,
             * it stays listed until its last trap is removed.
             */
            GSList* traps_on_gfn = (GSList*)g_hash_table_lookup(drakvuf->breakpoint_lookup_gfn, GSIZE_TO_POINTER(current_gfn));
            if (!container->traps)
            {
                traps_on_gfn = g_slist_remove(traps_on_gfn, GSIZE_TO_POINTER(container->breakpoint.pa));
                g_hash_table_remove(drakvuf->breakpoint_lookup_gfn, GSIZE_TO_POINTER(current_gfn));

                if ( traps_on_gfn )
                {
                    // the list head may change so we force a reinsert
                    g_hash_table_insert(drakvuf->breakpoint_lookup_gfn, GSIZE_TO_POINTER(current_gfn), traps_on_gfn);
                }
            }

            if (!container->traps)
            {
                struct remapped_gfn* remapped_gfn = (struct remapped_gfn*)g_hash_table_lookup(drakvuf->remapped_gfns,
                        GSIZE_TO_POINTER(current_gfn));
                if ( !remapped_gfn )
                {
                    fprintf(stderr, "Critical error in removing int3\n");
                    drakvuf->interrupted = -1;
                    break;
                }
                uint8_t backup;

                if ( VMI_FAILURE == vmi_read_8_pa(drakvuf->vmi, container->breakpoint.pa, &backup) )
                {
                    fprintf(stderr, "Critical error in removing int3\n");
                    drakvuf->interrupted = -1;
                    break;
                }

                if ( VMI_FAILURE == vmi_write_8_pa(drakvuf->vmi,
                        (remapped_gfn->r << 12) + (container->breakpoint.pa & VMI_BIT_MASK(0, 11)),
                        &backup) )
                {
                    fprintf(stderr, "Critical error in removing int3\n");
                    drakvuf->interrupted = -1;
                    break;
                }

                remove_trap(drakvuf, &container->breakpoint.guard);
                remove_trap(drakvuf, &container->breakpoint.guard2);

                /* In the idrx view the only memaccess traps are for guard3 and guard4, so if no breakpoint traps left on the gfn
                 * we can just remove the idrx settings directly */
                if ( !traps_on_gfn )
                {
                    if ( VMI_FAILURE == vmi_slat_change_gfn(vmi, drakvuf->altp2m_idrx, container->breakpoint.guard3.memaccess.gfn, ~(addr_t)0))
                    {
                        fprintf(stderr, "Critical error in removing int3, guard3 wasn't removed\n");
                        drakvuf->interrupted = -1;
                        break;
                    }
                    if ( VMI_FAILURE == vmi_slat_change_gfn(vmi, drakvuf->altp2m_idrx, container->breakpoint.guard4.memaccess.gfn, ~(addr_t)0))
                    {
                        fprintf(stderr, "Critical error in removing int3, guard4 wasn't removed\n");
                        drakvuf->interrupted = -1;
                        break;
                    }
                }

                g_hash_table_remove(drakvuf->breakpoint_lookup_pa, GSIZE_TO_POINTER(container->breakpoint.pa));
            }

            break;
        }
        case MEMACCESS:
        {
            status_t ret;
            struct wrapper* container = (struct wrapper*)g_hash_table_lookup(drakvuf->memaccess_lookup_trap, trap);
            if ( !container )
                return;

            container->traps = g_slist_remove(container->traps, trap);

            if (!container->traps)
            {
                if ( VMI_SUCCESS == vmi_slat_change_gfn(vmi, drakvuf->altp2m_idx, container->memaccess.gfn, ~(addr_t)0))
                {
                    PRINT_DEBUG("Removed memtrap for GFN 0x%lx in altp2m view %u\n",
                        container->memaccess.gfn, drakvuf->altp2m_idx);

                    struct remapped_gfn* remapped_gfn = (struct remapped_gfn*)g_hash_table_lookup(drakvuf->remapped_gfns,
                            GSIZE_TO_POINTER(container->memaccess.gfn));
                    if ( remapped_gfn )
                        remapped_gfn->active = 0;

                    g_hash_table_remove(drakvuf->memaccess_lookup_trap, trap);
                    g_hash_table_remove(drakvuf->memaccess_lookup_gfn, GSIZE_TO_POINTER(container->memaccess.gfn));

                }
                return;
            }

            /*
             * If more subscriber are present make sure we only set the required access settings.
             */
            GSList* loop = container->traps;
            vmi_mem_access_t update_access = 0;

            while (loop)
            {
                drakvuf_trap_t* _trap = (drakvuf_trap_t*)loop->data;
                update_access |= _trap->memaccess.access;
                loop=loop->next;
            }

            // No need to update permissions if it hasn't changed
            if ( update_access == container->memaccess.access )
                break;

            ret = vmi_set_mem_event(vmi, container->memaccess.gfn, update_access, drakvuf->altp2m_idx);
            if (VMI_SUCCESS == ret)
            {
                PRINT_DEBUG("Successfully set access to %c%c%c on GFN 0x%lx!\n",
                    (update_access & VMI_MEMACCESS_R) ? 'r' : '-',
                    (update_access & VMI_MEMACCESS_W) ? 'w' : '-',
                    (update_access & VMI_MEMACCESS_X) ? 'x' : '-',
                    container->memaccess.gfn
                );
                container->memaccess.access = update_access;
            }
            else
                PRINT_DEBUG("Failed to update memaccess trap settings on GFN 0x%lx!\n", container->memaccess.gfn);

            break;
        }
        case REGISTER:
        {
            if (CR3 == trap->regaccess.type)
            {
                drakvuf->cr3 = g_slist_remove(drakvuf->cr3, trap);
                if ( !drakvuf->cr3 && !drakvuf->enable_cr3_based_interception )
                    control_cr3_trap(drakvuf, 0);
            }
            else if (CR4 == trap->regaccess.type)
            {
                drakvuf->cr4 = g_slist_remove(drakvuf->cr4, trap);
                if (!drakvuf->cr4)
                    control_cr4_trap(drakvuf, 0);
            }
            else if (MSR_ALL == trap->regaccess.type)
            {
                drakvuf->msr = g_slist_remove(drakvuf->msr, trap);
                if (!drakvuf->msr)
                    control_msr_trap(drakvuf, 0);
            }
            else if (MSR_ANY == trap->regaccess.type)
            {
                uint32_t index = trap->regaccess.msr;
                drakvuf->msr = g_slist_remove(drakvuf->msr, trap);
                if (!drakvuf->msr)
                    control_msr_trap_any(drakvuf, 0, index);
            }
            break;
        }
        case DEBUG:
            drakvuf->debug = g_slist_remove(drakvuf->debug, trap);
            if ( !drakvuf->debug )
                control_debug_trap(drakvuf, 0);
            break;
        case CPUID:
            drakvuf->cpuid = g_slist_remove(drakvuf->cpuid, trap);
            if ( !drakvuf->cpuid )
                control_cpuid_trap(drakvuf, 0);
            break;
        case IO:
            drakvuf->io = g_slist_remove(drakvuf->io, trap);
            if ( !drakvuf->io )
                control_io_trap(drakvuf, 0);
            break;
        case CATCHALL_BREAKPOINT:
            drakvuf->catchall_breakpoint = g_slist_remove(drakvuf->catchall_breakpoint, trap);
        case __INVALID_TRAP_TYPE: /* fall-through */
        default:
            break;
    }
}

bool inject_trap_mem(drakvuf_t drakvuf, drakvuf_trap_t* trap, bool guard2)
{
    struct wrapper* s = (struct wrapper*)g_hash_table_lookup(drakvuf->memaccess_lookup_gfn,
            GSIZE_TO_POINTER(trap->memaccess.gfn));

    // We already have a trap registered on this page
    // check if type matches, if so, add trap to the list
    if (s)
    {
        drakvuf_trap_t* havetrap = (drakvuf_trap_t*)s->traps->data;
        if (havetrap->type != trap->type)
        {
            PRINT_DEBUG("Failed to add memaccess trap as gfn is already trapped!\n");
            return 0;
        }

        /*
         * Guard2 types are protecting remapped gfns, thus when hit
         * these need to be swapped to the altp2m_idr view.
         */
        s->memaccess.guard2 = guard2;

        if ( s->memaccess.access != trap->memaccess.access )
        {

            vmi_mem_access_t update_access = (s->memaccess.access | trap->memaccess.access);
            status_t ret = vmi_set_mem_event(drakvuf->vmi, trap->memaccess.gfn, update_access, drakvuf->altp2m_idx);

            if ( ret == VMI_FAILURE )
            {
                PRINT_DEBUG("*** FAILED TO SET MEMORY TRAP @ PAGE %lu ***\n", trap->memaccess.gfn);
                return 0;
            }

            s->memaccess.access = update_access;
        }

        s->traps = g_slist_prepend(s->traps, trap);
        g_hash_table_insert(drakvuf->memaccess_lookup_trap, trap, s);
        return 1;
    }
    else
    {
        s = (struct wrapper*)g_slice_alloc0(sizeof(struct wrapper));
        s->drakvuf = drakvuf;
        s->traps = g_slist_prepend(s->traps, trap);
        s->memaccess.gfn = trap->memaccess.gfn;
        s->memaccess.access = trap->memaccess.access;

        /*
         * Guard2 types are protecting remapped gfns, thus when hit
         * these need to be swapped to the altp2m_idr view.
         */
        s->memaccess.guard2 = guard2;

        status_t ret = vmi_set_mem_event(drakvuf->vmi, trap->memaccess.gfn, trap->memaccess.access, drakvuf->altp2m_idx);
        if ( ret == VMI_FAILURE )
        {
            PRINT_DEBUG("*** FAILED TO SET MEMORY TRAP @ PAGE %lu ***\n",
                trap->memaccess.gfn);
            g_slist_free(s->traps);
            g_slice_free(struct wrapper, s);
            return 0;
        }

        g_hash_table_insert(drakvuf->memaccess_lookup_gfn, GSIZE_TO_POINTER(s->memaccess.gfn), s);
        g_hash_table_insert(drakvuf->memaccess_lookup_trap, trap, s);
    }

    return 1;
}

/*
 * Set up the first trap on a breakpoint: the shadow copy of the page, its
 * mapping in the altp2m views, the breakpoint instruction and the guard traps.
 * Call with the domain paused.
 */
static bool arm_trap_pa(drakvuf_t drakvuf,
    drakvuf_trap_t* trap,
    addr_t pa)
{
    vmi_instance_t vmi = drakvuf->vmi;
    xen_pfn_t current_gfn = pa >> 12;

    struct wrapper* container = (struct wrapper*)g_slice_alloc0(sizeof(struct wrapper));
    if ( !container )
        return 0;

    container->drakvuf = drakvuf;
    container->traps = g_slist_prepend(container->traps, trap);
    container->breakpoint.pa = pa;

    /* Let's see if we have already created the shadow copy of this page */
    struct remapped_gfn* remapped_gfn = (struct remapped_gfn*)g_hash_table_lookup(drakvuf->remapped_gfns,
            GSIZE_TO_POINTER(current_gfn));

    if ( !remapped_gfn )
    {
        remapped_gfn = (struct remapped_gfn*)g_slice_alloc0(sizeof(struct remapped_gfn));
        if ( !remapped_gfn )
            goto err_exit;

        remapped_gfn->o = current_gfn;
        remapped_gfn->r = ++(drakvuf->max_gpfn);

        int rc = xen_populate_physmap(drakvuf->xen, drakvuf->domID, &remapped_gfn->r);
        PRINT_DEBUG("Physmap populated? %i\n", rc);
        if (!rc)
        {
            g_slice_free(struct remapped_gfn, remapped_gfn);
            remapped_gfn = NULL;
            goto err_exit;
        }

        g_hash_table_insert(drakvuf->remapped_gfns,
            GSIZE_TO_POINTER(remapped_gfn->o),
            remapped_gfn);
    }

    /*
     * The page may have been remapped previously but if it has no active traps
     * then the contents may be stale, so we copy it in that case just to make sure
     */
    if (!g_hash_table_lookup(drakvuf->breakpoint_lookup_gfn, GSIZE_TO_POINTER(remapped_gfn->o)) )
    {
        uint8_t backup[VMI_PS_4KB];
        if ( VMI_FAILURE == vmi_read_pa(drakvuf->vmi, current_gfn<<12, VMI_PS_4KB, &backup, NULL) )
        {
            fprintf(stderr, "Reading original page contents before remapping failed\n");
            goto err_exit;
        }

        if ( VMI_SUCCESS == vmi_write_pa(drakvuf->vmi, remapped_gfn->r << 12, VMI_PS_4KB, &backup, NULL) )
            PRINT_DEBUG("Copied trapped page to new location\n");
        else
        {
            // TODO cleanup
            fprintf(stderr, "Copying trapped page to new location FAILED\n");
            goto err_exit;
        }
    }

    if ( !remapped_gfn->active )
    {
        PRINT_DEBUG("Activating remapped gfns in the altp2m views!\n");
        remapped_gfn->active = 1;

        if (VMI_FAILURE == vmi_slat_change_gfn(
                drakvuf->vmi, drakvuf->altp2m_idx, current_gfn, remapped_gfn->r))
        {
            PRINT_DEBUG("%s: Failed to change gfn on view %u\n", __FUNCTION__, drakvuf->altp2m_idx);
            goto err_exit;
        }
        if (VMI_FAILURE == vmi_slat_change_gfn(
                drakvuf->vmi, drakvuf->altp2m_idr, remapped_gfn->r, drakvuf->sink_page_gfn))
        {
            PRINT_DEBUG("%s: Failed to change gfn on view %u\n", __FUNCTION__, drakvuf->altp2m_idr);
            goto err_exit;
        }

        if (VMI_FAILURE == vmi_slat_change_gfn(
                drakvuf->vmi, drakvuf->altp2m_idrx, remapped_gfn->r, drakvuf->sink_page_gfn))
        {
            PRINT_DEBUG("%s: Failed to change gfn on view %u\n", __FUNCTION__, drakvuf->altp2m_idrx);
            goto err_exit;
        }

    }

    /*
     * We MUST set guard and guard2 memaccess _after_ remapping as otherwise remapping
     * overwrites the memaccess settings.
     */
    container->breakpoint.guard.type = MEMACCESS;
    /* We need to merge rights of the previous traps on this page (if any) */
    container->breakpoint.guard.memaccess.access = VMI_MEMACCESS_RW;
    container->breakpoint.guard.memaccess.type = PRE;
    container->breakpoint.guard.memaccess.gfn = current_gfn;

    container->breakpoint.guard2.type = MEMACCESS;
    container->breakpoint.guard2.memaccess.access = VMI_MEMACCESS_RWX;
    container->breakpoint.guard2.memaccess.type = PRE;
    container->breakpoint.guard2.memaccess.gfn = remapped_gfn->r;

    container->breakpoint.guard3.type = MEMACCESS;
    container->breakpoint.guard3.memaccess.access = VMI_MEMACCESS_W;
    container->breakpoint.guard3.memaccess.type = PRE;
    container->breakpoint.guard3.memaccess.gfn = current_gfn;

    container->breakpoint.guard4.type = MEMACCESS;
    container->breakpoint.guard4.memaccess.access = VMI_MEMACCESS_RWX;
    container->breakpoint.guard4.memaccess.type = PRE;
    container->breakpoint.guard4.memaccess.gfn = remapped_gfn->r;

    addr_t rpa = (remapped_gfn->r<<12) + (container->breakpoint.pa & VMI_BIT_MASK(0, 11));
    uint8_t test;

    if (VMI_FAILURE == vmi_read_8_pa(vmi, pa, &test))
    {
        PRINT_DEBUG("FAILED TO READ @ 0x%lx !\n", container->breakpoint.pa);
        goto err_exit;
    }

    if (test == bp)
    {
        PRINT_DEBUG("Double-trap location @ 0x%lx !\n", container->breakpoint.pa);
        container->breakpoint.doubletrap = 1;
    }
    else
    {
        container->breakpoint.doubletrap = 0;

        if ( VMI_FAILURE == vmi_write_8_pa(vmi, rpa, &bp) )
        {
            PRINT_DEBUG("Using breakpoint instruction @ 0x%lx is not possible. Using fallback.\n", container->breakpoint.pa);
            container->breakpoint.guard.memaccess.access |= VMI_MEMACCESS_X;
        }
    }

    if ( !inject_trap_mem(drakvuf, &container->breakpoint.guard, 0) )
    {
        PRINT_DEBUG("[IDX] Failed to create guard trap for the breakpoint!\n");
        goto err_exit;
    }

    if ( !inject_trap_mem(drakvuf, &container->breakpoint.guard2, 1) )
    {
        PRINT_DEBUG("[IDX] Failed to create guard2 trap for the breakpoint!\n");
        goto err_exit;
    }

    /*
     * We don't use inject_trap_mem for guard3 and guard4 because the settings on them are fixed and no external
     * trap can change the memaccess settings for them.
     */
    if ( VMI_FAILURE == vmi_set_mem_event(drakvuf->vmi, container->breakpoint.guard3.memaccess.gfn, container->breakpoint.guard3.memaccess.access, drakvuf->altp2m_idrx) )
    {
        PRINT_DEBUG("[IDRX] Failed to create guard3 trap for the breakpoint!\n");
        goto err_exit;
    }
    if ( VMI_FAILURE == vmi_set_mem_event(drakvuf->vmi, container->breakpoint.guard4.memaccess.gfn, container->breakpoint.guard4.memaccess.access, drakvuf->altp2m_idrx) )
    {
        PRINT_DEBUG("[IDRX] Failed to create guard4 trap for the breakpoint!\n");
        goto err_exit;
    }

    // list of traps on this page
    GSList* traps = (GSList*)g_hash_table_lookup(drakvuf->breakpoint_lookup_gfn, GSIZE_TO_POINTER(current_gfn));
    traps = g_slist_append(traps, GSIZE_TO_POINTER(container->breakpoint.pa));

    // save trap location into lookup tree
    g_hash_table_insert(drakvuf->breakpoint_lookup_gfn, GSIZE_TO_POINTER(current_gfn), traps);
    g_hash_table_insert(drakvuf->breakpoint_lookup_pa, GSIZE_TO_POINTER(container->breakpoint.pa), container);
    g_hash_table_insert(drakvuf->breakpoint_lookup_trap, trap, container);

    PRINT_DEBUG("\t\tTrap added @ PA 0x%" PRIx64 " RPA 0x%" PRIx64 " Page %" PRIu64 " for %s.\n",
        container->breakpoint.pa, rpa, pa >> 12, trap->name);
    return 1;

err_exit:
    if ( container->traps )
        g_slist_free(container->traps);
    if ( remapped_gfn )
        g_hash_table_remove(drakvuf->remapped_gfns, GSIZE_TO_POINTER(remapped_gfn->o));
    g_slice_free(struct wrapper, container);
    return 0;
}

/*
 * Call with the VMI lock held, so the breakpoint can't be removed between
 * looking it up and adding the trap to it.
 */
bool inject_trap_pa(drakvuf_t drakvuf,
    drakvuf_trap_t* trap,
    addr_t pa)
{
    trap->last_ttl_rst = time(NULL);

    // check if already marked
    struct wrapper* container = (struct wrapper*)g_hash_table_lookup(drakvuf->breakpoint_lookup_pa,
            GSIZE_TO_POINTER(pa));

    /*
     * Adding a trap to a breakpoint that is already in memory only changes our
     * own tables, the guest doesn't see a difference, so it doesn't need to be
     * paused. This is the common case for syscall return traps.
     */
    if (container)
    {
        g_hash_table_insert(drakvuf->breakpoint_lookup_trap,
            trap,
            container);
        container->traps = g_slist_prepend(container->traps, trap);

        // The breakpoint is on the list of its gfn since it was armed
        return 1;
    }

    /*
     * Arming a new breakpoint changes the guest in several steps, no vCPU may
     * run in between. Domain pauses nest, the caller may have paused already.
     */
    trap_stats_arm(trap);
    drakvuf_pause(drakvuf);
    bool ret = arm_trap_pa(drakvuf, trap, pa);
    drakvuf_resume(drakvuf);

    return ret;
}

bool inject_trap(drakvuf_t drakvuf,
    drakvuf_trap_t* trap,
    addr_t vaddr,
    vmi_pid_t pid)
{

    vmi_instance_t vmi = drakvuf->vmi;
    addr_t dtb;
    addr_t pa = 0;
    status_t status;

    if ( VMI_FAILURE == vmi_pid_to_dtb(vmi, pid, &dtb) )
        return 0;

    if ( trap->breakpoint.addr_type == ADDR_VA )
        status = vmi_pagetable_lookup(vmi, dtb, trap->breakpoint.addr, &pa);
    else
        status = vmi_pagetable_lookup(vmi, dtb, vaddr + trap->breakpoint.rva, &pa);

    if ( VMI_FAILURE == status )
        return 0;

    return inject_trap_pa(drakvuf, trap, pa);
}

bool control_debug_trap(drakvuf_t drakvuf, bool toggle)
{
    drakvuf->debug_event.version = VMI_EVENTS_VERSION;
    drakvuf->debug_event.type = VMI_EVENT_DEBUG_EXCEPTION;
    drakvuf->debug_event.data = drakvuf;
    drakvuf->debug_event.callback = debug_cb;

    if ( toggle )
    {
        if (VMI_FAILURE == vmi_register_event(drakvuf->vmi, &drakvuf->debug_event))
        {
            fprintf(stderr, "Failed to register DEBUG event\n");
            return 0;
        }
    }
    else
    {
        if (VMI_FAILURE == vmi_clear_event(drakvuf->vmi, &drakvuf->debug_event, NULL))
        {
            fprintf(stderr, "Failed to clear DEBUG event\n");
            return 0;
        }
    }

    return 1;
}

bool control_cr3_trap(drakvuf_t drakvuf, bool toggle)
{
    drakvuf->cr3_event.version = VMI_EVENTS_VERSION;
    drakvuf->cr3_event.type = VMI_EVENT_REGISTER;
    drakvuf->cr3_event.reg_event.reg = CR3;
    drakvuf->cr3_event.reg_event.in_access = VMI_REGACCESS_W;
    drakvuf->cr3_event.data = drakvuf;
    drakvuf->cr3_event.callback = cr3_cb;

    if ( toggle )
    {
        if (VMI_FAILURE == vmi_register_event(drakvuf->vmi, &drakvuf->cr3_event))
        {
            fprintf(stderr, "Failed to register CR3 event\n");
            return 0;
        }
    }
    else
    {
        if (VMI_FAILURE == vmi_clear_event(drakvuf->vmi, &drakvuf->cr3_event, NULL))
        {
            fprintf(stderr, "Failed to clear CR3 event\n");
            return 0;
        }
    }

    return 1;
}

bool control_cr4_trap(drakvuf_t drakvuf, bool toggle)
{
    drakvuf->cr4_event.version = VMI_EVENTS_VERSION;
    drakvuf->cr4_event.type = VMI_EVENT_REGISTER;
    drakvuf->cr4_event.reg_event.reg = CR4;
    drakvuf->cr4_event.reg_event.in_access = VMI_REGACCESS_W;
    drakvuf->cr4_event.data = drakvuf;
    drakvuf->cr4_event.callback = cr4_cb;

    if ( toggle )
    {
        if (VMI_FAILURE == vmi_register_event(drakvuf->vmi, &drakvuf->cr4_event))
        {
            fprintf(stderr, "Failed to register CR4 event\n");
            return 0;
        }
    }
    else
    {
        if (VMI_FAILURE == vmi_clear_event(drakvuf->vmi, &drakvuf->cr4_event, NULL))
        {
            fprintf(stderr, "Failed to clear CR4 event\n");
            return 0;
        }
    }

    return 1;
}

bool control_cpuid_trap(drakvuf_t drakvuf, bool toggle)
{
    drakvuf->cpuid_event.version = VMI_EVENTS_VERSION;
    drakvuf->cpuid_event.type = VMI_EVENT_CPUID;
    drakvuf->cpuid_event.data = drakvuf;
    drakvuf->cpuid_event.callback = cpuid_cb;

    if ( toggle )
    {
        if (VMI_FAILURE == vmi_register_event(drakvuf->vmi, &drakvuf->cpuid_event))
        {
            fprintf(stderr, "Failed to register CPUID event\n");
            return 0;
        }
    }
    else
    {
        if (VMI_FAILURE == vmi_clear_event(drakvuf->vmi, &drakvuf->cpuid_event, NULL))
        {
            fprintf(stderr, "Failed to clear CPUID event\n");
            return 0;
        }
    }

    return 1;
}

bool control_io_trap(drakvuf_t drakvuf, bool toggle)
{
    drakvuf->io_event.version = VMI_EVENTS_VERSION;
    drakvuf->io_event.type = VMI_EVENT_IO;
    drakvuf->io_event.data = drakvuf;
    drakvuf->io_event.callback = io_cb;

    if ( toggle )
    {
        if (VMI_FAILURE == vmi_register_event(drakvuf->vmi, &drakvuf->io_event))
        {
            fprintf(stderr, "Failed to register I/O event\n");
            return 0;
        }
    }
    else
    {
        if (VMI_FAILURE == vmi_clear_event(drakvuf->vmi, &drakvuf->io_event, NULL))
        {
            fprintf(stderr, "Failed to clear I/O event\n");
            return 0;
        }
    }

    return 1;
}

bool control_msr_trap(drakvuf_t drakvuf, bool toggle)
{
    drakvuf->msr_event.version = VMI_EVENTS_VERSION;
    drakvuf->msr_event.type = VMI_EVENT_REGISTER;
    drakvuf->msr_event.reg_event.reg = MSR_ALL;
    drakvuf->msr_event.reg_event.in_access = VMI_REGACCESS_W;
    drakvuf->msr_event.data = drakvuf;
    drakvuf->msr_event.callback = msr_cb;

    if ( toggle )
    {
        if (VMI_FAILURE == vmi_register_event(drakvuf->vmi, &drakvuf->msr_event))
        {
            fprintf(stderr, "Failed to register MSR event\n");
            return 0;
        }
    }
    else
    {
        if (VMI_FAILURE == vmi_clear_event(drakvuf->vmi, &drakvuf->msr_event, NULL))
        {
            fprintf(stderr, "Failed to clear MSR event\n");
            return 0;
        }
    }

    return 1;
}

bool control_msr_trap_any(drakvuf_t drakvuf, bool toggle, uint32_t index)
{
    drakvuf->msr_event.version = VMI_EVENTS_VERSION;
    drakvuf->msr_event.type = VMI_EVENT_REGISTER;
    drakvuf->msr_event.reg_event.reg = MSR_ANY;
    drakvuf->msr_event.reg_event.in_access = VMI_REGACCESS_W;
    drakvuf->msr_event.reg_event.msr = index;
    drakvuf->msr_event.data = drakvuf;
    drakvuf->msr_event.callback = msr_cb;

    if ( toggle )
    {
        if (VMI_FAILURE == vmi_register_event(drakvuf->vmi, &drakvuf->msr_event))
        {
            fprintf(stderr, "Failed to register MSR event\n");
            return 0;
        }
    }
    else
    {
        if (VMI_FAILURE == vmi_clear_event(drakvuf->vmi, &drakvuf->msr_event, NULL))
        {
            fprintf(stderr, "Failed to clear MSR event\n");
            return 0;
        }
    }

    return 1;
}

// Whether all traps of a list are being removed, which turns off the event they share
static bool all_traps_removed(drakvuf_t drakvuf, GSList* traps)
{
    if (!traps)
        return false;

    for (GSList* loop = traps; loop; loop = loop->next)
        if (!g_hash_table_contains(drakvuf->remove_traps, loop->data))
            return false;

    return true;
}

/*
 * Whether freeing the removed traps clears a LibVMI event of the whole VM:
 * CR3, CR4, MSR, debug, CPUID or I/O. The breakpoint and memory access events
 * stay registered when their traps are removed.
 */
static bool removed_traps_clear_events(drakvuf_t drakvuf)
{
    return (all_traps_removed(drakvuf, drakvuf->cr3) && !drakvuf->enable_cr3_based_interception) ||
        all_traps_removed(drakvuf, drakvuf->cr4) ||
        all_traps_removed(drakvuf, drakvuf->msr) ||
        all_traps_removed(drakvuf, drakvuf->debug) ||
        all_traps_removed(drakvuf, drakvuf->cpuid) ||
        all_traps_removed(drakvuf, drakvuf->io);
}

// Process the requests already on the ring. Call with the VM paused, so no new ones arrive.
static status_t drain_ring(drakvuf_t drakvuf)
{
    status_t status = VMI_SUCCESS;

    while (VMI_SUCCESS == status && vmi_are_events_pending(drakvuf->vmi) > 0)
        status = vmi_events_listen(drakvuf->vmi, 0);

    return status;
}

void drakvuf_vmi_event_callback (int fd, void* data)
{
    UNUSED(fd);
    drakvuf_t drakvuf = (drakvuf_t)data;

    /*
     * With parallel events the callbacks run on the LibVMI worker threads
     * while this waits, so the VMI lock must not be held here. The flag is
     * changed with the lock held so that drakvuf_remove_trap called from
     * another thread either finishes before the callbacks look at the traps
     * or defers the removal.
     */
    if (drakvuf->parallel_events)
    {
        drakvuf_lock_and_get_vmi(drakvuf);
        g_atomic_int_set(&drakvuf->listening, 1);
        drakvuf_release_vmi(drakvuf);
    }

    status_t status = vmi_events_listen(drakvuf->vmi, drakvuf->poll_rc);
    if (VMI_SUCCESS != status)
    {
        PRINT_DEBUG("Error waiting for events or timeout, quitting...\n");
        drakvuf->interrupted = -1;
    }

    // All requests are answered and no callback runs until the next listen
    if (drakvuf->parallel_events)
    {
        drakvuf_lock_and_get_vmi(drakvuf);
        bool clears_events = removed_traps_clear_events(drakvuf);
        drakvuf_release_vmi(drakvuf);

        /*
         * Freed here, outside of the callbacks, the traps clear their LibVMI
         * events right away. LibVMI only defers the clearing in a callback,
         * to pause the VM and process the requests left on the ring first:
         * the vCPUs placed new ones since the listen, and with the event
         * cleared they'd find no handler and fail the next listen. So do the
         * same here.
         */
        bool paused = clears_events && drakvuf_pause(drakvuf);
        if (clears_events && !paused)
            fprintf(stderr, "Failed to pause the VM to clear events of removed traps\n");
        if (paused)
            trap_stats_drain();

        if (paused && VMI_SUCCESS != drain_ring(drakvuf))
        {
            PRINT_DEBUG("Error processing the events left before clearing events, quitting...\n");
            drakvuf->interrupted = -1;
        }

        drakvuf_lock_and_get_vmi(drakvuf);
        g_atomic_int_set(&drakvuf->listening, 0);
        drakvuf_free_removed_traps(drakvuf);
        drakvuf_release_vmi(drakvuf);

        if (paused && !drakvuf_resume(drakvuf))
        {
            fprintf(stderr, "Failed to resume the VM after clearing events of removed traps\n");
            drakvuf->interrupted = -1;
        }
    }
}

void destroy_reader_vmis(drakvuf_t drakvuf)
{
    for (unsigned int i = 0; i < MAX_DRAKVUF_VCPU; i++)
    {
        if (drakvuf->reader_vmi[i])
            vmi_destroy(drakvuf->reader_vmi[i]);
        drakvuf->reader_vmi[i] = NULL;
        drakvuf->reader_flush_counter[i] = 0;
    }
}

/*
 * One LibVMI instance per vCPU to read guest memory on its event thread.
 * Call with the VMI lock held and no events processed, after the OS has been
 * initialized.
 */
bool create_reader_vmis(drakvuf_t drakvuf)
{
    destroy_reader_vmis(drakvuf);

    for (unsigned int i = 0; i < drakvuf->vcpus && i < MAX_DRAKVUF_VCPU; i++)
    {
        if (VMI_FAILURE == vmi_clone_reader(drakvuf->vmi, &drakvuf->reader_vmi[i]))
        {
            fprintf(stderr, "Failed to create the LibVMI reader instance for vCPU %u\n", i);
            destroy_reader_vmis(drakvuf);
            return false;
        }
    }

    return true;
}

/*
 * Process the remaining events on the calling thread again. Call with no
 * events processed and the VM paused.
 */
bool stop_parallel_events(drakvuf_t drakvuf)
{
    // Also stops LibVMI workers started with LIBVMI_VCPU_BATCH
    bool ret = VMI_SUCCESS == vmi_events_set_parallel(drakvuf->vmi, false);
    if (!ret)
        fprintf(stderr, "Failed to stop parallel event processing\n");

    if (!drakvuf->parallel_events)
        return ret;

    drakvuf->parallel_events = false;

    // While the events of the removed traps are still registered, see drakvuf_vmi_event_callback
    if (VMI_SUCCESS != drain_ring(drakvuf))
        fprintf(stderr, "Failed to process the remaining events\n");

    drakvuf_free_removed_traps(drakvuf);
    destroy_reader_vmis(drakvuf);

    return ret;
}

static void drakvuf_poll(drakvuf_t drakvuf, unsigned int timeout)
{
    int rc = poll(drakvuf->event_fds, drakvuf->event_fd_cnt, timeout);
    drakvuf->poll_rc = rc;

    if (!rc && timeout)
        return;

    else if (rc < 0)
    {
        PRINT_DEBUG("DRAKVUF loop broke unexpectedly: [Errno: %d] %s\n", errno, strerror(errno));
        if (errno != EINTR)
        {
            drakvuf->interrupted = -1;
        }
        return;
    }

    /* check and process each fd if it was raised */
    for (int poll_ix=0; poll_ix<drakvuf->event_fd_cnt; poll_ix++)
    {
        if (timeout && !(drakvuf->event_fds[poll_ix].revents & (POLLIN | POLLERR)) )
            continue;

        fd_info_t fd_info = &drakvuf->fd_info_lookup[poll_ix];
        fd_info->event_cb(fd_info->fd, fd_info->data);
    }
}

void drakvuf_loop(drakvuf_t drakvuf, bool (*is_interrupted)(drakvuf_t, void*), void* data)
{

    PRINT_DEBUG("Started DRAKVUF polling loop\n");

    drakvuf->interrupted = 0;
    drakvuf_force_resume(drakvuf);

    while (!is_interrupted(drakvuf, data))
        drakvuf_poll(drakvuf, 1000);

    drakvuf_pause(drakvuf);

    // Ensures all events are processed from the ring
    drakvuf_poll(drakvuf, 0);

    PRINT_DEBUG("DRAKVUF polling loop finished\n");
}

void drakvuf_toggle_context_based_interception(drakvuf_t drakvuf)
{
    bool toggle = !drakvuf->enable_cr3_based_interception;
    status_t status;
    drakvuf_pause(drakvuf);

    if (toggle)
    {
        status = vmi_slat_switch(drakvuf->vmi, drakvuf->altp2m_idrx);
        if (VMI_FAILURE == status)
            PRINT_DEBUG("Enabling context based interception failed. \n");

        if ( !drakvuf->cr3 && !control_cr3_trap(drakvuf, 1) )
            PRINT_DEBUG("Failed to enable CR3 trap for context based interception. \n");


        drakvuf->enable_cr3_based_interception = true;
    }
    else
    {
        status = vmi_slat_switch(drakvuf->vmi, drakvuf->altp2m_idx);
        if (VMI_FAILURE == status)
            PRINT_DEBUG("Disabling context based interception failed. \n");

        if ( !drakvuf->cr3 )
            control_cr3_trap(drakvuf, 0);

        drakvuf->enable_cr3_based_interception = false;
    }

    drakvuf_resume(drakvuf);
}

bool init_vmi(drakvuf_t drakvuf, bool fast_singlestep)
{
    int rc;

    vmi_init_data_t* init_data = (vmi_init_data_t*)g_try_malloc0(sizeof(vmi_init_data_t) + sizeof(vmi_init_data_entry_t));
    if ( !init_data )
        return 0;

    init_data->count = 1;
    init_data->entry[0].type = VMI_INIT_DATA_XEN_EVTCHN;
    init_data->entry[0].data = (void*) xen_get_evtchn(drakvuf->xen);

    PRINT_DEBUG("init_vmi on domID %u -> %s\n", drakvuf->domID, drakvuf->dom_name);

    /* initialize the libvmi library */
    status_t status = vmi_init(&drakvuf->vmi,
            VMI_XEN,
            &drakvuf->domID,
            VMI_INIT_DOMAINID | VMI_INIT_EVENTS,
            init_data,
            NULL);
    g_free(init_data);
    if ( VMI_FAILURE == status )
    {
        fprintf(stderr, "Failed to init LibVMI library.\n");
        return 0;
    }
    PRINT_DEBUG("init_vmi: initializing vmi done\n");

    drakvuf->vcpus = vmi_get_num_vcpus(drakvuf->vmi);
    drakvuf->init_memsize = xen_get_maxmemkb(drakvuf->xen, drakvuf->domID);

    drakvuf->max_gpfn = vmi_get_max_physical_address(drakvuf->vmi) >> XC_PAGE_SHIFT;
    if ( !drakvuf->max_gpfn )
        return 0;

    PRINT_DEBUG("Max GPFN: 0x%lx\n", drakvuf->max_gpfn);

    // Crete tables to lookup breakpoints
    drakvuf->breakpoint_lookup_pa = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, free_wrapper);
    drakvuf->breakpoint_lookup_gfn = g_hash_table_new(g_direct_hash, g_direct_equal);
    drakvuf->breakpoint_lookup_trap = g_hash_table_new(g_direct_hash, g_direct_equal);
    drakvuf->memaccess_lookup_gfn = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, free_wrapper);
    drakvuf->memaccess_lookup_trap = g_hash_table_new(g_direct_hash, g_direct_equal);
    drakvuf->remapped_gfns = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, free_remapped_gfn);
    drakvuf->remove_traps = g_hash_table_new(g_direct_hash, g_direct_equal);
    drakvuf->injections_in_progress = g_hash_table_new(g_direct_hash, g_direct_equal);

    unsigned int i;
    /*
     * Setup singlestep event handlers but don't turn on MTF.
     * Max MAX_DRAKVUF_VCPU CPUs!
     */
    for (i = 0; i < drakvuf->vcpus && i < MAX_DRAKVUF_VCPU; i++)
    {
        drakvuf->step_event[i] = (vmi_event_t*)g_try_malloc0(sizeof(vmi_event_t));
        if ( !drakvuf->step_event[i] )
        {
            fprintf(stderr, "Out of memory during initialization\n");
            return 0;
        }

        SETUP_SINGLESTEP_EVENT(drakvuf->step_event[i], 1u << i, vmi_reset_trap, 0);
        drakvuf->step_event[i]->data = drakvuf;
        if (VMI_FAILURE == vmi_register_event(drakvuf->vmi, drakvuf->step_event[i]))
        {
            fprintf(stderr, "Failed to register singlestep for vCPU %u\n", i);
            return 0;
        }
    }

    /* domain->max_pages is mostly just an annoyance that we can safely ignore */
    rc = xen_set_maxmemkb(drakvuf->xen, drakvuf->domID, ~0);
    PRINT_DEBUG("Max mem set? %i\n", rc);
    if (!rc)
        return 0;

    drakvuf->sink_page_gfn = ++(drakvuf->max_gpfn);

    rc = xen_populate_physmap(drakvuf->xen, drakvuf->domID, &drakvuf->sink_page_gfn);
    PRINT_DEBUG("Physmap populated? %i\n", rc);
    if (!rc)
        return 0;

    uint8_t fmask[VMI_PS_4KB] = {[0 ... VMI_PS_4KB-1] = 0xFF};
    if (VMI_FAILURE == vmi_write_pa(drakvuf->vmi, drakvuf->sink_page_gfn<<12, VMI_PS_4KB, &fmask, NULL))
    {
        PRINT_DEBUG("Failed to mask FF to the empty page\n");
        return 0;
    }

    bool altp2m = xen_set_altp2m_params(drakvuf->xen, drakvuf->domID);
    PRINT_DEBUG("Altp2m params set: %i\n", altp2m);
    if (!altp2m)
        return 0;

    altp2m = vmi_slat_control(drakvuf->vmi, 1) == VMI_SUCCESS;
    PRINT_DEBUG("Altp2m enabled: %i\n", altp2m);
    if (!altp2m)
        return 0;

    /*
     * Create altp2m view
     *
     * The idx view is used primarily during DRAKVUF execution. In this view all breakpointed
     * pages will have their shadow copies activated.
     */
    status = vmi_slat_create(drakvuf->vmi, &drakvuf->altp2m_idx);
    if (VMI_FAILURE == status)
    {
        PRINT_DEBUG("Altp2m view X creation failed\n");
        return 0;
    }
    PRINT_DEBUG("Altp2m view X created with ID %u\n", drakvuf->altp2m_idx);

    /*
     * We will use the idr view to map all shadow pages to the sink page in case
     * something is trying to check the contents of the shadow pages.
     */
    status = vmi_slat_create(drakvuf->vmi, &drakvuf->altp2m_idr);
    if (VMI_FAILURE == status)
    {
        PRINT_DEBUG("Altp2m view R creation failed\n");
        return 0;
    }
    PRINT_DEBUG("Altp2m view R created with ID %u\n", drakvuf->altp2m_idr);

    /*
     * IDRX View is used for context based interception, in order to protect
     * pages that has breakpoints during execution of unmonitored contexts.
     */
    drakvuf->context_switch_intercept_processes = NULL;
    status = vmi_slat_create(drakvuf->vmi, &drakvuf->altp2m_idrx);
    if (VMI_FAILURE == status)
    {
        PRINT_DEBUG("Altp2m view RW creation failed\n");
        return 0;
    }
    PRINT_DEBUG("Altp2m view RW created with ID %u\n", drakvuf->altp2m_idrx);

    SETUP_INTERRUPT_EVENT(&drakvuf->interrupt_event, int3_cb);
    drakvuf->interrupt_event.data = drakvuf;

    if (VMI_FAILURE == vmi_register_event(drakvuf->vmi, &drakvuf->interrupt_event))
    {
        fprintf(stderr, "Failed to register interrupt event\n");
        return 0;
    }

    SETUP_MEM_EVENT(&drakvuf->mem_event, ~0ULL, VMI_MEMACCESS_RWX, pre_mem_cb, 1);
    drakvuf->mem_event.data = drakvuf;

    if (VMI_FAILURE == vmi_register_event(drakvuf->vmi, &drakvuf->mem_event))
    {
        fprintf(stderr, "Failed to register generic mem event\n");
        return 0;
    }

    if (VMI_FAILURE == vmi_set_mem_event(drakvuf->vmi, drakvuf->sink_page_gfn, VMI_MEMACCESS_RWX, drakvuf->altp2m_idx))
    {
        PRINT_DEBUG("Sink page protection failed in IDX view\n");
        return 0;
    }

    if (VMI_FAILURE == vmi_set_mem_event(drakvuf->vmi, drakvuf->sink_page_gfn, VMI_MEMACCESS_RWX, drakvuf->altp2m_idrx))
    {
        PRINT_DEBUG("Sink page protection failed in IDRX view\n");
        return 0;
    }

    status = vmi_slat_switch(drakvuf->vmi, drakvuf->altp2m_idx);
    if (VMI_FAILURE == status)
    {
        PRINT_DEBUG("Failed to switch Altp2m view to X\n");
        return 0;
    }

    // TODO: Fast singlestep is disabled by default for now while a bug is being fixed upstream in Xen
    if ( fast_singlestep && xen_version() >= 14 )
        drakvuf->int3_response_flags = VMI_EVENT_RESPONSE_SLAT_ID |     // Switch to this ID immediately
            VMI_EVENT_RESPONSE_NEXT_SLAT_ID; // Switch to next ID after singlestepping a single instruction
    else
        drakvuf->int3_response_flags = VMI_EVENT_RESPONSE_SLAT_ID |     // Switch to this ID immediately
            VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP; // Turn on singlestep

    PRINT_DEBUG("init_vmi finished\n");
    return 1;
}

// -------------------------- closing

void close_vmi(drakvuf_t drakvuf)
{
    PRINT_DEBUG("close_vmi starting\n");

    xen_pause(drakvuf->xen, drakvuf->domID);

    trap_stats_print();

    if (drakvuf->vmi)
    {
        // The caller holds the VMI lock, so the remaining callbacks have to run on this thread
        stop_parallel_events(drakvuf);

        // clear the ring
        vmi_events_listen(drakvuf->vmi, 0);

        if (VMI_FAILURE == vmi_slat_switch(drakvuf->vmi, 0))
            fprintf(stderr, "Failed to switch on default view\n");
        if (drakvuf->altp2m_idx && VMI_FAILURE == vmi_slat_destroy(drakvuf->vmi, drakvuf->altp2m_idx))
            fprintf(stderr, "Altp2m view X %u destruction failed\n", drakvuf->altp2m_idx);
        if (drakvuf->altp2m_idr && VMI_FAILURE == vmi_slat_destroy(drakvuf->vmi, drakvuf->altp2m_idr))
            fprintf(stderr, "Altp2m view R %u destruction failed\n", drakvuf->altp2m_idr);
        if (drakvuf->altp2m_idrx && VMI_FAILURE == vmi_slat_destroy(drakvuf->vmi, drakvuf->altp2m_idrx))
            fprintf(stderr, "Altp2m view RX %u destruction failed\n", drakvuf->altp2m_idrx);
        if (VMI_FAILURE == vmi_slat_control(drakvuf->vmi, false))
            fprintf(stderr, "Failed to disable alternate SLAT\n");

        // clear the generic mem_event to speed up shutdown
        vmi_clear_event(drakvuf->vmi, &drakvuf->mem_event, NULL);
        vmi_destroy(drakvuf->vmi);
        drakvuf->vmi = NULL;
    }

    if (drakvuf->memaccess_lookup_gfn)
    {
        GHashTableIter i;
        gpointer key = NULL;
        struct wrapper* s = NULL;
        ghashtable_foreach(drakvuf->memaccess_lookup_gfn, i, key, s)
        {
            g_slist_free(s->traps);
            s->traps = NULL;
        }
        // gets freed later
    }

    if (drakvuf->breakpoint_lookup_gfn)
    {
        GHashTableIter i;
        gpointer key = NULL;
        GSList* list = NULL;
        ghashtable_foreach(drakvuf->breakpoint_lookup_gfn, i, key, list)
        {
            g_slist_free(list);
        }

        g_hash_table_destroy(drakvuf->breakpoint_lookup_gfn);
        drakvuf->breakpoint_lookup_gfn = NULL;
    }

    if (drakvuf->breakpoint_lookup_pa)
    {
        GHashTableIter i;
        gpointer key = NULL;
        struct wrapper* s = NULL;
        ghashtable_foreach(drakvuf->breakpoint_lookup_pa, i, key, s)
        {
            g_slist_free(s->traps);
        }

        g_hash_table_destroy(drakvuf->breakpoint_lookup_pa);
        drakvuf->breakpoint_lookup_pa = NULL;
    }

    if (drakvuf->remapped_gfns)
    {
        GHashTableIter i;
        gpointer key;
        struct remapped_gfn* remapped_gfn = NULL;
        ghashtable_foreach(drakvuf->remapped_gfns, i, key, remapped_gfn)
        {
            xen_decrease_reservation(drakvuf->xen, drakvuf->domID, &remapped_gfn->r);
        }

        g_hash_table_destroy(drakvuf->remapped_gfns);
        drakvuf->remapped_gfns = NULL;
    }

    if (drakvuf->debug)
        g_slist_free(drakvuf->debug);
    if (drakvuf->cpuid)
        g_slist_free(drakvuf->cpuid);
    if (drakvuf->io)
        g_slist_free(drakvuf->io);
    if (drakvuf->cr3)
        g_slist_free(drakvuf->cr3);
    if (drakvuf->catchall_breakpoint)
        g_slist_free(drakvuf->catchall_breakpoint);
    if (drakvuf->memaccess_lookup_gfn)
        g_hash_table_destroy(drakvuf->memaccess_lookup_gfn);
    if (drakvuf->memaccess_lookup_trap)
        g_hash_table_destroy(drakvuf->memaccess_lookup_trap);
    if (drakvuf->breakpoint_lookup_trap)
        g_hash_table_destroy(drakvuf->breakpoint_lookup_trap);
    if (drakvuf->remove_traps)
        g_hash_table_destroy(drakvuf->remove_traps);
    if (drakvuf->injections_in_progress)
        g_hash_table_destroy(drakvuf->injections_in_progress);

    drakvuf->debug = NULL;
    drakvuf->cpuid = NULL;
    drakvuf->io = NULL;
    drakvuf->cr3 = NULL;
    drakvuf->memaccess_lookup_gfn = NULL;
    drakvuf->breakpoint_lookup_trap = NULL;
    drakvuf->remove_traps = NULL;

    unsigned int i;
    for (i = 0; i < drakvuf->vcpus; i++)
    {
        if ( !drakvuf->step_event[i] )
            continue;

        if ( drakvuf->step_event[i]->data != drakvuf )
        {
            struct memcb_pass* pass = (struct memcb_pass*)drakvuf->step_event[i]->data;
            free_proc_data_priv_2(&pass->proc_data, &pass->attached_proc_data);
            g_slice_free(struct memcb_pass, pass);
        }

        g_free(drakvuf->step_event[i]);
        drakvuf->step_event[i] = NULL;
    }

    if (drakvuf->sink_page_gfn)
        xen_decrease_reservation(drakvuf->xen, drakvuf->domID, &drakvuf->sink_page_gfn);
    xen_set_maxmemkb(drakvuf->xen, drakvuf->domID, drakvuf->init_memsize);

    drakvuf->altp2m_idx = 0;
    drakvuf->altp2m_idr = 0;
    drakvuf->sink_page_gfn = 0;

    xen_resume(drakvuf->xen, drakvuf->domID);

    PRINT_DEBUG("close_vmi finished\n");
}
