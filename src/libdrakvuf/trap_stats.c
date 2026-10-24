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

#include "trap_stats.h"
#include "private.h"

#ifdef DRAKVUF_DEBUG

#include <inttypes.h>
#include <stdio.h>
#include <time.h>

/* Counters of one (plugin, trap type, trap name) */
struct trap_stat
{
    const char* owner;
    const char* type;
    char* name;
    bool mt_safe;
    gint64 hits;
    gint64 cb_ns;
    gint64 serial_wait_ns;   // waiting for serial_cb_lock before the callback
    gint64 adds;
    gint64 arms;
    gint64 removes;
    gint64 copies;   // page copied again after the guest wrote to it
};

/* Per plugin, of the code running on its behalf: its callbacks and its startup */
struct owner_stat
{
    const char* owner;
    gint64 vmi_waits;
    gint64 vmi_wait_ns;
    gint64 pauses;
};

#define NO_OWNER "libdrakvuf"

static GMutex stats_lock;
static GHashTable* trap_stats;    // key: "owner|type|mt_safe|name", value: struct trap_stat*
static GHashTable* owner_stats;   // key: owner string, value: struct owner_stat*
/* Pages copied again after the guest wrote to them */
struct page_copies
{
    addr_t gfn;
    gint64 copies;
    const char* owner;
    char* trap;   // one of the breakpoints on the page
};
static GHashTable* page_copies;   // key: gfn, value: struct page_copies*

static gint64 int3_events;
static gint64 int3_ns;
static gint64 serial_event_wait_ns;
static gint64 drains;

/* Plugin the current thread runs code for, the owner of the traps it adds */
static __thread const char* current_owner;

const char* drakvuf_trap_owner_enter(const char* owner)
{
    const char* previous = current_owner;
    current_owner = owner;
    return previous;
}

void drakvuf_trap_owner_leave(const char* previous)
{
    current_owner = previous;
}

gint64 trap_stats_now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (gint64)ts.tv_sec * 1000000000 + ts.tv_nsec;
}

static const char* trap_type_name(const drakvuf_trap_t* trap)
{
    switch (trap->type)
    {
        case BREAKPOINT:
            return "bp";
        case MEMACCESS:
            return "mem";
        case REGISTER:
            if (trap->regaccess.type == CR3)
                return "cr3";
            if (trap->regaccess.type == CR4)
                return "cr4";
            return "msr";
        case DEBUG:
            return "debug";
        case CPUID:
            return "cpuid";
        case IO:
            return "io";
        case CATCHALL_BREAKPOINT:
            return "catchall";
        default:
            return "?";
    }
}

/* Call with stats_lock held */
static struct owner_stat* owner_stat(const char* owner)
{
    if (!owner_stats)
        owner_stats = g_hash_table_new(g_str_hash, g_str_equal);

    struct owner_stat* stat = g_hash_table_lookup(owner_stats, owner);
    if (!stat)
    {
        stat = g_new0(struct owner_stat, 1);
        stat->owner = owner;
        g_hash_table_insert(owner_stats, (gpointer)owner, stat);
    }
    return stat;
}

/*
 * The trap keeps a pointer to its counters, which live until DRAKVUF exits.
 * The trap struct is overwritten: callers may allocate it uninitialized.
 */
void trap_stats_add(drakvuf_trap_t* trap)
{
    const char* owner = current_owner ? current_owner : NO_OWNER;
    const char* type = trap_type_name(trap);
    const char* name = trap->name ? trap->name : "-";
    gchar* key = g_strdup_printf("%s|%s|%d|%s", owner, type, trap->mt_safe, name);

    g_mutex_lock(&stats_lock);
    if (!trap_stats)
        trap_stats = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);

    struct trap_stat* stat = g_hash_table_lookup(trap_stats, key);
    if (!stat)
    {
        stat = g_new0(struct trap_stat, 1);
        stat->owner = owner;
        stat->type = type;
        stat->name = g_strdup(name);
        stat->mt_safe = trap->mt_safe;
        g_hash_table_insert(trap_stats, key, stat);
    }
    else
        g_free(key);
    stat->adds++;
    g_mutex_unlock(&stats_lock);

    trap->owner = owner;
    trap->stats = stat;
}

void trap_stats_arm(const drakvuf_trap_t* trap)
{
    struct trap_stat* stat = trap->stats;
    if (stat)
        __atomic_fetch_add(&stat->arms, 1, __ATOMIC_RELAXED);
}

void trap_stats_remove(const drakvuf_trap_t* trap)
{
    struct trap_stat* stat = trap->stats;
    if (stat)
        __atomic_fetch_add(&stat->removes, 1, __ATOMIC_RELAXED);
}

void trap_stats_shadow_copy(const drakvuf_trap_t* trap)
{
    struct trap_stat* stat = trap->stats;
    if (stat)
        __atomic_fetch_add(&stat->copies, 1, __ATOMIC_RELAXED);
}

event_response_t trap_stats_call(drakvuf_t drakvuf, drakvuf_trap_info_t* info, gint64 serial_wait_ns)
{
    // The callback may remove the trap, its counters stay
    struct trap_stat* stat = info->trap->stats;
    const char* previous = drakvuf_trap_owner_enter(info->trap->owner);
    gint64 start = trap_stats_now();

    event_response_t rsp = info->trap->cb(drakvuf, info);

    gint64 ns = trap_stats_now() - start;
    drakvuf_trap_owner_leave(previous);

    if (stat)
    {
        __atomic_fetch_add(&stat->hits, 1, __ATOMIC_RELAXED);
        __atomic_fetch_add(&stat->cb_ns, ns, __ATOMIC_RELAXED);
        __atomic_fetch_add(&stat->serial_wait_ns, serial_wait_ns, __ATOMIC_RELAXED);
    }
    return rsp;
}

void trap_stats_ah_call(drakvuf_t drakvuf, drakvuf_trap_t* trap)
{
    const char* previous = drakvuf_trap_owner_enter(trap->owner);
    trap->ah_cb(drakvuf, trap);
    drakvuf_trap_owner_leave(previous);
}

void trap_stats_page_copy(addr_t gfn, const drakvuf_trap_t* trap)
{
    g_mutex_lock(&stats_lock);
    if (!page_copies)
        page_copies = g_hash_table_new(g_int64_hash, g_int64_equal);

    struct page_copies* page = g_hash_table_lookup(page_copies, &gfn);
    if (!page)
    {
        page = g_new0(struct page_copies, 1);
        page->gfn = gfn;
        page->owner = trap && trap->owner ? trap->owner : NO_OWNER;
        page->trap = g_strdup(trap && trap->name ? trap->name : "-");
        g_hash_table_insert(page_copies, &page->gfn, page);
    }
    page->copies++;
    g_mutex_unlock(&stats_lock);
}

static gint compare_copies(gconstpointer a, gconstpointer b)
{
    gint64 ca = (*(struct page_copies* const*)a)->copies;
    gint64 cb = (*(struct page_copies* const*)b)->copies;
    return (ca < cb) - (ca > cb);
}

#define MAX_PAGE_ROWS 20

void trap_stats_vmi_wait(gint64 ns)
{
    g_mutex_lock(&stats_lock);
    struct owner_stat* stat = owner_stat(current_owner ? current_owner : NO_OWNER);
    stat->vmi_waits++;
    stat->vmi_wait_ns += ns;
    g_mutex_unlock(&stats_lock);
}

void trap_stats_serial_event_wait(gint64 ns)
{
    __atomic_fetch_add(&serial_event_wait_ns, ns, __ATOMIC_RELAXED);
}

void trap_stats_pause(void)
{
    g_mutex_lock(&stats_lock);
    owner_stat(current_owner ? current_owner : NO_OWNER)->pauses++;
    g_mutex_unlock(&stats_lock);
}

void trap_stats_int3(gint64 ns)
{
    __atomic_fetch_add(&int3_events, 1, __ATOMIC_RELAXED);
    __atomic_fetch_add(&int3_ns, ns, __ATOMIC_RELAXED);
}

void trap_stats_drain(void)
{
    __atomic_fetch_add(&drains, 1, __ATOMIC_RELAXED);
}

static gint64 stat_cost(const struct trap_stat* stat)
{
    return stat->cb_ns + stat->serial_wait_ns;
}

static gint compare_cost(gconstpointer a, gconstpointer b)
{
    gint64 ca = stat_cost(*(struct trap_stat* const*)a);
    gint64 cb = stat_cost(*(struct trap_stat* const*)b);
    return (ca < cb) - (ca > cb);
}

/* Totals of one plugin over its traps */
struct owner_total
{
    const char* owner;
    struct trap_stat sum;
};

static gint compare_total(gconstpointer a, gconstpointer b)
{
    gint64 ca = stat_cost(&(*(struct owner_total* const*)a)->sum);
    gint64 cb = stat_cost(&(*(struct owner_total* const*)b)->sum);
    return (ca < cb) - (ca > cb);
}

#define MAX_TRAP_ROWS 60

void trap_stats_print(void)
{
    g_mutex_lock(&stats_lock);

    GPtrArray* rows = g_ptr_array_new();
    GHashTable* totals = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, g_free);
    if (trap_stats)
    {
        GHashTableIter iter;
        gpointer key, value;
        g_hash_table_iter_init(&iter, trap_stats);
        while (g_hash_table_iter_next(&iter, &key, &value))
        {
            struct trap_stat* stat = value;
            g_ptr_array_add(rows, stat);

            struct owner_total* total = g_hash_table_lookup(totals, stat->owner);
            if (!total)
            {
                total = g_new0(struct owner_total, 1);
                total->owner = stat->owner;
                g_hash_table_insert(totals, (gpointer)stat->owner, total);
            }
            total->sum.hits += stat->hits;
            total->sum.cb_ns += stat->cb_ns;
            total->sum.serial_wait_ns += stat->serial_wait_ns;
            total->sum.adds += stat->adds;
            total->sum.arms += stat->arms;
            total->sum.removes += stat->removes;
            total->sum.copies += stat->copies;
        }
    }
    if (owner_stats)
    {
        // Plugins that only waited, without traps of their own
        GHashTableIter iter;
        gpointer key, value;
        g_hash_table_iter_init(&iter, owner_stats);
        while (g_hash_table_iter_next(&iter, &key, &value))
        {
            if (!g_hash_table_lookup(totals, key))
            {
                struct owner_total* total = g_new0(struct owner_total, 1);
                total->owner = key;
                g_hash_table_insert(totals, key, total);
            }
        }
    }

    fprintf(stderr, "\n[TRAP-STATS] breakpoint events %" G_GINT64_FORMAT ", %.1f ms in the handler (%.1f us each),"
        " %.1f ms waiting for serial_cb_lock in non-breakpoint events, %" G_GINT64_FORMAT " ring drains\n",
        int3_events, int3_ns / 1e6, int3_events ? int3_ns / 1e3 / int3_events : 0.0,
        serial_event_wait_ns / 1e6, drains);

    GPtrArray* owners = g_ptr_array_new();
    GHashTableIter iter;
    gpointer key, value;
    g_hash_table_iter_init(&iter, totals);
    while (g_hash_table_iter_next(&iter, &key, &value))
        g_ptr_array_add(owners, value);
    g_ptr_array_sort(owners, compare_total);

    fprintf(stderr, "[TRAP-STATS] %-16s %10s %10s %10s %12s %10s %10s %10s %10s %8s %8s\n",
        "plugin", "hits", "cb_ms", "us/hit", "serial_ms", "vmi_ms", "adds", "arms", "removes", "pauses", "copies");
    for (guint i = 0; i < owners->len; i++)
    {
        struct owner_total* total = g_ptr_array_index(owners, i);
        struct owner_stat* ostat = owner_stats ? g_hash_table_lookup(owner_stats, total->owner) : NULL;
        fprintf(stderr, "[TRAP-STATS] %-16s %10" G_GINT64_FORMAT " %10.1f %10.2f %12.1f %10.1f %10" G_GINT64_FORMAT
            " %10" G_GINT64_FORMAT " %10" G_GINT64_FORMAT " %8" G_GINT64_FORMAT " %8" G_GINT64_FORMAT "\n",
            total->owner, total->sum.hits, total->sum.cb_ns / 1e6,
            total->sum.hits ? total->sum.cb_ns / 1e3 / total->sum.hits : 0.0,
            total->sum.serial_wait_ns / 1e6, ostat ? ostat->vmi_wait_ns / 1e6 : 0.0,
            total->sum.adds, total->sum.arms, total->sum.removes, ostat ? ostat->pauses : 0, total->sum.copies);
    }

    g_ptr_array_sort(rows, compare_cost);
    fprintf(stderr, "[TRAP-STATS] %-16s %-8s %2s %10s %10s %10s %12s %10s %10s %10s %8s  %s\n",
        "plugin", "type", "mt", "hits", "cb_ms", "us/hit", "serial_ms", "adds", "arms", "removes", "copies", "trap");
    for (guint i = 0; i < rows->len && i < MAX_TRAP_ROWS; i++)
    {
        struct trap_stat* stat = g_ptr_array_index(rows, i);
        fprintf(stderr, "[TRAP-STATS] %-16s %-8s %2d %10" G_GINT64_FORMAT " %10.1f %10.2f %12.1f %10" G_GINT64_FORMAT
            " %10" G_GINT64_FORMAT " %10" G_GINT64_FORMAT " %8" G_GINT64_FORMAT "  %s\n",
            stat->owner, stat->type, stat->mt_safe, stat->hits, stat->cb_ns / 1e6,
            stat->hits ? stat->cb_ns / 1e3 / stat->hits : 0.0, stat->serial_wait_ns / 1e6,
            stat->adds, stat->arms, stat->removes, stat->copies, stat->name);
    }
    if (rows->len > MAX_TRAP_ROWS)
        fprintf(stderr, "[TRAP-STATS] %u more traps\n", rows->len - MAX_TRAP_ROWS);

    if (page_copies)
    {
        GPtrArray* pages = g_ptr_array_new();
        g_hash_table_iter_init(&iter, page_copies);
        while (g_hash_table_iter_next(&iter, &key, &value))
            g_ptr_array_add(pages, value);
        g_ptr_array_sort(pages, compare_copies);

        fprintf(stderr, "[TRAP-STATS] pages copied again after guest writes: %u, the most copied:\n", pages->len);
        fprintf(stderr, "[TRAP-STATS] %-16s %10s %-16s  %s\n", "page", "copies", "plugin", "a trap on it");
        for (guint i = 0; i < pages->len && i < MAX_PAGE_ROWS; i++)
        {
            struct page_copies* page = g_ptr_array_index(pages, i);
            fprintf(stderr, "[TRAP-STATS] 0x%-14" PRIx64 " %10" G_GINT64_FORMAT " %-16s  %s\n",
                (uint64_t)(page->gfn << 12), page->copies, page->owner, page->trap);
        }
        g_ptr_array_free(pages, TRUE);
    }

    g_ptr_array_free(owners, TRUE);
    g_ptr_array_free(rows, TRUE);
    g_hash_table_destroy(totals);

    g_mutex_unlock(&stats_lock);
}

#endif
