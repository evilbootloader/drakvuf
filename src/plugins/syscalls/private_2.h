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

#ifndef SYSCALLS_PRIVATE_2_H
#define SYSCALLS_PRIVATE_2_H

#include <mutex>
#include <optional>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "plugins/plugin_utils.h"
#include "plugins/plugins_ex.h"
#include "plugins/output_format.h"
#include "plugins/helpers/return_tracker.h"

#include "private.h"

struct syscalls_config
{
    const char* syscalls_filter_file;
    const char* win32k_profile;
    bool disable_sysret;
    const char* sysret_mode;
};

// How syscall returns are caught, see --sysret-mode
enum class sysret_mode_t
{
    // A breakpoint at the return address of each syscall, removed when it returns
    PER_CALL,
    // Every syscall is caught where it returns to its caller in the kernel. The return
    // breakpoints stay in place, the calls in progress are kept per thread.
    KERNEL,
};

// internal syscalls class
class syscalls_base : public pluginex
{
public:
    os_t os;
    addr_t kernel_base;
    addr_t register_size;
    bool is32bit;
    bool disable_sysret;
    sysret_mode_t sysret_mode;

    std::unordered_set<std::string> filter;

    // `ret` is the syscall's result, which is not always in rax where the hooked function returns
    void print_sysret(drakvuf_t drakvuf, drakvuf_trap_info_t* info, int nr, uint64_t ret, const char* extra_info = nullptr);
    std::string parse_argument(drakvuf_t drakvuf, drakvuf_trap_info_t* info, const syscalls_ns::arg_t& arg, addr_t val);
    uint64_t mask_value(const syscalls_ns::arg_t& arg, uint64_t val);
    uint64_t transform_value(drakvuf_t drakvuf, drakvuf_trap_info_t* info, const syscalls_ns::arg_t& arg, uint64_t val);
    bool read_syscalls_filter(const char* filter_file);

    virtual char* win_extract_string(drakvuf_t drakvuf, drakvuf_trap_info_t* info, const syscalls_ns::arg_t& arg, addr_t val)
    {
        return NULL;
    }

    /*
     * Sysret mode kernel: every syscall is caught where the hooked function
     * returns to its caller in the kernel, through a return breakpoint that
     * stays in place, see return_tracker.
     */
    struct pending_syscall
    {
        uint16_t num;
        const char* module;
        const char* name;
        // Where the result is when the hooked function returns, if not in rax:
        // pt_regs->ax for the Linux dispatchers, which return void
        addr_t result_va;
    };
    return_tracker<pending_syscall> sysret_tracker;

    bool track_syscall_return(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t ret_addr,
        uint16_t num, const char* module, const char* name, addr_t result_va = 0);
    // Drops the calls of a process' threads that never returned
    void forget_process_syscalls(vmi_pid_t pid);
    void kernel_sysret(drakvuf_t drakvuf, drakvuf_trap_info_t* info, const pending_syscall& call);

    // Prints the sysret of a call caught in sysret mode kernel, info->trap carries its name and module
    virtual void print_kernel_sysret(drakvuf_t drakvuf, drakvuf_trap_info_t* info, const pending_syscall& call) = 0;

    syscalls_base(drakvuf_t drakvuf, const syscalls_config* config, output_format_t output);
    syscalls_base(const syscalls_base&) = delete;
    syscalls_base& operator=(const syscalls_base&) = delete;
};

#endif
