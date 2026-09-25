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

#ifndef MEMDUMP_LINUX_H
#define MEMDUMP_LINUX_H

#include "plugins/plugins_ex.h"
#include "private.h"

class memdump;

namespace memdump_ns
{

// Linux kernel struct offsets needed for memdump
enum linux_memdump_offsets
{
    TASK_STRUCT_MM,
    MM_STRUCT_MMAP,
    MM_STRUCT_PGD,
    VM_AREA_STRUCT_VM_START,
    VM_AREA_STRUCT_VM_END,
    VM_AREA_STRUCT_VM_FLAGS,
    VM_AREA_STRUCT_VM_NEXT,
    VM_AREA_STRUCT_VM_FILE,
    __LINUX_MEMDUMP_OFFSET_MAX
};

static const char* linux_memdump_offset_names[__LINUX_MEMDUMP_OFFSET_MAX][2] =
{
    [TASK_STRUCT_MM] = {"task_struct", "mm"},
    [MM_STRUCT_MMAP] = {"mm_struct", "mmap"},
    [MM_STRUCT_PGD] = {"mm_struct", "pgd"},
    [VM_AREA_STRUCT_VM_START] = {"vm_area_struct", "vm_start"},
    [VM_AREA_STRUCT_VM_END] = {"vm_area_struct", "vm_end"},
    [VM_AREA_STRUCT_VM_FLAGS] = {"vm_area_struct", "vm_flags"},
    [VM_AREA_STRUCT_VM_NEXT] = {"vm_area_struct", "vm_next"},
    [VM_AREA_STRUCT_VM_FILE] = {"vm_area_struct", "vm_file"},
};

// pt_regs offsets for reading syscall arguments
enum linux_pt_regs
{
    PT_REGS_R15,
    PT_REGS_R14,
    PT_REGS_R13,
    PT_REGS_R12,
    PT_REGS_RBP,
    PT_REGS_RBX,
    PT_REGS_R11,
    PT_REGS_R10,
    PT_REGS_R9,
    PT_REGS_R8,
    PT_REGS_RAX,
    PT_REGS_RCX,
    PT_REGS_RDX,
    PT_REGS_RSI,
    PT_REGS_RDI,
    PT_REGS_ORIG_RAX,
    PT_REGS_RIP,
    __PT_REGS_REQUIRED, // GPRs above this point are required
    PT_REGS_CS = __PT_REGS_REQUIRED,
    PT_REGS_EFLAGS,
    PT_REGS_RSP,
    PT_REGS_SS,
    __PT_REGS_MAX
};

// Required GPR offsets — must be resolvable from the kernel profile
static const char* linux_pt_regs_names_required[__PT_REGS_REQUIRED][2] =
{
    [PT_REGS_R15]      = {"pt_regs", "r15"},
    [PT_REGS_R14]      = {"pt_regs", "r14"},
    [PT_REGS_R13]      = {"pt_regs", "r13"},
    [PT_REGS_R12]      = {"pt_regs", "r12"},
    [PT_REGS_RBP]      = {"pt_regs", "bp"},
    [PT_REGS_RBX]      = {"pt_regs", "bx"},
    [PT_REGS_R11]      = {"pt_regs", "r11"},
    [PT_REGS_R10]      = {"pt_regs", "r10"},
    [PT_REGS_R9]       = {"pt_regs", "r9"},
    [PT_REGS_R8]       = {"pt_regs", "r8"},
    [PT_REGS_RAX]      = {"pt_regs", "ax"},
    [PT_REGS_RCX]      = {"pt_regs", "cx"},
    [PT_REGS_RDX]      = {"pt_regs", "dx"},
    [PT_REGS_RSI]      = {"pt_regs", "si"},
    [PT_REGS_RDI]      = {"pt_regs", "di"},
    [PT_REGS_ORIG_RAX] = {"pt_regs", "orig_ax"},
    [PT_REGS_RIP]      = {"pt_regs", "ip"},
};

// Optional offsets — cs/ss may be inside anonymous unions on kernel 6.x+ (FRED)
static const char* linux_pt_regs_names_optional[__PT_REGS_MAX - __PT_REGS_REQUIRED][2] =
{
    [PT_REGS_CS - __PT_REGS_REQUIRED]       = {"pt_regs", "cs"},
    [PT_REGS_EFLAGS - __PT_REGS_REQUIRED]   = {"pt_regs", "flags"},
    [PT_REGS_RSP - __PT_REGS_REQUIRED]      = {"pt_regs", "sp"},
    [PT_REGS_SS - __PT_REGS_REQUIRED]       = {"pt_regs", "ss"},
};

// Linux x86_64 syscall numbers for memory operations
enum linux_memory_syscalls
{
    __NR_mmap = 9,
    __NR_mprotect = 10,
    __NR_munmap = 11,
    __NR_mremap = 25,
    __NR_clone = 56,
    __NR_exit_group = 231,
    __NR_process_vm_writev = 311,
    __NR_pkey_mprotect = 329,
};

// VM flags from linux/mm.h (kernel internal values, not exposed in userspace headers)
enum vm_flags
{
    VM_READ = 0x00000001,
    VM_WRITE = 0x00000002,
    VM_EXEC = 0x00000004,
    VM_SHARED = 0x00000008,
};

} // namespace memdump_ns

// Use system-defined PROT_* and CLONE_* macros
#include <sys/mman.h>
#include <sched.h>

class linux_memdump : public pluginex
{
public:
    memdump* parent;

    // Config flags (mapped from Windows equivalents)
    bool disable_free_vm;      // Disables munmap monitoring
    bool disable_protect_vm;   // Disables mprotect monitoring
    bool disable_write_vm;     // Disables process_vm_writev monitoring
    bool disable_terminate_proc; // Disables exit_group monitoring
    bool disable_create_thread;  // Disables clone monitoring
    bool disable_shellcode_detect; // Disables RWX mmap detection

    // Kernel struct offsets
    std::array<size_t, memdump_ns::__LINUX_MEMDUMP_OFFSET_MAX> offsets;
    std::array<size_t, memdump_ns::__PT_REGS_MAX> regs;

    // Syscall hooks
    std::unique_ptr<libhook::SyscallHook> syscall_hook;

    // Return hooks for async syscall results
    std::map<std::pair<uint64_t, addr_t>, std::unique_ptr<libhook::ReturnHook>> ret_hooks;

    // Callbacks
    event_response_t syscall_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info);

    // Helper functions
    bool get_pt_regs_and_nr(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t* pt_regs_addr, uint64_t* nr);
    bool read_pt_regs_arg(drakvuf_t drakvuf, addr_t pt_regs_addr, int arg_index, uint64_t* value);
    bool is_rwx_region(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t addr);
    bool check_elf_header(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t addr);

    linux_memdump(drakvuf_t drakvuf, const memdump_config* config, output_format_t output, memdump* parent);
    linux_memdump(const linux_memdump&) = delete;
    linux_memdump& operator=(const linux_memdump&) = delete;
};

#endif
