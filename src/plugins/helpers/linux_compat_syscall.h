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

#ifndef LINUX_COMPAT_SYSCALL_H
#define LINUX_COMPAT_SYSCALL_H

/*
 * 32-bit syscalls of a 64-bit Linux kernel, for the plugins that hook the
 * syscall entry themselves (filetracer, fileextractor, memdump): which
 * function dispatches them, where their number and arguments are, and which
 * x86-64 syscall each one is. A 32-bit process is invisible to a plugin that
 * hooks do_syscall_64 alone.
 */

#include <cstdint>
#include <cstring>
#include <utility>

#include <libdrakvuf/libdrakvuf.h>
#include "plugins/helpers/vmi_lock_guard.h"

namespace linux_compat
{

/*
 * What the syscalls plugin hooks for 32-bit syscalls, in its order: hooked
 * under the same name the breakpoint is shared with it, and the EventUID that
 * joins a plugin's record to the syscall's. ia32_sys_call(regs, nr) sees
 * int $0x80, sysenter and the 32-bit syscall instruction; kernels before it
 * (2024) have do_int80_syscall_32(regs), which sees int $0x80 only.
 */
inline const char* const dispatchers[] = { "ia32_sys_call", "do_int80_syscall_32" };

/*
 * pt_regs and the syscall number at a hook on one of the dispatchers, by the
 * name it was hooked under (trap->name). `orig_ax` is pt_regs.orig_ax's
 * offset.
 */
inline bool get_pt_regs_and_nr(drakvuf_t drakvuf, drakvuf_trap_info_t* info, size_t orig_ax, addr_t* pt_regs_addr, uint64_t* nr)
{
    *pt_regs_addr = info->regs->rdi;

    // ia32_sys_call(const struct pt_regs *regs, unsigned int nr)
    if (info->trap->name && !strcmp(info->trap->name, dispatchers[0]))
    {
        *nr = static_cast<uint32_t>(info->regs->rsi);
        return true;
    }

    // do_int80_syscall_32(struct pt_regs *regs): the number is what the
    // process left in eax
    uint32_t nr32 = 0;
    vmi_reader_guard vmi(drakvuf);
    if (VMI_SUCCESS != vmi_read_32_va(vmi, *pt_regs_addr + orig_ax, 0, &nr32))
        return false;
    *nr = nr32;
    return true;
}

/*
 * The six arguments: ebx, ecx, edx, esi, edi, ebp, whose offsets in pt_regs
 * `regs` gives in that order. Each is the low half of its register: the high
 * half is not the process's, and the kernel's own wrappers drop it. So a
 * pointer is right as it is, and a signed argument (an fd, AT_FDCWD) is to be
 * read as an int.
 */
inline bool read_args(drakvuf_t drakvuf, addr_t pt_regs_addr, const size_t regs[6], uint64_t args[6])
{
    vmi_reader_guard vmi(drakvuf);
    for (int i = 0; i < 6; i++)
    {
        uint32_t value = 0;
        if (VMI_SUCCESS != vmi_read_32_va(vmi, pt_regs_addr + regs[i], 0, &value))
            return false;
        args[i] = value;
    }
    return true;
}

// i386 syscalls that take their arguments differently from the x86-64
// syscall doing the same
enum : uint16_t
{
    NR_lseek = 19,
    NR_clone = 120,
    NR_llseek = 140,
    NR_pread64 = 180,
    NR_pwrite64 = 181,
    NR_mmap2 = 192,
    NR_truncate64 = 193,
    NR_ftruncate64 = 194,
};

struct translation
{
    uint16_t i386;      // number in the i386 table
    uint16_t x64;       // the x86-64 syscall that does the same
    const char* name;   // the i386 syscall's, as the syscalls plugin prints it
};

/*
 * The syscalls the three plugins handle. Numbers and names are the syscalls
 * plugin's (linux_syscalls_table_ia32, linux_syscalls_table_x64), which its
 * unit check holds this table to.
 *
 * Left out: mmap (90), which takes a pointer to its six arguments -- memdump
 * reads it itself; fstatat64 and statx, whose x86-64 counterparts the plugins
 * do not handle either; socketcall.
 */
inline const translation translations[] =
{
    { 3, 0, "read" },
    { 4, 1, "write" },
    { 5, 2, "open" },
    { 6, 3, "close" },
    { 8, 85, "creat" },
    { 9, 86, "link" },
    { 10, 87, "unlink" },
    { 12, 80, "chdir" },
    { 15, 90, "chmod" },
    { 16, 94, "lchown" },
    { 18, 4, "oldstat" },
    { NR_lseek, 8, "lseek" },
    { 28, 5, "oldfstat" },
    { 33, 21, "access" },
    { 38, 82, "rename" },
    { 39, 83, "mkdir" },
    { 40, 84, "rmdir" },
    { 41, 32, "dup" },
    { 63, 33, "dup2" },
    { 83, 88, "symlink" },
    { 84, 6, "oldlstat" },
    { 85, 89, "readlink" },
    { 91, 11, "munmap" },
    { 92, 76, "truncate" },
    { 93, 77, "ftruncate" },
    { 94, 91, "fchmod" },
    { 95, 93, "fchown" },
    { 106, 4, "stat" },
    { 107, 6, "lstat" },
    { 108, 5, "fstat" },
    { NR_clone, 56, "clone" },
    { 125, 10, "mprotect" },
    { 133, 81, "fchdir" },
    { NR_llseek, 8, "_llseek" },
    { 163, 25, "mremap" },
    { NR_pread64, 17, "pread64" },
    { NR_pwrite64, 18, "pwrite64" },
    { 182, 92, "chown" },
    { 183, 79, "getcwd" },
    { 187, 40, "sendfile" },
    { NR_mmap2, 9, "mmap2" },
    { NR_truncate64, 76, "truncate64" },
    { NR_ftruncate64, 77, "ftruncate64" },
    { 195, 4, "stat64" },
    { 196, 6, "lstat64" },
    { 197, 5, "fstat64" },
    { 198, 94, "lchown32" },
    { 207, 93, "fchown32" },
    { 212, 92, "chown32" },
    { 220, 217, "getdents64" },
    { 239, 40, "sendfile64" },
    { 252, 231, "exit_group" },
    { 295, 257, "openat" },
    { 296, 258, "mkdirat" },
    { 297, 259, "mknodat" },
    { 298, 260, "fchownat" },
    { 301, 263, "unlinkat" },
    { 302, 264, "renameat" },
    { 303, 265, "linkat" },
    { 304, 266, "symlinkat" },
    { 305, 267, "readlinkat" },
    { 306, 268, "fchmodat" },
    { 307, 269, "faccessat" },
    { 348, 311, "process_vm_writev" },
    { 353, 316, "renameat2" },
    { 356, 319, "memfd_create" },
    { 380, 329, "pkey_mprotect" },
    { 437, 437, "openat2" },
};

inline uint64_t join64(uint64_t low, uint64_t high)
{
    return (high << 32) | static_cast<uint32_t>(low);
}

// The x86-64 syscall an i386 one is, nullptr for one not in `translations`
inline const translation* find(uint64_t i386_nr)
{
    for (const auto& t : translations)
        if (t.i386 == i386_nr)
            return &t;
    return nullptr;
}

/*
 * The arguments of i386 syscall `i386_nr` (from read_args) put in the order
 * and units of the x86-64 syscall find() gives for it, so the code that
 * handles the one handles the other.
 */
inline void to_x64_args(uint64_t i386_nr, uint64_t args[6])
{
    switch (i386_nr)
    {
        case NR_lseek:
            // off_t is 32 bits and signed
            args[1] = static_cast<uint64_t>(static_cast<int64_t>(static_cast<int32_t>(args[1])));
            break;
        case NR_llseek:
            // _llseek(fd, offset_high, offset_low, loff_t* result, whence)
            args[1] = join64(args[2], args[1]);
            args[2] = args[4];
            break;
        case NR_pread64:
        case NR_pwrite64:
            // (fd, buf, count, pos_low, pos_high)
            args[3] = join64(args[3], args[4]);
            break;
        case NR_truncate64:
        case NR_ftruncate64:
            // (path or fd, length_low, length_high)
            args[1] = join64(args[1], args[2]);
            break;
        case NR_mmap2:
            // The offset is in 4096-byte units, whatever the page size
            args[5] <<= 12;
            break;
        case NR_clone:
            // (flags, newsp, parent_tid, tls, child_tid): the last two the
            // other way round
            std::swap(args[3], args[4]);
            break;
        default:
            break;
    }
}

} // namespace linux_compat

#endif
