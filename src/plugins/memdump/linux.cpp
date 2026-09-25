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

#include <inttypes.h>
#include <assert.h>
#include <libvmi/libvmi.h>
#include <map>
#include <string>

#include "plugins/plugins.h"
#include "plugins/output_format.h"

#include "memdump.h"
#include "linux.h"
#include "private.h"

using namespace memdump_ns;

bool linux_memdump::get_pt_regs_and_nr(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t* pt_regs_addr, uint64_t* nr)
{
    /*
     * For x64_sys_call: long x64_sys_call(struct pt_regs *regs, unsigned int nr)
     *   - rdi = pt_regs* (kernel address, bit 47 set)
     *   - esi = syscall number (32-bit)
     */
    if (VMI_GET_BIT(info->regs->rdi, 47))
    {
        *pt_regs_addr = info->regs->rdi;
        uint32_t nr_32 = (uint32_t)(info->regs->rsi & 0xFFFFFFFF);
        if (nr_32 < 0x1000)
        {
            *nr = nr_32;
            return true;
        }

        // Fallback: read orig_rax from pt_regs
        auto vmi = vmi_lock_guard(drakvuf);
        return VMI_SUCCESS == vmi_read_addr_va(vmi, *pt_regs_addr + this->regs[PT_REGS_ORIG_RAX], 0, nr);
    }

    // Newer kernel style: do_syscall_64(unsigned long nr, struct pt_regs *regs)
    *nr = info->regs->rdi;
    *pt_regs_addr = info->regs->rsi;
    return true;
}

bool linux_memdump::read_pt_regs_arg(drakvuf_t drakvuf, addr_t pt_regs_addr, int arg_index, uint64_t* value)
{
    // x64 syscall args in pt_regs: rdi, rsi, rdx, r10, r8, r9
    static const int arg_offsets[] =
    {
        PT_REGS_RDI, PT_REGS_RSI, PT_REGS_RDX, PT_REGS_R10, PT_REGS_R8, PT_REGS_R9
    };

    if (arg_index < 0 || arg_index >= 6)
        return false;

    auto vmi = vmi_lock_guard(drakvuf);
    return VMI_SUCCESS == vmi_read_addr_va(vmi, pt_regs_addr + this->regs[arg_offsets[arg_index]], 0, value);
}

bool linux_memdump::is_rwx_region(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t addr)
{
    // Check if address is in an RWX memory region by checking page table flags
    auto vmi = vmi_lock_guard(drakvuf);

    page_info_t p_info = {};
    if (VMI_SUCCESS != vmi_pagetable_lookup_extended(vmi, info->regs->cr3, addr, &p_info))
        return false;

    bool page_valid = (p_info.x86_ia32e.pte_value & (1UL << 0)) != 0;
    bool page_write = (p_info.x86_ia32e.pte_value & (1UL << 1)) != 0;
    bool page_execute = (p_info.x86_ia32e.pte_value & (1UL << 63)) == 0; // NX bit = 0 means executable

    return page_valid && page_write && page_execute;
}

bool linux_memdump::check_elf_header(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t addr)
{
    auto vmi = vmi_lock_guard(drakvuf);

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = addr
    );

    uint32_t magic;
    if (VMI_SUCCESS != vmi_read_32(vmi, &ctx, &magic))
        return false;

    // ELF magic: 0x7F 'E' 'L' 'F'
    return magic == 0x464C457F;
}

static const char* get_memory_syscall_name(uint64_t nr)
{
    switch (nr)
    {
        case __NR_mmap:
            return "mmap";
        case __NR_mprotect:
            return "mprotect";
        case __NR_munmap:
            return "munmap";
        case __NR_mremap:
            return "mremap";
        case __NR_clone:
            return "clone";
        case __NR_exit_group:
            return "exit_group";
        case __NR_process_vm_writev:
            return "process_vm_writev";
        case __NR_pkey_mprotect:
            return "pkey_mprotect";
        default:
            return nullptr;
    }
}

static bool is_memory_syscall(uint64_t nr)
{
    return get_memory_syscall_name(nr) != nullptr;
}

event_response_t linux_memdump::syscall_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    addr_t pt_regs_addr = 0;
    uint64_t nr = 0;

    if (!get_pt_regs_and_nr(drakvuf, info, &pt_regs_addr, &nr))
        return VMI_EVENT_RESPONSE_NONE;

    // Filter for memory-related syscalls only
    if (!is_memory_syscall(nr))
        return VMI_EVENT_RESPONSE_NONE;

    const char* syscall_name = get_memory_syscall_name(nr);

    // Read syscall arguments from pt_regs
    uint64_t arg0 = 0, arg1 = 0, arg2 = 0, arg3 = 0, arg4 = 0;
    read_pt_regs_arg(drakvuf, pt_regs_addr, 0, &arg0);
    read_pt_regs_arg(drakvuf, pt_regs_addr, 1, &arg1);
    read_pt_regs_arg(drakvuf, pt_regs_addr, 2, &arg2);
    read_pt_regs_arg(drakvuf, pt_regs_addr, 3, &arg3);
    read_pt_regs_arg(drakvuf, pt_regs_addr, 4, &arg4);

    switch (nr)
    {
        case __NR_mmap:
        {
            // Shellcode detection via RWX mmap
            if (this->disable_shellcode_detect)
                break;

            // void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
            addr_t addr = arg0;
            size_t length = arg1;
            int prot = (int)arg2;

            // Check for RWX mapping (suspicious)
            if ((prot & PROT_READ) && (prot & PROT_WRITE) && (prot & PROT_EXEC))
            {
                PRINT_DEBUG("[MEMDUMP] Detected mmap with RWX protection at 0x%lx, size 0x%lx\n",
                    (unsigned long)addr, (unsigned long)length);

                fmt::print(this->m_output_format, "memdump", drakvuf, info,
                    keyval("Syscall", fmt::Qstr(syscall_name)),
                    keyval("DumpReason", fmt::Qstr("RWX mmap detected")),
                    keyval("Address", fmt::Xval(addr)),
                    keyval("Length", fmt::Xval(length)),
                    keyval("Protection", fmt::Nval(prot))
                );
            }
            break;
        }

        case __NR_mprotect:
        case __NR_pkey_mprotect:
        {
            // Equivalent to NtProtectVirtualMemory
            if (this->disable_protect_vm)
                break;

            // int mprotect(void *addr, size_t len, int prot)
            addr_t addr = arg0;
            size_t length = arg1;
            int prot = (int)arg2;

            // Check for protection being changed to RWX
            if ((prot & PROT_READ) && (prot & PROT_WRITE) && (prot & PROT_EXEC))
            {
                PRINT_DEBUG("[MEMDUMP] Detected mprotect changing to RWX at 0x%lx, size 0x%lx\n",
                    (unsigned long)addr, (unsigned long)length);

                // Try to dump the region
                auto vmi = vmi_lock_guard(drakvuf);
                ACCESS_CONTEXT(ctx,
                    .translate_mechanism = VMI_TM_PROCESS_DTB,
                    .dtb = info->regs->cr3,
                    .addr = addr
                );

                if (!dump_memory_region(drakvuf, vmi, info, parent, &ctx, length,
                        "mprotect to RWX detected", nullptr, false))
                {
                    PRINT_DEBUG("[MEMDUMP] Failed to dump mprotect region\n");
                }
            }
            break;
        }

        case __NR_munmap:
        {
            // Equivalent to NtFreeVirtualMemory
            if (this->disable_free_vm)
                break;

            // int munmap(void *addr, size_t length)
            addr_t addr = arg0;
            size_t length = arg1;

            // Check if unmapping RWX region or region with ELF header
            if (is_rwx_region(drakvuf, info, addr))
            {
                PRINT_DEBUG("[MEMDUMP] Detected munmap of RWX region at 0x%lx\n", (unsigned long)addr);

                auto vmi = vmi_lock_guard(drakvuf);
                ACCESS_CONTEXT(ctx,
                    .translate_mechanism = VMI_TM_PROCESS_DTB,
                    .dtb = info->regs->cr3,
                    .addr = addr
                );

                if (!dump_memory_region(drakvuf, vmi, info, parent, &ctx, length,
                        "munmap of RWX region", nullptr, false))
                {
                    PRINT_DEBUG("[MEMDUMP] Failed to dump munmap region\n");
                }
            }
            else
            {
                if (!check_elf_header(drakvuf, info, addr))
                    break;

                PRINT_DEBUG("[MEMDUMP] Detected munmap of ELF at 0x%lx\n", (unsigned long)addr);

                auto vmi = vmi_lock_guard(drakvuf);
                ACCESS_CONTEXT(ctx,
                    .translate_mechanism = VMI_TM_PROCESS_DTB,
                    .dtb = info->regs->cr3,
                    .addr = addr
                );

                if (!dump_memory_region(drakvuf, vmi, info, parent, &ctx, length,
                        "munmap of ELF binary", nullptr, false))
                {
                    PRINT_DEBUG("[MEMDUMP] Failed to dump munmap ELF region\n");
                }
            }
            break;
        }

        case __NR_process_vm_writev:
        {
            // Equivalent to NtWriteVirtualMemory
            if (this->disable_write_vm)
                break;

            // ssize_t process_vm_writev(pid_t pid, const struct iovec *local_iov,
            //     unsigned long liovcnt, const struct iovec *remote_iov,
            //     unsigned long riovcnt, unsigned long flags)
            vmi_pid_t target_pid = (vmi_pid_t)arg0;

            // This is a remote process write - always suspicious
            PRINT_DEBUG("[MEMDUMP] Detected process_vm_writev to PID %d\n", target_pid);

            fmt::print(this->m_output_format, "memdump", drakvuf, info,
                keyval("Syscall", fmt::Qstr(syscall_name)),
                keyval("DumpReason", fmt::Qstr("Remote process memory write")),
                keyval("TargetPID", fmt::Nval(target_pid))
            );
            break;
        }

        case __NR_clone:
        {
            // Equivalent to NtCreateThreadEx
            if (this->disable_create_thread)
                break;

            // long clone(unsigned long flags, void *stack, int *parent_tid, int *child_tid, unsigned long tls)
            unsigned long flags = arg0;

            // Check if CLONE_VM is set (thread creation sharing address space)
            if (flags & CLONE_VM)
            {
                PRINT_DEBUG("[MEMDUMP] Detected clone with CLONE_VM flag\n");

                fmt::print(this->m_output_format, "memdump", drakvuf, info,
                    keyval("Syscall", fmt::Qstr(syscall_name)),
                    keyval("DumpReason", fmt::Qstr("Thread creation with shared memory")),
                    keyval("Flags", fmt::Xval(flags))
                );
            }
            break;
        }

        case __NR_exit_group:
        {
            // Equivalent to NtTerminateProcess
            if (this->disable_terminate_proc)
                break;

            // void exit_group(int status)
            PRINT_DEBUG("[MEMDUMP] Process terminating via exit_group\n");

            fmt::print(this->m_output_format, "memdump", drakvuf, info,
                keyval("Syscall", fmt::Qstr(syscall_name)),
                keyval("DumpReason", fmt::Qstr("Process termination")),
                keyval("ExitStatus", fmt::Nval((int)arg0))
            );
            break;
        }

        default:
            break;
    }

    return VMI_EVENT_RESPONSE_NONE;
}

linux_memdump::linux_memdump(drakvuf_t drakvuf, const memdump_config* c, output_format_t output, memdump* parent_)
    : pluginex(drakvuf, output)
    , parent(parent_)
    , disable_free_vm(c->memdump_disable_free_vm)
    , disable_protect_vm(c->memdump_disable_protect_vm)
    , disable_write_vm(c->memdump_disable_write_vm)
    , disable_terminate_proc(c->memdump_disable_terminate_proc)
    , disable_create_thread(c->memdump_disable_create_thread)
    , disable_shellcode_detect(c->memdump_disable_shellcode_detect)
{
    PRINT_DEBUG("[MEMDUMP] Initializing Linux memdump\n");

    // Get kernel struct offsets
    if (!drakvuf_get_kernel_struct_members_array_rva(drakvuf, linux_memdump_offset_names,
            this->offsets.size(), this->offsets.data()))
    {
        PRINT_DEBUG("[MEMDUMP] Warning: Failed to get some Linux kernel offsets\n");
    }

    // Get required pt_regs offsets (GPRs used for syscall argument reading)
    if (!drakvuf_get_kernel_struct_members_array_rva(drakvuf, linux_pt_regs_names_required,
            __PT_REGS_REQUIRED, this->regs.data()))
    {
        PRINT_DEBUG("[MEMDUMP] Failed to get required pt_regs offsets, memdump disabled\n");
        return;
    }

    // Get optional pt_regs offsets (cs/ss may be in anonymous unions on kernel 6.x+)
    if (!drakvuf_get_kernel_struct_members_array_rva(drakvuf, linux_pt_regs_names_optional,
            __PT_REGS_MAX - __PT_REGS_REQUIRED, this->regs.data() + __PT_REGS_REQUIRED))
    {
        PRINT_DEBUG("[MEMDUMP] Warning: optional pt_regs offsets unavailable (cs/ss)\n");
    }

    // Try do_syscall_64 first - reliable on kernel 6.x+ with FRED where
    // x64_sys_call may be called via static_call (bypassing INT3 at entry)
    syscall_hook = createSyscallHook("do_syscall_64", &linux_memdump::syscall_cb, "do_syscall_64");
    if (syscall_hook)
    {
        PRINT_DEBUG("[MEMDUMP] Hooked do_syscall_64\n");
        return;
    }
    PRINT_DEBUG("[MEMDUMP] do_syscall_64 hook failed, trying x64_sys_call\n");

    // Fallback to x64_sys_call
    syscall_hook = createSyscallHook("x64_sys_call", &linux_memdump::syscall_cb, "x64_sys_call");
    if (syscall_hook)
    {
        PRINT_DEBUG("[MEMDUMP] Hooked x64_sys_call\n");
        return;
    }

    PRINT_DEBUG("[MEMDUMP] No syscall entry point found, memdump disabled\n");
}
