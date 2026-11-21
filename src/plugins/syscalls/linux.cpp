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
#include <atomic>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

#include "plugins/output_format.h"

#include "linux.h"

using namespace syscalls_ns;

// prctl's option that names the calling thread: PR_SET_NAME in prctl_option
static constexpr uint32_t LINUX_PR_SET_NAME = 15;


bool linux_syscalls::get_pt_regs_addr(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t* pt_regs_addr, addr_t* nr)
{
    auto vmi = vmi_reader_guard(drakvuf);

    /*
     * For x64_sys_call: long x64_sys_call(struct pt_regs *regs, unsigned int nr)
     *   - rdi = pt_regs* (kernel address, bit 47 set)
     *   - esi = syscall number (32-bit!)
     *
     * For syscall_enter_from_user_mode: (struct pt_regs *regs, long syscall)
     *   - rdi = pt_regs* (kernel address, bit 47 set)
     *   - rsi = syscall number
     *
     * For do_syscall_64 (older kernels): (struct pt_regs *regs)
     *   - rdi = pt_regs*
     *   - syscall number in pt_regs->orig_rax
     *
     * For do_syscall_64 (newer kernels): (unsigned long nr, struct pt_regs *regs)
     *   - rdi = syscall number (won't have bit 47 set)
     *   - rsi = pt_regs*
     */
    if ( VMI_GET_BIT(info->regs->rdi, 47) )
    {
        // rdi is a kernel pointer (pt_regs)
        *pt_regs_addr = info->regs->rdi;

        // For x64_sys_call and syscall_enter_from_user_mode, the syscall number
        // is passed as the second argument. Use 32-bit esi for x64_sys_call
        // (unsigned int nr) or full rsi for syscall_enter_from_user_mode (long).
        // Both are small values (< 0x1000), so just use the lower 32 bits.
        uint32_t nr_32 = (uint32_t)(info->regs->rsi & 0xFFFFFFFF);
        if (nr_32 < 0x1000)
        {
            *nr = nr_32;
            return true;
        }

        // Otherwise, read orig_rax from pt_regs (do_syscall_64 old style)
        return VMI_SUCCESS == vmi_read_addr_va(vmi, *pt_regs_addr + this->regs[PT_REGS_ORIG_RAX], 0, nr);
    }

    /*
    * On newer kernels: __visible void do_syscall_64(unsigned long nr, struct pt_regs *regs)
    */
    *nr = info->regs->rdi;
    *pt_regs_addr = info->regs->rsi;
    return true;
}

std::vector<uint64_t> linux_syscalls::build_arguments_buffer(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t pt_regs_addr, addr_t nr,
    const syscall_t* sc, const char* syscall_type)
{
    std::vector<uint64_t> arguments;

    // unknown syscall, so skip. A 32-bit syscall of a 64-bit kernel has an i386 number, which goes higher.
    bool ia32 = !this->is32bit && !strcmp(syscall_type, SYSCALL_TYPE_LINUX_X32);
    if ((this->is32bit && nr > NUM_SYSCALLS_LINUX_X32) ||
        (!this->is32bit && nr > (ia32 ? NUM_SYSCALLS_LINUX_IA32 : NUM_SYSCALLS_LINUX_X64)))
        return arguments;

    int nargs = sc->num_args;

    // get arguments only if we know how many to get
    if (!nargs)
        return arguments;

    // Now now, only support legacy syscall arg passing on 32 bit
    if ( 4 == this->register_size )
    {
        if ( nargs > 0 )
            arguments.push_back(info->regs->rbx);
        if ( nargs > 1 )
            arguments.push_back(info->regs->rcx);
        if ( nargs > 2 )
            arguments.push_back(info->regs->rdx);
        if ( nargs > 3 )
            arguments.push_back(info->regs->rsi);
        if ( nargs > 4 )
            arguments.push_back(info->regs->rdi);
    }
    else if ( 8 == this->register_size )
    {
        // Support both calling conventions for 64 bit Linux syscalls
        if (pt_regs_addr)
        {
            auto vmi = vmi_reader_guard(drakvuf);
            // The syscall args are passed via a struct pt_regs *, which is in %rdi upon entry
            size_t pt_regs[__PT_REGS_MAX] = {0};
            ACCESS_CONTEXT(ctx,
                .translate_mechanism = VMI_TM_PROCESS_DTB,
                .dtb = info->regs->cr3
            );

            for ( int i = 0; i < __PT_REGS_MAX; i++)
            {
                ctx.addr = pt_regs_addr + this->regs[i];
                if ( VMI_FAILURE == vmi_read_64(vmi, &ctx, &pt_regs[i]) )
                {
                    PRINT_DEBUG("[SYSCALLS] vmi_read_64(%p) failed\n", (void*)ctx.addr);
                    return arguments;
                }
            }

            // The order of the arguments is different when processing x32 syscalls
            // https://elixir.bootlin.com/linux/v5.10.166/source/arch/x86/include/asm/syscall_wrapper.h#L24
            // Assume if it is not x32 syscall, then we will use the standard convention for x64
            // The upper halves of the registers of a 32-bit process are not its own: the
            // kernel's wrappers truncate them too, and a pointer would not be read otherwise.
            if ( !strcmp(syscall_type, SYSCALL_TYPE_LINUX_X32) )
            {
                if ( nargs > 0 )
                    arguments.push_back((uint32_t)pt_regs[PT_REGS_RBX]);
                if ( nargs > 1 )
                    arguments.push_back((uint32_t)pt_regs[PT_REGS_RCX]);
                if ( nargs > 2 )
                    arguments.push_back((uint32_t)pt_regs[PT_REGS_RDX]);
                if ( nargs > 3 )
                    arguments.push_back((uint32_t)pt_regs[PT_REGS_RSI]);
                if ( nargs > 4 )
                    arguments.push_back((uint32_t)pt_regs[PT_REGS_RDI]);
                if ( nargs > 5 )
                    arguments.push_back((uint32_t)pt_regs[PT_REGS_RBP]);
            }
            else
            {
                if ( nargs > 0 )
                    arguments.push_back(pt_regs[PT_REGS_RDI]);
                if ( nargs > 1 )
                    arguments.push_back(pt_regs[PT_REGS_RSI]);
                if ( nargs > 2 )
                    arguments.push_back(pt_regs[PT_REGS_RDX]);
                // The fourth is in r10, not rcx as for a function: the syscall instruction
                // puts the address it returns to in rcx
                if ( nargs > 3 )
                    arguments.push_back(pt_regs[PT_REGS_R10]);
                if ( nargs > 4 )
                    arguments.push_back(pt_regs[PT_REGS_R8]);
                if ( nargs > 5 )
                    arguments.push_back(pt_regs[PT_REGS_R9]);
            }
        }
        else
        {
            // The args are passed directly via registers in sycall context
            if ( nargs > 0 )
                arguments.push_back(info->regs->rdi);
            if ( nargs > 1 )
                arguments.push_back(info->regs->rsi);
            if ( nargs > 2 )
                arguments.push_back(info->regs->rdx);
            if ( nargs > 3 )
                arguments.push_back(info->regs->rcx);
            if ( nargs > 4 )
                arguments.push_back(info->regs->r8);
            if ( nargs > 5 )
                arguments.push_back(info->regs->r9);
        }
    }

    return arguments;
}

/*
 * What get_origin reads, from the kernel profile: the vDSO of an mm_struct and its size, the
 * path of a struct file, and the kernel's vDSO images, which tell a 32-bit process from a 64-bit
 * one. False when one is missing: syscalls are reported without where they came from then.
 */
bool linux_syscalls::setup_origin(drakvuf_t drakvuf)
{
    addr_t mm_context = 0, context_vdso = 0, context_vdso_image = 0, path_dentry = 0;
    if (!drakvuf_get_kernel_struct_member_rva(drakvuf, "task_struct", "mm", &this->task_mm) ||
        !drakvuf_get_kernel_struct_member_rva(drakvuf, "mm_struct", "context", &mm_context) ||
        !drakvuf_get_kernel_struct_member_rva(drakvuf, "mm_context_t", "vdso", &context_vdso) ||
        !drakvuf_get_kernel_struct_member_rva(drakvuf, "mm_context_t", "vdso_image", &context_vdso_image) ||
        !drakvuf_get_kernel_struct_member_rva(drakvuf, "vdso_image", "size", &this->vdso_image_size) ||
        !drakvuf_get_kernel_struct_member_rva(drakvuf, "file", "f_path", &this->file_path) ||
        !drakvuf_get_kernel_struct_member_rva(drakvuf, "path", "dentry", &path_dentry))
        return false;
    this->mm_vdso = mm_context + context_vdso;
    this->mm_vdso_image = mm_context + context_vdso_image;

    // A kernel without the compat ABIs has no vdso_image_32 or vdso_image_x32
    auto vmi = vmi_lock_guard(drakvuf);
    if (VMI_SUCCESS != vmi_translate_ksym2v(vmi, "vdso_image_64", &this->vdso_image_64))
        return false;
    vmi_translate_ksym2v(vmi, "vdso_image_32", &this->vdso_image_32);
    vmi_translate_ksym2v(vmi, "vdso_image_x32", &this->vdso_image_x32);
    return true;
}

/*
 * The file mapped at `addr`: its path, or "" for memory no file backs; nothing when it could not
 * be looked up -- the VMA list, which only kernels before 6.1 have (drakvuf_linux_find_vma), or
 * the file's path. A file is cached by its VMA's range; memory no file backs is not, since it is
 * unmapped and mapped again, and a file may be mapped where it was.
 */
std::optional<std::string> linux_syscalls::resolve_module(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t mm, addr_t addr)
{
    const auto key = std::make_pair(info->proc_data.pid, mm);
    {
        std::lock_guard<std::mutex> lock(this->mappings_mtx);
        if (auto it = this->mappings.find(key); it != this->mappings.end())
        {
            for (const auto& m : it->second)
                if (addr >= m.start && addr < m.end)
                    return m.name;
        }
    }

    const addr_t task = info->proc_data.base_addr;
    addr_t file = 0;
    if (!drakvuf_linux_find_vma_file(drakvuf, task, addr, &file))
        return {};
    if (!file)
        return std::string();

    // Across mounts, as the process's own path is (ProcessName): the two are
    // compared to tell a program's own code
    char* path = drakvuf_get_filepath_from_path(drakvuf, file + this->file_path);
    if (!path)
        return {};
    std::string name = path;
    g_free(path);

    addr_t start = 0, end = 0;
    if (drakvuf_linux_find_vma(drakvuf, task, addr, &start, &end))
    {
        std::lock_guard<std::mutex> lock(this->mappings_mtx);
        this->mappings[key].push_back({ start, end, name });
    }
    return name;
}

/*
 * Where a syscall was made from: pt_regs->ip, the instruction after the one that entered the
 * kernel, and the file mapped there. That is libc, the dynamic linker, the vDSO or the program
 * itself -- static and Go programs make their syscalls from their own code, so a program's own
 * file says nothing -- or memory no file backs: shellcode, injected code, a packer's unpacked
 * program. No frame 1 as on Windows: a libc wrapper that is a cancellation point keeps a frame
 * of its own, so the word at the stack pointer is not always a return address, and nothing here
 * unwinds with .eh_frame.
 *
 * For a 32-bit syscall, the process's bitness, by its vDSO -- the kernel maps vdso_image_32 for a
 * 32-bit process -- since a 64-bit process making one (int 0x80) goes past what traces only the
 * 64-bit syscall table, and past seccomp filters written for it. pt_regs->cs would not say: the
 * sysenter and compat syscall entries store a constant there.
 */
linux_syscalls::syscall_origin linux_syscalls::get_origin(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t pt_regs_addr, const char* syscall_type)
{
    syscall_origin origin;
    if (!this->task_mm || !pt_regs_addr)
        return origin;

    addr_t mm = 0, vdso = 0, vdso_image = 0, vdso_size = 0;
    {
        vmi_reader_guard vmi(drakvuf);
        if (VMI_SUCCESS != vmi_read_addr_va(vmi, pt_regs_addr + this->regs[PT_REGS_RIP], 0, &origin.caller) ||
            VMI_SUCCESS != vmi_read_addr_va(vmi, info->proc_data.base_addr + this->task_mm, 0, &mm) || !mm)
            return {};
        if (VMI_SUCCESS == vmi_read_addr_va(vmi, mm + this->mm_vdso, 0, &vdso) &&
            VMI_SUCCESS == vmi_read_addr_va(vmi, mm + this->mm_vdso_image, 0, &vdso_image) && vdso_image &&
            VMI_SUCCESS != vmi_read_addr_va(vmi, vdso_image + this->vdso_image_size, 0, &vdso_size))
            vdso_size = 0;
    }

    if (vdso && origin.caller >= vdso && origin.caller < vdso + vdso_size)
        origin.module = "[vdso]";
    else if (origin.caller)
        origin.module = this->resolve_module(drakvuf, info, mm, origin.caller);

    if (!strcmp(syscall_type, SYSCALL_TYPE_LINUX_X32) && vdso_image)
    {
        if (vdso_image == this->vdso_image_32)
            origin.bitness = 32;
        else if (vdso_image == this->vdso_image_64 || vdso_image == this->vdso_image_x32)
            origin.bitness = 64;
    }
    return origin;
}

// PR_SET_NAME's arg2: the name the thread takes, of which the kernel copies the 15 bytes a comm
// holds. Nothing when it cannot be read up to its end.
static std::optional<std::string> read_thread_name(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t addr)
{
    char comm[16] = {0}; // TASK_COMM_LEN
    size_t got = 0;
    {
        vmi_reader_guard vmi(drakvuf);
        ACCESS_CONTEXT(ctx,
            .translate_mechanism = VMI_TM_PROCESS_DTB,
            .dtb = info->regs->cr3,
            .addr = addr
        );
        // Stops at a page that is not present, with what was read before it
        vmi_read(vmi, &ctx, sizeof(comm) - 1, comm, &got);
    }
    if (!got || (got < sizeof(comm) - 1 && !memchr(comm, 0, got)))
        return {};
    return std::string(comm);
}

void linux_syscalls::print_syscall(drakvuf_t drakvuf, drakvuf_trap_info_t* entry_info, const syscalls_ns::syscall_t* sc, uint16_t syscall_num, const char* syscall_type, std::vector<uint64_t> arguments, const syscall_origin& origin)
{
    // Name the trap after the syscall so Method shows it. The dispatcher hooks are shared by all
    // syscalls and may run on several vCPU threads at once, so a copy of the trap is named.
    drakvuf_trap_t trap = *entry_info->trap;
    if (sc)
        trap.name = sc->display_name;
    drakvuf_trap_info_t named_info = *entry_info;
    named_info.trap = &trap;
    drakvuf_trap_info_t* info = &named_info;

    std::vector<std::pair<char const*, fmt::Aarg>> fmt_args;
    for (size_t i = 0; i < arguments.size(); i++)
    {
        // What prctl's arg2 is depends on its option, which parse_argument does not see: for
        // PR_SET_NAME the new name, a blank one being how Mirai hides its process
        if (i == 1 && sc->args[0].type == linux_intopt_pr_ && (uint32_t)arguments[0] == LINUX_PR_SET_NAME)
        {
            if (auto name = read_thread_name(drakvuf, info, arguments[i]))
            {
                fmt_args.push_back(keyval(sc->args[i].name, exact_str(*name)));
                continue;
            }
        }
        auto str = this->parse_argument(drakvuf, info, sc->args[i], arguments[i]);
        if (!str.empty())
            fmt_args.push_back(keyval(sc->args[i].name, fmt::Estr(str)));
        else
        {
            uint64_t value = this->transform_value(drakvuf, info, sc->args[i], arguments[i]);
            fmt_args.push_back(keyval(sc->args[i].name, fmt::Xval(value)));
        }
    }

    char* tmp = drakvuf_get_process_name(drakvuf, info->proc_data.base_addr, false);
    std::string thread_name = tmp ?: "";
    g_free(tmp);

    // Where it was made from (get_origin): left out when unknown, the module "" for memory no
    // file backs (exact_str)
    std::optional<fmt::Xval<addr_t>> caller;
    if (origin.caller)
        caller = fmt::Xval(origin.caller);
    std::optional<fmt::Estr<std::string>> from_module;
    if (origin.caller && origin.module)
        from_module = exact_str(*origin.module);
    std::optional<fmt::Nval<int>> bitness;
    if (origin.bitness)
        bitness = fmt::Nval(origin.bitness);

    fmt::print(this->m_output_format, "syscall", drakvuf, info,
        keyval("ThreadName", fmt::Estr(thread_name)),
        keyval("Module", fmt::Qstr(std::move(info->trap->breakpoint.module))),
        keyval("vCPU", fmt::Nval(info->vcpu)),
        keyval("CR3", fmt::Xval(info->regs->cr3)),
        keyval("Syscall", fmt::Nval((uint64_t)syscall_num)),
        keyval("NArgs", fmt::Nval(sc->num_args)),
        keyval("Type", fmt::Rstr(syscall_type)),
        keyval("Bitness", bitness),
        keyval("Caller", caller),
        keyval("FromModule", from_module),
        fmt_args
    );
}

event_response_t linux_syscalls::linux_ret_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto params = libhook::GetTrapParams<linux_syscall_data>(info);

    // Set trap name to syscall name so Method field shows the actual syscall
    if (params->sc)
        info->trap->name = params->sc->display_name;

    this->print_sysret(drakvuf, info, (uint64_t)params->num, this->syscall_result(drakvuf, info, params->result_va));

    auto hookID = make_hook_id(info, params->target_rsp);
    this->ret_hooks.erase(hookID);

    return VMI_EVENT_RESPONSE_NONE;
}

// Helper to look up syscall definition for dispatcher hooks (x64_sys_call/do_syscall_64, ia32_sys_call/do_int80_syscall_32)
// Returns nullptr if the syscall should be skipped (invalid, no definition, or filtered)
const syscall_t* linux_syscalls::lookup_syscall_for_dispatcher(drakvuf_trap_info_t* info, addr_t nr, const char** out_type, uint16_t* out_num)
{
    bool is_32bit_syscall = (info->trap->name && strstr(info->trap->name, "32") != nullptr);
    const syscall_t** syscall_table = is_32bit_syscall ? linuxsc::linux_syscalls_table_ia32 : linuxsc::linux_syscalls_table_x64;
    uint64_t num_syscalls = is_32bit_syscall ? NUM_SYSCALLS_LINUX_IA32 : NUM_SYSCALLS_LINUX_X64;
    *out_type = is_32bit_syscall ? SYSCALL_TYPE_LINUX_X32 : SYSCALL_TYPE_LINUX_X64;

    if (nr >= num_syscalls)
    {
        PRINT_DEBUG("[SYSCALLS] Unknown syscall nr=%lu (max=%lu), skipping\n", nr, num_syscalls);
        return nullptr;
    }

    const syscall_t* syscall_def = syscall_table[nr];
    if (!syscall_def)
    {
        PRINT_DEBUG("[SYSCALLS] No definition for syscall nr=%lu, skipping\n", nr);
        return nullptr;
    }

    *out_num = (uint16_t)nr;

    // Apply filter if configured
    if (!this->filter.empty() && (this->filter.find(syscall_def->display_name) == this->filter.end()))
        return nullptr;

    return syscall_def;
}

bool linux_syscalls::hooks_mt_safe() const
{
    return this->disable_sysret || this->sysret_mode == sysret_mode_t::KERNEL;
}

void linux_syscalls::print_kernel_sysret(drakvuf_t drakvuf, drakvuf_trap_info_t* info, const pending_syscall& call)
{
    this->print_sysret(drakvuf, info, call.num, this->syscall_result(drakvuf, info, call.result_va));
}

/*
 * do_syscall_64 and do_int80_syscall_32 store the result in pt_regs->ax and
 * return void (or a bool on newer kernels), so rax where they return is not
 * the result. x64_sys_call and the __x64_sys_* functions return it in rax, and
 * their caller stores it after they return.
 */
addr_t linux_syscalls::result_va_of(drakvuf_trap_info_t* info, addr_t pt_regs_addr)
{
    const char* hooked = info->trap->name;
    if (!pt_regs_addr || !hooked)
        return 0;
    if (strcmp(hooked, "do_syscall_64") && strcmp(hooked, "do_int80_syscall_32"))
        return 0;
    return pt_regs_addr + this->regs[PT_REGS_RAX];
}

uint64_t linux_syscalls::syscall_result(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t result_va)
{
    if (!result_va)
        return info->regs->rax;

    auto vmi = vmi_reader_guard(drakvuf);
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = result_va
    );
    uint64_t result = 0;
    if (VMI_FAILURE == vmi_read_64(vmi, &ctx, &result))
    {
        PRINT_DEBUG("[SYSCALLS] Failed to read the result at 0x%lx\n", result_va);
        return info->regs->rax;
    }
    return result;
}

// Runs on several vCPU threads at once when hooks_mt_safe(): the hook params are shared by all
// syscalls of a dispatcher hook and are only read here.
event_response_t linux_syscalls::linux_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    addr_t pt_regs_addr = 0;
    addr_t nr = ~0;

    if (!get_pt_regs_addr(drakvuf, info, &pt_regs_addr, &nr))
    {
        PRINT_DEBUG("[SYSCALLS] get_pt_regs_addr failed in %s\n",
            info->trap->name ? info->trap->name : "null");
        return VMI_EVENT_RESPONSE_NONE;
    }

    auto params = libhook::GetTrapParams<linux_syscall_data>(info);
    const syscall_t* syscall_def = params->sc;
    const char* syscall_type = params->type.c_str();
    uint16_t syscall_num = params->num;

    // For dispatcher hooks (x64_sys_call/do_syscall_64) sc is null, the syscall is looked up dynamically
    if (!syscall_def)
    {
        syscall_def = lookup_syscall_for_dispatcher(info, nr, &syscall_type, &syscall_num);
        if (!syscall_def)
            return VMI_EVENT_RESPONSE_NONE;
    }

    auto arguments = build_arguments_buffer(drakvuf, info, pt_regs_addr, nr, syscall_def, syscall_type);
    this->print_syscall(drakvuf, info, syscall_def, syscall_num, syscall_type, arguments,
        this->get_origin(drakvuf, info, pt_regs_addr, syscall_type));

    if (this->disable_sysret || this->is_stopping())
        return VMI_EVENT_RESPONSE_NONE;

    if (this->sysret_mode == sysret_mode_t::KERNEL)
    {
        // exit and exit_group don't return
        if (strcmp(syscall_def->display_name, "exit") && strcmp(syscall_def->display_name, "exit_group"))
        {
            // Where the hooked function returns to, for do_syscall_64 a fixed spot in entry_SYSCALL_64
            addr_t ret_addr = drakvuf_get_function_return_address(drakvuf, info);
            if (ret_addr)
                this->track_syscall_return(drakvuf, info, ret_addr, syscall_num,
                    info->trap->breakpoint.module, syscall_def->display_name,
                    this->result_va_of(info, pt_regs_addr));
        }
        return VMI_EVENT_RESPONSE_NONE;
    }

    auto hook = this->createReturnHook<linux_syscall_data>(info, &linux_syscalls::linux_ret_cb, syscall_def->display_name);
    if (!hook)
        return VMI_EVENT_RESPONSE_NONE;

    auto ret_params = libhook::GetTrapParams<linux_syscall_data>(hook->trap_);
    ret_params->setResultCallParams(drakvuf, info);
    ret_params->num = syscall_num;
    ret_params->type = syscall_type;
    ret_params->sc = syscall_def;
    ret_params->result_va = this->result_va_of(info, pt_regs_addr);

    auto hookID = make_hook_id(info, ret_params->target_rsp);
    this->ret_hooks[hookID] = std::move(hook);

    return VMI_EVENT_RESPONSE_NONE;
}

bool linux_syscalls::register_hook(char* syscall_name, uint64_t syscall_number, const syscall_t* syscall_definition, bool is_x64)
{
    auto hook = createSyscallHook<linux_syscall_data>(syscall_name, &linux_syscalls::linux_cb, syscall_definition->display_name,
            UNLIMITED_TTL, this->hooks_mt_safe());
    if (!hook)
    {
        PRINT_DEBUG("[SYSCALLS] Failed to register %s\n", syscall_name);
        return false;
    }

    // Populate params to hook
    auto params = libhook::GetTrapParams<linux_syscall_data>(hook->trap_);
    params->num = syscall_number;
    params->type = is_x64 ? SYSCALL_TYPE_LINUX_X64 : SYSCALL_TYPE_LINUX_X32;
    params->sc = syscall_definition;

    // If there is a collision when two functions point to the same address (for example getpid/getppid),
    // then we will take only the last one that got into the map, in this case __x64_sys_*
    this->hooks[hook->trap_->breakpoint.addr] = std::move(hook);
    return true;
}

bool linux_syscalls::trap_syscall_table_entries(drakvuf_t drakvuf)
{
    /*
     * Modern kernels (6.x) use static_call/retpoline optimizations that may bypass
     * the actual function entry points. On kernel 6.x+ with FRED, x64_sys_call is
     * called via static_call which can patch the call site to skip the function
     * entry point, making INT3 breakpoints there ineffective. We hook do_syscall_64
     * first since it is always called directly from the syscall entry assembly.
     *
     * Hook priority:
     * 1. do_syscall_64 - outer dispatcher, always called at entry point
     *    Old signature: void do_syscall_64(struct pt_regs *regs)
     *    New signature: void do_syscall_64(unsigned long nr, struct pt_regs *regs)
     * 2. x64_sys_call - inner dispatcher (may be bypassed by static_call on FRED)
     * 3. Individual __x64_sys_* hooks - legacy fallback
     *
     * Note: Filter is applied at callback time instead of hook registration time.
     */
    PRINT_DEBUG("[SYSCALLS] Using modern kernel syscall hooking mode\n");

    // For x64 systems, try do_syscall_64 first (reliable on FRED kernels)
    if (!this->is32bit)
    {
        auto hook = createSyscallHook<linux_syscall_data>("do_syscall_64", &linux_syscalls::linux_cb, "do_syscall_64",
                UNLIMITED_TTL, this->hooks_mt_safe());

        if (hook)
        {
            auto params = libhook::GetTrapParams<linux_syscall_data>(hook->trap_);
            params->num = 0;
            params->type = SYSCALL_TYPE_LINUX_X64;
            params->sc = nullptr;  // null sc triggers dynamic lookup in linux_cb

            addr_t hook_addr = hook->trap_->breakpoint.addr;
            this->hooks[hook_addr] = std::move(hook);
            PRINT_DEBUG("[SYSCALLS] Registered do_syscall_64 hook at 0x%lx\n", (unsigned long)hook_addr);
        }
        else
        {
            // Fallback to x64_sys_call
            PRINT_DEBUG("[SYSCALLS] do_syscall_64 not found, trying x64_sys_call\n");
            hook = createSyscallHook<linux_syscall_data>("x64_sys_call", &linux_syscalls::linux_cb, "x64_sys_call",
                    UNLIMITED_TTL, this->hooks_mt_safe());
            if (hook)
            {
                auto params = libhook::GetTrapParams<linux_syscall_data>(hook->trap_);
                params->num = 0;
                params->type = SYSCALL_TYPE_LINUX_X64;
                params->sc = nullptr;

                addr_t hook_addr = hook->trap_->breakpoint.addr;
                this->hooks[hook_addr] = std::move(hook);
                PRINT_DEBUG("[SYSCALLS] Registered x64_sys_call hook at 0x%lx\n", (unsigned long)hook_addr);
            }
            else
            {
                PRINT_DEBUG("[SYSCALLS] Failed to register syscall hook, falling back to individual syscall hooks\n");
                return this->trap_syscall_table_entries_legacy(drakvuf);
            }
        }
    }

    /*
     * 32-bit syscalls. On a 64-bit kernel, int $0x80 and sysenter or syscall from
     * 32-bit mode all dispatch through ia32_sys_call(regs, nr), the counterpart of
     * x64_sys_call, which takes its arguments the same way. By then the number is
     * final and all six arguments are in pt_regs: the sysenter path reads the sixth
     * from the user stack first. Kernels before the 2024 branch history injection
     * fix don't have it and call through ia32_sys_call_table; do_int80_syscall_32
     * is the fallback there, and sees int $0x80 only. A kernel whose int $0x80
     * goes to int80_emulation has no do_int80_syscall_32 at all, so its hook was
     * never placed: the Ubuntu (5.15) and Android (6.6) guests' among them.
     * A 32-bit kernel keeps the do_int80_syscall_32 hook it had.
     */
    std::vector<const char*> dispatchers32 = { "do_int80_syscall_32" };
    if (!this->is32bit)
        dispatchers32.insert(dispatchers32.begin(), "ia32_sys_call");

    bool hooked32 = false;
    for (const char* dispatcher : dispatchers32)
    {
        auto hook = createSyscallHook<linux_syscall_data>(dispatcher, &linux_syscalls::linux_cb, dispatcher,
                UNLIMITED_TTL, this->hooks_mt_safe());
        if (!hook)
        {
            PRINT_DEBUG("[SYSCALLS] %s not found\n", dispatcher);
            continue;
        }

        auto params = libhook::GetTrapParams<linux_syscall_data>(hook->trap_);
        params->num = 0;
        params->type = SYSCALL_TYPE_LINUX_X32;
        params->sc = nullptr;  // null sc triggers dynamic lookup

        this->hooks[hook->trap_->breakpoint.addr] = std::move(hook);
        PRINT_DEBUG("[SYSCALLS] Registered %s hook\n", dispatcher);
        hooked32 = true;
        break;
    }

    // Only a debug message until now, which hid that no 32-bit syscall was traced
    if (!hooked32)
        fprintf(stderr, "[SYSCALLS] No 32-bit syscall dispatcher found, syscalls of 32-bit processes are not traced\n");

    return true;
}

// Legacy method for older kernels where individual __x64_sys_* hooks work
bool linux_syscalls::trap_syscall_table_entries_legacy(drakvuf_t drakvuf)
{
    // In this case, we check whether we were able to install all syscalls without errors,
    // and if this isn't the case, we simply warn the user that some syscalls couldn't be installed correctly
    // For example, old kernels don't support new syscalls, and hooks can't be installed
    bool check = true;
    static const syscall_t** syscall_table = (this->is32bit)? linuxsc::linux_syscalls_table_x32 : linuxsc::linux_syscalls_table_x64;
    uint64_t num_syscalls = (this->is32bit)? NUM_SYSCALLS_LINUX_X32 : NUM_SYSCALLS_LINUX_X64;

    // Iterate over all syscalls and setup breakpoint on each function instead of do_syscall_64
    // This increase performance, especially with filter file
    char syscall_name[256] = {0};
    for (uint64_t syscall_number = 0; syscall_number < num_syscalls; syscall_number++)
    {
        const syscall_t* syscall_defintion = syscall_table[syscall_number];
        // Setup filter
        if (!this->filter.empty() && (this->filter.find(syscall_defintion->display_name) == this->filter.end()))
            continue;

        // x32 syscall breakpoint
        snprintf(syscall_name, sizeof(syscall_name), "__ia32_sys_%s", syscall_defintion->name);
        if (!this->register_hook(syscall_name, syscall_number, syscall_defintion, false))
            check = false;
        memset(syscall_name, sizeof(char), sizeof(syscall_name));

        // If only 32bit system we don't have x64 symbols so skip
        if (this->is32bit) continue;

        // x64 syscall breakpoint
        snprintf(syscall_name, sizeof(syscall_name), "__x64_sys_%s", syscall_defintion->name);
        if (!this->register_hook(syscall_name, syscall_number, syscall_defintion, true))
            check = false;
        memset(syscall_name, sizeof(char), sizeof(syscall_name));
    }

    return check;
}


linux_syscalls::linux_syscalls(drakvuf_t drakvuf, const syscalls_config* config, output_format_t output) : syscalls_base(drakvuf, config, output)
{
    // Get required pt_regs offsets (GPRs used for syscall argument reading)
    if (!drakvuf_get_kernel_struct_members_array_rva(drakvuf, linux_pt_regs_names_required,
            __PT_REGS_REQUIRED, this->regs.data()))
    {
        fprintf(stderr, "[SYSCALLS] Failed to get required pt_regs offsets, syscalls disabled\n");
        return;
    }

    // Get optional pt_regs offsets (cs/ss may be in anonymous unions on kernel 6.x+)
    if (!drakvuf_get_kernel_struct_members_array_rva(drakvuf, linux_pt_regs_names_optional,
            __PT_REGS_MAX - __PT_REGS_REQUIRED, this->regs.data() + __PT_REGS_REQUIRED))
    {
        fprintf(stderr, "[SYSCALLS] Warning: optional pt_regs offsets unavailable (cs/ss)\n");
    }

    if (!this->setup_origin(drakvuf))
    {
        this->task_mm = 0;
        fprintf(stderr, "[SYSCALLS] Warning: the kernel profile lacks the vDSO or file offsets: syscalls are reported without where they were made from\n");
    }

    if (!this->trap_syscall_table_entries(drakvuf))
    {
        fprintf(stderr, "[SYSCALLS] Failed to set breakpoints on some syscalls\n");
        PRINT_DEBUG("[SYSCALLS] Failed to set breakpoints on some syscalls.\n");
    }
    else
    {
        PRINT_DEBUG("[SYSCALLS] Syscall table breakpoints set\n");
    }
}
