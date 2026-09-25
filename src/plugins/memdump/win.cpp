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

#include "plugins/plugins.h"
#include "plugins/output_format.h"

#include "memdump.h"
#include "win.h"
#include "private.h"

static event_response_t terminate_process_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    uint64_t process_handle = drakvuf_get_function_argument(drakvuf, info, 1);

    if (process_handle != ~0ULL)
    {
        PRINT_DEBUG("[MEMDUMP] Terminate process handle not pointing to self, ignore %lx\n", process_handle);
        return VMI_EVENT_RESPONSE_NONE;
    }

    auto wm = get_trap_plugin<win_memdump>(info);
    dump_from_stack(drakvuf, info, wm->parent);
    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t shellcode_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    uint64_t handle = drakvuf_get_function_argument(drakvuf, info, 1);
    addr_t base_address_ptr = drakvuf_get_function_argument(drakvuf, info, 2);

    addr_t process = 0;
    addr_t dtb     = 0;

    if (!drakvuf_get_process_by_handle(drakvuf, info, handle, &process, &dtb))
    {
        PRINT_DEBUG("[MEMDUMP] Shellcode cb: Failed to get process by handle %lx\n", handle);
        return VMI_EVENT_RESPONSE_NONE;
    }

    auto wm = get_trap_plugin<win_memdump>(info);
    auto plugin = wm->parent;

    auto vmi = vmi_lock_guard(drakvuf);
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = base_address_ptr
    );

    addr_t base_address;
    if (VMI_SUCCESS != vmi_read_addr(vmi, &ctx, &base_address))
    {
        PRINT_DEBUG("[MEMDUMP] Shellcode cb: Failed to read base address in NtFreeVirtualMemory\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    mmvad_info_t mmvad;
    if (!drakvuf_find_mmvad(drakvuf, process, base_address, &mmvad))
    {
        PRINT_DEBUG("[MEMDUMP] Shellcode cb: failed to find MMVAD for memory passed to NtFreeVirtualMemory\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    page_info_t p_info = {};
    if (vmi_pagetable_lookup_extended(vmi, dtb, base_address, &p_info) == VMI_SUCCESS)
    {
        bool pte_valid       = (p_info.x86_ia32e.pte_value & (1UL << 0))  != 0;
        bool page_writeable  = (p_info.x86_ia32e.pte_value & (1UL << 1))  != 0;
        bool page_executable = (p_info.x86_ia32e.pte_value & (1UL << 63)) == 0;
        size_t len_bytes     = (mmvad.ending_vpn - mmvad.starting_vpn + 1) * VMI_PS_4KB;

        if (pte_valid && page_writeable && page_executable && len_bytes >= 0x1000)
        {
            PRINT_DEBUG("[MEMDUMP] Dumping RWX vad\n");
            ctx.addr = mmvad.starting_vpn << 12;
            ctx.dtb  = dtb;
            if (!dump_memory_region(drakvuf, vmi, info, plugin, &ctx, len_bytes, "Possible shellcode detected", nullptr, false))
            {
                PRINT_DEBUG("[MEMDUMP] Failed to store memory dump due to an internal error\n");
            }
        }
    }
    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t free_virtual_memory_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    uint64_t process_handle = drakvuf_get_function_argument(drakvuf, info, 1);
    addr_t mem_base_address_ptr = drakvuf_get_function_argument(drakvuf, info, 2);

    if (process_handle != ~0ULL)
    {
        PRINT_DEBUG("[MEMDUMP] Free process handle not pointing to self, ignore %lx\n", process_handle);
        return VMI_EVENT_RESPONSE_NONE;
    }

    auto wm = get_trap_plugin<win_memdump>(info);
    auto plugin = wm->parent;

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = mem_base_address_ptr
    );

    addr_t mem_base_address;

    if (VMI_SUCCESS != vmi_read_addr(vmi, &ctx, &mem_base_address))
    {
        PRINT_DEBUG("[MEMDUMP] Failed to read base address in NtFreeVirtualMemory\n");
        drakvuf_release_vmi(drakvuf);
        return VMI_EVENT_RESPONSE_NONE;
    }

    mmvad_info_t mmvad;

    if (!drakvuf_find_mmvad(drakvuf, info->attached_proc_data.base_addr, mem_base_address, &mmvad))
    {
        PRINT_DEBUG("[MEMDUMP] Failed to find MMVAD for memory passed to NtFreeVirtualMemory\n");
        drakvuf_release_vmi(drakvuf);
        return VMI_EVENT_RESPONSE_NONE;
    }

    ctx.addr = mem_base_address;
    uint16_t magic;
    char* magic_c = (char*)&magic;

    if (VMI_SUCCESS != vmi_read_16(vmi, &ctx, &magic))
    {
        PRINT_DEBUG("[MEMDUMP] Failed to access memory to be used with NtFreeVirtualMemory %lx\n", ctx.addr);
        drakvuf_release_vmi(drakvuf);
        return VMI_EVENT_RESPONSE_NONE;
    }

    if (magic_c[0] == 'M' && magic_c[1] == 'Z')
    {
        ctx.addr = mmvad.starting_vpn << 12;
        size_t len_bytes = (mmvad.ending_vpn - mmvad.starting_vpn + 1) * VMI_PS_4KB;

        if (!dump_memory_region(drakvuf, vmi, info, plugin, &ctx, len_bytes, "Possible binary detected", nullptr, false))
        {
            PRINT_DEBUG("[MEMDUMP] Failed to store memory dump due to an internal error\n");
        }
    }

    page_info_t p_info = {};

    if (vmi_pagetable_lookup_extended(vmi, info->regs->cr3, mem_base_address, &p_info) == VMI_SUCCESS)
    {
        bool pte_valid = (p_info.x86_ia32e.pte_value & (1UL << 0)) != 0;
        bool page_writeable = (p_info.x86_ia32e.pte_value & (1UL << 1)) != 0;
        bool page_executable = (p_info.x86_ia32e.pte_value & (1UL << 63)) == 0;

        ctx.addr = mmvad.starting_vpn << 12;
        size_t len_bytes = (mmvad.ending_vpn - mmvad.starting_vpn + 1) * VMI_PS_4KB;

        if (len_bytes > 0x1000 && pte_valid && page_writeable && page_executable)
        {
            if (!dump_memory_region(drakvuf, vmi, info, plugin, &ctx, len_bytes, "Interesting RWX memory", nullptr, false))
            {
                PRINT_DEBUG("[MEMDUMP] Failed to store memory dump due to an internal error\n");
            }
        }
    }

    drakvuf_release_vmi(drakvuf);
    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t protect_virtual_memory_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    uint64_t process_handle = drakvuf_get_function_argument(drakvuf, info, 1);
    addr_t mem_base_address_ptr = drakvuf_get_function_argument(drakvuf, info, 2);

    if (process_handle != ~0ULL)
    {
        PRINT_DEBUG("[MEMDUMP] Protect process handle not pointing to self, ignore %lx\n", process_handle);
        return VMI_EVENT_RESPONSE_NONE;
    }

    auto wm = get_trap_plugin<win_memdump>(info);
    auto plugin = wm->parent;

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = mem_base_address_ptr
    );

    addr_t mem_base_address;

    if (VMI_SUCCESS != vmi_read_addr(vmi, &ctx, &mem_base_address))
    {
        PRINT_DEBUG("[MEMDUMP] Failed to read base address in NtProtectVirtualMemory\n");
        drakvuf_release_vmi(drakvuf);
        return VMI_EVENT_RESPONSE_NONE;
    }

    mmvad_info_t mmvad;

    if (!drakvuf_find_mmvad(drakvuf, info->attached_proc_data.base_addr, mem_base_address, &mmvad))
    {
        PRINT_DEBUG("[MEMDUMP] Failed to find MMVAD for memory passed to NtProtectVirtualMemory\n");
        drakvuf_release_vmi(drakvuf);
        return VMI_EVENT_RESPONSE_NONE;
    }

    ctx.addr = mem_base_address;
    uint16_t magic;
    char* magic_c = (char*)&magic;

    if (VMI_SUCCESS != vmi_read_16(vmi, &ctx, &magic))
    {
        PRINT_DEBUG("[MEMDUMP] Failed to access memory to be used with NtProtectVirtualMemory %lx\n", ctx.addr);
        drakvuf_release_vmi(drakvuf);
        return VMI_EVENT_RESPONSE_NONE;
    }

    if (magic_c[0] == 'M' && magic_c[1] == 'Z')
    {
        ctx.addr = mmvad.starting_vpn << 12;
        size_t len_bytes = (mmvad.ending_vpn - mmvad.starting_vpn + 1) * VMI_PS_4KB;

        if (!dump_memory_region(drakvuf, vmi, info, plugin, &ctx, len_bytes, "Possible binary detected", nullptr, false))
        {
            PRINT_DEBUG("[MEMDUMP] Failed to store memory dump due to an internal error\n");
        }
    }

    drakvuf_release_vmi(drakvuf);
    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t write_virtual_memory_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    addr_t process_handle = drakvuf_get_function_argument(drakvuf, info, 1);
    addr_t base_address = drakvuf_get_function_argument(drakvuf, info, 2);
    addr_t buffer_ptr = drakvuf_get_function_argument(drakvuf, info, 3);
    addr_t buffer_size = drakvuf_get_function_argument(drakvuf, info, 4);

    if (process_handle == ~0ULL)
        return VMI_EVENT_RESPONSE_NONE;

    auto wm = get_trap_plugin<win_memdump>(info);
    auto plugin = wm->parent;

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = buffer_ptr
    );

    vmi_pid_t target_pid;
    addr_t process_addr = 0;
    char* target_name = nullptr;

    if ( drakvuf_get_pid_from_handle(drakvuf, info, process_handle, &target_pid) &&
        drakvuf_find_process(drakvuf, target_pid, nullptr, &process_addr) )
    {
        target_name = drakvuf_get_process_name(drakvuf, process_addr, true);
    }

    if (!target_name)
        target_name = g_strdup("<UNKNOWN>");

    extras_t extras =
    {
        .type = WriteVirtualMemoryExtras,
        .write_virtual_memory_extras =
        {
            .target_pid = target_pid,
            .target_name = target_name,
            .base_address = base_address,
        },
    };

    if (!dump_memory_region(drakvuf, vmi, info, plugin, &ctx, buffer_size, "NtWriteVirtualMemory called", &extras, true))
    {
        PRINT_DEBUG("[MEMDUMP] Failed to store memory dump due to an internal error\n");
    }

    g_free(target_name);
    drakvuf_release_vmi(drakvuf);
    return VMI_EVENT_RESPONSE_NONE;
}

static bool dump_if_points_to_executable_memory(
    drakvuf_t drakvuf,
    drakvuf_trap_info* info,
    vmi_instance_t vmi,
    addr_t process_base,
    addr_t target_addr,
    const char* reason,
    extras_t* extras)
{
    auto wm = get_trap_plugin<win_memdump>(info);
    memdump* plugin = wm->parent;

    addr_t dtb;
    if (!drakvuf_get_process_dtb(drakvuf, process_base, &dtb))
    {
        PRINT_DEBUG("[MEMDUMP] Failed to retrieve process dtb\n");
        return false;
    }

    page_info_t p_info = {};
    if (VMI_SUCCESS != vmi_pagetable_lookup_extended(vmi, dtb, target_addr, &p_info))
    {
        PRINT_DEBUG("[MEMDUMP] Failed to retrieve page protection flags\n");
        return false;
    }

    bool page_valid = (p_info.x86_ia32e.pte_value & (1UL << 0)) != 0;
    bool page_execute = (p_info.x86_ia32e.pte_value & (1UL << 63)) == 0;
    if (!page_valid || !page_execute)
    {
        return false;
    }

    mmvad_info_t mmvad;
    if (!drakvuf_find_mmvad(drakvuf, process_base, target_addr, &mmvad))
    {
        PRINT_DEBUG("[MEMDUMP] Failed to find mmvad\n");
        return false;
    }

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = dtb,
        .addr = mmvad.starting_vpn * VMI_PS_4KB
    );
    size_t dump_size = (mmvad.ending_vpn - mmvad.starting_vpn + 1) * VMI_PS_4KB;
    if (!dump_memory_region(drakvuf, vmi, info, plugin, &ctx, dump_size, reason, extras, extras != nullptr))
    {
        PRINT_DEBUG("[MEMDUMP] Failed to dump memory\n");
        return false;
    }
    return true;
}

static event_response_t create_remote_thread_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    addr_t target_process_handle = drakvuf_get_function_argument(drakvuf, info, 4);
    vmi_pid_t target_process_pid;
    if (!drakvuf_get_pid_from_handle(drakvuf, info, target_process_handle, &target_process_pid))
    {
        PRINT_DEBUG("[MEMDUMP] Failed to retrieve target process pid for handle %lx\n", target_process_handle);
        return VMI_EVENT_RESPONSE_NONE;
    }

    if (target_process_pid == info->proc_data.pid)
    {
        return VMI_EVENT_RESPONSE_NONE;
    }

    addr_t target_process;
    if (!drakvuf_find_process(drakvuf, target_process_pid, nullptr, &target_process))
    {
        PRINT_DEBUG("[MEMDUMP] Failed to retrieve target_process\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    addr_t start_routine = drakvuf_get_function_argument(drakvuf, info, 5);
    auto vmi = vmi_lock_guard(drakvuf);
    dump_if_points_to_executable_memory(drakvuf, info, vmi, target_process, start_routine, "CreateRemoteThread heuristic", nullptr);

    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t set_information_thread_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto wm = get_trap_plugin<win_memdump>(info);

    addr_t thread_information_class = drakvuf_get_function_argument(drakvuf, info, 2);
    if (thread_information_class != ThreadWow64Context)
    {
        return VMI_EVENT_RESPONSE_NONE;
    }

    addr_t resumed_thread_handle = drakvuf_get_function_argument(drakvuf, info, 1);
    addr_t caller_eprocess = drakvuf_get_current_process(drakvuf, info);
    addr_t resumed_ethread;
    if (!drakvuf_obj_ref_by_handle(drakvuf, info, caller_eprocess, resumed_thread_handle, OBJ_MANAGER_THREAD_OBJECT, &resumed_ethread))
    {
        PRINT_DEBUG("[MEMDUMP] Failed to retrieve resumed_ethread\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    addr_t resumed_eprocess;
    auto vmi = vmi_lock_guard(drakvuf);
    if (VMI_SUCCESS != vmi_read_addr_va(vmi, resumed_ethread + wm->kthread_process_rva, 0, &resumed_eprocess))
    {
        PRINT_DEBUG("[MEMDUMP] Failed to retrieve resumed process\n");
        return VMI_EVENT_RESPONSE_NONE;
    }
    vmi_pid_t resumed_process_pid;
    if (!drakvuf_get_process_pid(drakvuf, resumed_eprocess, &resumed_process_pid))
    {
        PRINT_DEBUG("[MEMDUMP] Failed to retrieve resumed process pid\n");
        return VMI_EVENT_RESPONSE_NONE;
    }
    if (resumed_process_pid == info->proc_data.pid)
    {
        return VMI_EVENT_RESPONSE_NONE;
    }

    addr_t wow64_context = drakvuf_get_function_argument(drakvuf, info, 3);
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = wow64_context + wm->wow64context_eax_rva
    );
    uint32_t wow_eax = 0;
    if (VMI_SUCCESS != vmi_read_32(vmi, &ctx, &wow_eax))
    {
        PRINT_DEBUG("[MEMDUMP] Failed to read eax field from wow64_context\n");
        return VMI_EVENT_RESPONSE_NONE;
    }
    uint32_t wow_eip = 0;
    ctx.addr = wow64_context + wm->wow64context_eip_rva;
    if (VMI_SUCCESS != vmi_read_32(vmi, &ctx, &wow_eip))
    {
        PRINT_DEBUG("[MEMDUMP] Failed to read eip field from wow64_context\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    dump_if_points_to_executable_memory(drakvuf, info, vmi, resumed_eprocess, wow_eax, "SetThreadContext heuristic", nullptr);
    dump_if_points_to_executable_memory(drakvuf, info, vmi, resumed_eprocess, wow_eip, "SetThreadContext heuristic", nullptr);

    return VMI_EVENT_RESPONSE_NONE;
}

win_memdump::win_memdump(drakvuf_t drakvuf, const memdump_config* c, output_format_t output, memdump* parent_)
    : pluginex(drakvuf, output)
    , parent(parent_)
    , dll_base_rva(0)
    , dll_base_wow_rva(0)
    , kthread_process_rva(0)
    , wow64context_eip_rva(0)
    , wow64context_eax_rva(0)
{
    if (!drakvuf_get_kernel_struct_member_rva(drakvuf, "_LDR_DATA_TABLE_ENTRY", "DllBase", &this->dll_base_rva) ||
        !drakvuf_get_kernel_struct_member_rva(drakvuf, "_KTHREAD", "Process", &this->kthread_process_rva))
    {
        throw -1;
    }

    json_object* json_wow = drakvuf_get_json_wow(drakvuf);
    bool const is64bit = (drakvuf_get_page_mode(drakvuf) == VMI_PM_IA32E);

    if (is64bit)
    {
        if (json_wow)
        {
            if (!json_get_struct_member_rva(drakvuf, json_wow, "_LDR_DATA_TABLE_ENTRY", "DllBase", &this->dll_base_wow_rva) ||
                !json_get_struct_member_rva(drakvuf, json_wow, "_CONTEXT", "Eip", &this->wow64context_eip_rva) ||
                !json_get_struct_member_rva(drakvuf, json_wow, "_CONTEXT", "Eax", &this->wow64context_eax_rva))
            {
                throw -1;
            }
        }
        else
        {
            PRINT_DEBUG("Memdump works better when there is a JSON profile for WoW64 NTDLL (-w)\n");
        }
    }

    parent->setup_usermode_dotnet_hooks(c);

    breakpoint_in_system_process_searcher bp;
    if (!c->memdump_disable_free_vm)
        if (!register_trap(nullptr, free_virtual_memory_hook_cb, bp.for_syscall_name("NtFreeVirtualMemory")))
            throw -1;
    if (!c->memdump_disable_protect_vm)
        if (!register_trap(nullptr, protect_virtual_memory_hook_cb, bp.for_syscall_name("NtProtectVirtualMemory")))
            throw -1;
    if (!c->memdump_disable_terminate_proc)
        if (!register_trap(nullptr, terminate_process_hook_cb, bp.for_syscall_name("NtTerminateProcess")))
            throw -1;
    if (!c->memdump_disable_write_vm)
        if (!register_trap(nullptr, write_virtual_memory_hook_cb, bp.for_syscall_name("NtWriteVirtualMemory")))
            throw -1;
    if (!c->memdump_disable_create_thread)
        if (!register_trap(nullptr, create_remote_thread_hook_cb, bp.for_syscall_name("NtCreateThreadEx")))
            throw -1;
    if (!c->memdump_disable_set_thread && is64bit && json_wow)
        if (!register_trap(nullptr, set_information_thread_hook_cb, bp.for_syscall_name("NtSetInformationThread")))
            throw -1;
    if (!c->memdump_disable_shellcode_detect)
        if (!register_trap(nullptr, shellcode_cb, bp.for_syscall_name("NtFreeVirtualMemory")))
            throw -1;

    parent->userhook_init(c, output);
}
