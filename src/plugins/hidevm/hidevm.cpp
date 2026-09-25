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

#include <config.h>
#include <glib.h>
#include <inttypes.h>
#include <algorithm>
#include <string>
#include <libvmi/libvmi.h>
#include <assert.h>
#include <libdrakvuf/json-util.h>
#include <libdrakvuf/libdrakvuf.h>

#include "plugins/output_format.h"
#include "hidevm.h"
#include "private.h"

event_response_t hidevm::NtClose_cb(drakvuf_t, drakvuf_trap_info_t* info)
{
    auto vmi = vmi_lock_guard(drakvuf);
    auto params = libhook::GetTrapParams(info);

    auto hook_ID = make_hook_id(info, params->target_rsp);

    // We need to set our fake handle value with 0 to avoid invalid handle exception
    if (this->NtClose_hook.count(hook_ID))
    {
        uint64_t Handle = drakvuf_get_function_argument(drakvuf, info, 1);
        if (Handle == this->FakeWmiGuidHandle)
        {
            if (VMI_FAILURE == vmi_set_vcpureg(vmi, 0, RCX, info->vcpu))
            {
                PRINT_DEBUG("[HIDEVM] Breakpoint on NtClose: Failed to set RCX to 0\n");
            }
            this->stage = 0;
            this->query_stage = 0;
            this->NtClose_hook.erase(hook_ID);
        }
    }

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t hidevm::ReturnNtDeviceIoControlFile_cb(drakvuf_t, drakvuf_trap_info_t* info)
{
    auto vmi = vmi_lock_guard(drakvuf);
    auto params = libhook::GetTrapParams(info);

    auto hook_ID = make_hook_id(info, params->target_rsp);

    // Verify that hook for this thread was created
    if (this->ret_hooks.count(hook_ID))
    {
        if (params->verifyResultCallParams(drakvuf, info))
        {
            if (this->stage == STAGE_WMI_OPEN_BLOCK)
            {
                if (info->regs->rax == STATUS_WMI_GUID_NOT_FOUND)
                {
                    ACCESS_CONTEXT(ctx,
                        .translate_mechanism = VMI_TM_PROCESS_DTB,
                        .dtb = info->regs->cr3,
                        .addr = this->addr_WmiKmRequestOpenBlock_Handle
                    );
                    // Set fake handle value of WmiGuid
                    if (VMI_SUCCESS == vmi_write_64(vmi, &ctx, &this->FakeWmiGuidHandle))
                    {
                        if (VMI_SUCCESS == vmi_set_vcpureg(vmi, STATUS_SUCCESS, RAX, info->vcpu))
                        {
                            this->stage = STAGE_WMI_QUERY_GUID_INFORMATION;
                        }
                        else
                        {
                            this->stage = 0;
                            PRINT_DEBUG("[HIDEVM] Breakpoint on return NtDeviceIoControlFile(IOCTL_WMI_OPEN_GUID_BLOCK): Failed to set RAX to STATUS_SUCCESS\n");
                        }
                    }
                    else
                    {
                        this->stage = 0;
                        PRINT_DEBUG("[HIDEVM] Breakpoint on return NtDeviceIoControlFile(IOCTL_WMI_OPEN_GUID_BLOCK) Failed to write fake WmiGuid Handle\n");
                    }
                }
                this->ret_hooks.erase(hook_ID);
            }
            else if (this->stage == STAGE_WMI_QUERY_GUID_INFORMATION)
            {
                ACCESS_CONTEXT(ctx,
                    .translate_mechanism = VMI_TM_PROCESS_DTB,
                    .dtb = info->regs->cr3,
                    .addr = this->addr_InputBuffer_Status
                );

                uint64_t InputBuffer_Status = 0;
                if (VMI_SUCCESS == vmi_write_64(vmi, &ctx, &InputBuffer_Status))
                {
                    ctx.addr = this->addr_IoStatusBlock_Information;
                    uint64_t IoStatusBlock_Information = 0x10;
                    // IoStatusBlock.Information on return from NtDeviceIoControlFile with IOCTL_WMI_QUERY_GUID_INFORMATION should contain 0x10
                    if (VMI_SUCCESS == vmi_write_64(vmi, &ctx, &IoStatusBlock_Information))
                    {
                        if (VMI_SUCCESS == vmi_set_vcpureg(vmi, STATUS_SUCCESS, RAX, info->vcpu))
                        {
                            this->stage = STAGE_WMI_QUERY_ALL_DATA;
                        }
                        else
                        {
                            this->stage = 0;
                            PRINT_DEBUG("[HIDEVM] Breakpoint on return NtDeviceIoControlFile(IOCTL_WMI_QUERY_GUID_INFORMATION): Failed to set RAX to STATUS_SUCCESS\n");
                        }
                    }
                    else
                    {
                        this->stage = 0;
                        PRINT_DEBUG("[HIDEVM] Breakpoint on return NtDeviceIoControlFile(IOCTL_WMI_QUERY_GUID_INFORMATION): Failed to write InputBuffer.Status\n");
                    }
                }
                else
                {
                    this->stage = 0;
                    PRINT_DEBUG("[HIDEVM] Breakpoint on return NtDeviceIoControlFile(IOCTL_WMI_QUERY_GUID_INFORMATION): Failed to write InputBuffer.Status\n");
                }
                this->addr_InputBuffer_Status = 0;
                this->addr_IoStatusBlock_Information = 0;
                this->ret_hooks.erase(hook_ID);
            }
            else if (this->stage == STAGE_WMI_QUERY_ALL_DATA)
            {
                uint32_t out_WmiKmQueryData_Length = 0;
                uint32_t out_WmiKmQueryData_Flags = 0;
                uint32_t out_WmiKmQueryData_DataLen = 0;
                uint64_t out_IoStatusBlock_Information = 0;

                if (this->query_stage == 1)
                {
                    ACCESS_CONTEXT(ctx,
                        .translate_mechanism = VMI_TM_PROCESS_DTB,
                        .dtb = info->regs->cr3,
                        .addr = this->addr_InputBuffer + WmiKmQueryData_Length
                    );
                    // Prepare data on first return from NtDeviceIoControlFile with IOCTL_WMI_QUERY_ALL_DATA
                    out_WmiKmQueryData_Length = 0x38;
                    if (VMI_SUCCESS == vmi_write_32(vmi, &ctx, &out_WmiKmQueryData_Length))
                    {
                        ctx.addr = this->addr_InputBuffer + WmiKmQueryData_Guid;
                        if (VMI_SUCCESS == vmi_write(vmi, &ctx, sizeof(binThermalZoneGuid), (void*)binThermalZoneGuid, nullptr))
                        {
                            ctx.addr = this->addr_InputBuffer + WmiKmQueryData_Flags;
                            out_WmiKmQueryData_Flags = 0x20;
                            if (VMI_SUCCESS == vmi_write_32(vmi, &ctx, &out_WmiKmQueryData_Flags))
                            {
                                ctx.addr = this->addr_InputBuffer + WmiKmQueryData_DataLen;
                                out_WmiKmQueryData_DataLen = sizeof(WMI_data);
                                if (VMI_SUCCESS == vmi_write_32(vmi, &ctx, &out_WmiKmQueryData_DataLen))
                                {
                                    ctx.addr = this->addr_IoStatusBlock_Information;
                                    out_IoStatusBlock_Information = 0x38;
                                    if (VMI_SUCCESS == vmi_write_64(vmi, &ctx, &out_IoStatusBlock_Information))
                                    {
                                        if (VMI_SUCCESS == vmi_set_vcpureg(vmi, STATUS_SUCCESS, RAX, info->vcpu))
                                        {
                                            this->addr_InputBuffer = 0;
                                            this->addr_IoStatusBlock_Information = 0;
                                            this->query_stage = 2;
                                        }
                                        else
                                        {
                                            this->stage = 0;
                                            PRINT_DEBUG("[HIDEVM] Breakpoint on return NtDeviceIoControlFile(IOCTL_WMI_QUERY_ALL_DATA) Step 1: Failed to set RAX to STATUS_SUCCESS\n");
                                        }
                                    }
                                    else
                                    {
                                        this->stage = 0;
                                        PRINT_DEBUG("[HIDEVM] Breakpoint on return NtDeviceIoControlFile(IOCTL_WMI_QUERY_ALL_DATA) Step 1: Failed to write IoStatusBlock.Information (Bytes returned)\n");
                                    }
                                }
                                else
                                {
                                    this->stage = 0;
                                    PRINT_DEBUG("[HIDEVM] Breakpoint on return NtDeviceIoControlFile(IOCTL_WMI_QUERY_ALL_DATA) Step 1: Failed to write InputBuffer.DataLen\n");
                                }
                            }
                            else
                            {
                                this->stage = 0;
                                PRINT_DEBUG("[HIDEVM] Breakpoint on return NtDeviceIoControlFile(IOCTL_WMI_QUERY_ALL_DATA) Step 1: Failed to write InputBuffer.Flags\n");
                            }
                        }
                        else
                        {
                            this->stage = 0;
                            PRINT_DEBUG("[HIDEVM] Breakpoint on return NtDeviceIoControlFile(IOCTL_WMI_QUERY_ALL_DATA) Step 1: Failed to write InputBuffer.Guid\n");
                        }
                    }
                    else
                    {
                        this->stage = 0;
                        PRINT_DEBUG("[HIDEVM] Breakpoint on return NtDeviceIoControlFile(IOCTL_WMI_QUERY_ALL_DATA) Step 1: Failed to write InputBuffer.Length\n");
                    }
                }
                else if (this->query_stage == 2)
                {
                    ACCESS_CONTEXT(ctx,
                        .translate_mechanism = VMI_TM_PROCESS_DTB,
                        .dtb = info->regs->cr3,
                        .addr = this->addr_InputBuffer
                    );

                    // Set fake data to OutputBuffer, that should be returned
                    if (VMI_SUCCESS == vmi_write(vmi, &ctx, sizeof(WMI_data), (void*)WMI_data, nullptr))
                    {
                        out_IoStatusBlock_Information = sizeof(WMI_data);
                        ctx.addr = this->addr_IoStatusBlock_Information;
                        if (VMI_SUCCESS == vmi_write_64(vmi, &ctx, &out_IoStatusBlock_Information))
                        {
                            if (VMI_SUCCESS == vmi_set_vcpureg(vmi, STATUS_SUCCESS, RAX, info->vcpu))
                            {
                                this->addr_InputBuffer_Status = 0;
                                this->addr_IoStatusBlock_Information = 0;
                                this->NtClose_hook[hook_ID] = this->createSyscallHook("NtClose", &hidevm::NtClose_cb);
                                fmt::print(this->format, "hidevm", drakvuf, info,
                                    keyval("Reason", fmt::Qstr("MSAcpi_ThermalZoneTemperature query spoofed"))
                                );
                            }
                            else
                            {
                                this->stage = 0;
                                PRINT_DEBUG("[HIDEVM] Breakpoint on return NtDeviceIoControlFile(IOCTL_WMI_QUERY_ALL_DATA) Step 2: Failed to write InputBuffer.Status\n");
                            }
                        }
                        else
                        {
                            this->stage = 0;
                            PRINT_DEBUG("[HIDEVM] Breakpoint on return NtDeviceIoControlFile(IOCTL_WMI_QUERY_ALL_DATA) Step 2: Failed to write IoStatusBlock.Information\n");
                        }
                    }
                    else
                    {
                        this->stage = 0;
                        PRINT_DEBUG("[HIDEVM] Breakpoint on return NtDeviceIoControlFile(IOCTL_WMI_QUERY_ALL_DATA) Step 2: Failed to write WMI data buffer\n");
                    }
                }
                this->ret_hooks.erase(hook_ID);
            }
        }
    }

    return VMI_EVENT_RESPONSE_NONE;
}

static bool check_process_is_wmiprvse(drakvuf_trap_info_t* info)
{
    const char* wmiprvse_proc = "windows\\system32\\wbem\\wmiprvse.exe";
    std::string attached_process(info->attached_proc_data.name);
    std::transform(attached_process.begin(), attached_process.end(), attached_process.begin(), [](unsigned char c)
    {
        return std::tolower(c);
    });

    return (attached_process.find(wmiprvse_proc) != std::string::npos);
}

event_response_t hidevm::NtDeviceIoControlFile_cb(drakvuf_t, drakvuf_trap_info_t* info)
{
    auto vmi = vmi_lock_guard(drakvuf);

    uint64_t IoControlCode = drakvuf_get_function_argument(drakvuf, info, 6) & 0xFFFFFFFF;
    // Hook ID is needed to validate, that syscall return hook is in the same context as our hook chain
    auto params = libhook::GetTrapParams(info);
    auto hook_ID = make_hook_id(info, params->target_rsp);

    // First NtDeviceIoControlFile call with IoControlCode IOCTL_WMI_OPEN_GUID_BLOCK should return WmiGuid handle
    if (IoControlCode == IOCTL_WMI_OPEN_GUID_BLOCK)
    {
        if (check_process_is_wmiprvse(info))
        {
            if (this->stage != 0)
                return VMI_EVENT_RESPONSE_NONE;
            addr_t InputBuffer = 0;
            InputBuffer = drakvuf_get_function_argument(drakvuf, info, 7); // InputBuffer -> *WMI_KM_REQUEST_OPEN_BLOCK
            if (!InputBuffer)
            {
                PRINT_DEBUG("[HIDEVM] Breakpoint in WmiPrvSE.exe NtDeviceIoControlFile(IOCTL_WMI_OPEN_GUID_BLOCK): Failed to read InputBuffer argument\n");
                return VMI_EVENT_RESPONSE_NONE;
            }

            addr_t InputBuffer_GuidObjectAttributes = 0; // WMI_KM_REQUEST_OPEN_BLOCK.GuidObjectAttributes
            uint64_t GuidObjectAttributes_Length = 0;
            addr_t GuidObjectAttributes_ObjectName = 0;
            unicode_string_t* guid_object_name = nullptr;
            unicode_string_t guid_object_name_utf8;

            ACCESS_CONTEXT(ctx,
                .translate_mechanism = VMI_TM_PROCESS_DTB,
                .dtb = info->regs->cr3,
                .addr = InputBuffer + WmiKmRequestOpenBlock_ObjectAttributes
            );
            // We need to check that (*WMI_KM_REQUEST_OPEN_BLOCK)InputBuffer->GuidObjectAttributes->ObjectName contains thermal zone GUID
            if (VMI_FAILURE == vmi_read_64(vmi, &ctx, &InputBuffer_GuidObjectAttributes))
            {
                PRINT_DEBUG("[HIDEVM] Breakpoint in WmiPrvSE.exe NtDeviceIoControlFile(IOCTL_WMI_OPEN_GUID_BLOCK): Failed to read GuidObjectAttributes address\n");
                return VMI_EVENT_RESPONSE_NONE;
            }

            ctx.addr = InputBuffer_GuidObjectAttributes + this->objattr_length;
            if (VMI_FAILURE == vmi_read_64(vmi, &ctx, &GuidObjectAttributes_Length))
            {
                PRINT_DEBUG("[HIDEVM] Breakpoint in WmiPrvSE.exe NtDeviceIoControlFile(IOCTL_WMI_OPEN_GUID_BLOCK): Failed to read GuidObjectAttributes.Length\n");
                return VMI_EVENT_RESPONSE_NONE;
            }
            if (GuidObjectAttributes_Length != 0x30)
            {
                PRINT_DEBUG("[HIDEVM] Breakpoint in WmiPrvSE.exe NtDeviceIoControlFile(IOCTL_WMI_OPEN_GUID_BLOCK): Invalid GuidObjectAttributes Length\n");
                return VMI_EVENT_RESPONSE_NONE;
            }

            ctx.addr = InputBuffer_GuidObjectAttributes + this->objattr_name;
            if (VMI_FAILURE == vmi_read_64(vmi, &ctx, &GuidObjectAttributes_ObjectName))
            {
                PRINT_DEBUG("[HIDEVM] Breakpoint in WmiPrvSE.exe NtDeviceIoControlFile(IOCTL_WMI_OPEN_GUID_BLOCK): Failed to read GuidObjectAttributes.ObjectName\n");
                return VMI_EVENT_RESPONSE_NONE;
            }

            if (!GuidObjectAttributes_ObjectName)
            {
                PRINT_DEBUG("[HIDEVM] Breakpoint in WmiPrvSE.exe NtDeviceIoControlFile(IOCTL_WMI_OPEN_GUID_BLOCK): Invalid GuidObjectAttributes.ObjectName\n");
                return VMI_EVENT_RESPONSE_NONE;
            }

            ctx.addr = GuidObjectAttributes_ObjectName;
            guid_object_name = vmi_read_unicode_str(vmi, &ctx);
            if (guid_object_name)
            {
                memset(&guid_object_name_utf8, 0, sizeof(guid_object_name_utf8));
                if (VMI_FAILURE == vmi_convert_str_encoding(guid_object_name, &guid_object_name_utf8, "UTF-8"))
                {
                    PRINT_DEBUG("[HIDEVM] Breakpoint in WmiPrvSE.exe NtDeviceIoControlFile(IOCTL_WMI_OPEN_GUID_BLOCK): Failed to convert Guid ObjectName to UTF-8\n");
                    vmi_free_unicode_str(guid_object_name);
                    return VMI_EVENT_RESPONSE_NONE;
                }
                if (!strcmp((const char*)guid_object_name_utf8.contents, "\\WmiGuid\\A1BC18C0-A7C8-11D1-BF3C-00A0C9062910"))
                {
                    PRINT_DEBUG("[HIDEVM] Breakpoint in WmiPrvSE.exe NtDeviceIoControlFile(IOCTL_WMI_OPEN_GUID_BLOCK): GUID ObjectName: %s\n", guid_object_name_utf8.contents);
                    // We need to save address of Handle field, to write fake handle in syscall return hook
                    this->addr_WmiKmRequestOpenBlock_Handle = InputBuffer + WmiKmRequestOpenBlock_Handle;
                    // After validating GUID value we set 1st stage hook
                    this->stage = STAGE_WMI_OPEN_BLOCK;
                    auto hook = this->createReturnHook(info, &hidevm::ReturnNtDeviceIoControlFile_cb);
                    // Save original PID and TID to validate that next steps are in the same chain
                    this->prev_hook_ID = hook_ID;
                    this->ret_hooks[hook_ID] = std::move(hook);
                }
                vmi_free_unicode_str(guid_object_name);
                free(guid_object_name_utf8.contents);
            }
        }
    }
    // Second stage of getting data is checking the status of WmiGuid
    else if (IoControlCode == IOCTL_WMI_QUERY_GUID_INFORMATION && hook_ID == this->prev_hook_ID)
    {
        if (check_process_is_wmiprvse(info))
        {
            if (this->stage == STAGE_WMI_QUERY_GUID_INFORMATION)
            {
                addr_t InputBuffer = 0;
                addr_t IoStatusBlock = 0;
                addr_t InputBuffer_Handle = 0;

                InputBuffer = drakvuf_get_function_argument(drakvuf, info, 7); // InputBuffer -> WMI_KM_REQUEST_GUID_INFO*
                IoStatusBlock = drakvuf_get_function_argument(drakvuf, info, 5);

                if (!InputBuffer)
                {
                    PRINT_DEBUG("[HIDEVM] Breakpoint in WmiPrvSE.exe NtDeviceIoControlFile(IOCTL_WMI_QUERY_GUID_INFORMATION): Failed to read InputBuffer\n");
                    this->stage = 0;
                    return VMI_EVENT_RESPONSE_NONE;
                }
                if (!IoStatusBlock)
                {
                    PRINT_DEBUG("[HIDEVM] Breakpoint in WmiPrvSE.exe NtDeviceIoControlFile(IOCTL_WMI_QUERY_GUID_INFORMATION): Failed to read IoStatusBlock\n");
                    this->stage = 0;
                    return VMI_EVENT_RESPONSE_NONE;
                }

                ACCESS_CONTEXT(ctx,
                    .translate_mechanism = VMI_TM_PROCESS_DTB,
                    .dtb = info->regs->cr3,
                    .addr = InputBuffer + WmiKmRequestQueryGuidInfo_Handle
                );
                if (VMI_FAILURE == vmi_read_64(vmi, &ctx, &InputBuffer_Handle))
                {
                    PRINT_DEBUG("[HIDEVM] Breakpoint in WmiPrvSE.exe NtDeviceIoControlFile(IOCTL_WMI_QUERY_GUID_INFORMATION): Failed to read InputBuffer.Handle\n");
                    this->stage = 0;
                    return VMI_EVENT_RESPONSE_NONE;
                }

                if (InputBuffer_Handle == this->FakeWmiGuidHandle)
                {
                    // Addresses of InputBuffer.Status and IoStatusBlock.Information are saved to spoof values in return hook
                    this->addr_InputBuffer_Status = InputBuffer + WmiKmRequestQueryGuidInfo_Status;
                    this->addr_IoStatusBlock_Information = IoStatusBlock + this->iostatusblock_information;

                    auto hook = this->createReturnHook(info, &hidevm::ReturnNtDeviceIoControlFile_cb);
                    this->ret_hooks[hook_ID] = std::move(hook);
                }
            }
        }
    }
    // Third stage of getting data consists of 2 steps: 1) Get data size 2) Get data
    else if (IoControlCode == IOCTL_WMI_QUERY_ALL_DATA && hook_ID == this->prev_hook_ID)
    {
        if (check_process_is_wmiprvse(info))
        {
            if (this->stage == STAGE_WMI_QUERY_ALL_DATA)
            {
                addr_t InputBuffer = 0;
                addr_t IoStatusBlock = 0;
                addr_t InputBuffer_Handle = 0;

                InputBuffer = drakvuf_get_function_argument(drakvuf, info, 7); // InputBuffer -> WMI_KM_QUERY_DATA*
                IoStatusBlock = drakvuf_get_function_argument(drakvuf, info, 5);
                if (!InputBuffer)
                {
                    PRINT_DEBUG("[HIDEVM] Breakpoint in WmiPrvSE.exe NtDeviceIoControlFile(IOCTL_WMI_QUERY_ALL_DATA): Failed to read InputBuffer\n");
                    this->stage = 0;
                    return VMI_EVENT_RESPONSE_NONE;
                }
                if (!IoStatusBlock)
                {
                    PRINT_DEBUG("[HIDEVM] Breakpoint in WmiPrvSE.exe NtDeviceIoControlFile(IOCTL_WMI_QUERY_ALL_DATA): Failed to read IoStatusBlock\n");
                    this->stage = 0;
                    return VMI_EVENT_RESPONSE_NONE;
                }

                ACCESS_CONTEXT(ctx,
                    .translate_mechanism = VMI_TM_PROCESS_DTB,
                    .dtb = info->regs->cr3,
                    .addr = InputBuffer + WmiKmQueryData_Handle
                );
                if (VMI_FAILURE == vmi_read_64(vmi, &ctx, &InputBuffer_Handle))
                {
                    PRINT_DEBUG("[HIDEVM] Breakpoint in WmiPrvSE.exe NtDeviceIoControlFile(IOCTL_WMI_QUERY_ALL_DATA): Failed to read InputBuffer.Handle\n");
                    this->stage = 0;
                    return VMI_EVENT_RESPONSE_NONE;
                }
                if (InputBuffer_Handle == this->FakeWmiGuidHandle)
                {
                    this->addr_IoStatusBlock_Information = IoStatusBlock + this->iostatusblock_information;
                    this->addr_InputBuffer = InputBuffer;

                    // If this is a first call with IOCTL_WMI_QUERY_ALL_DATA we set the first stage
                    if (!this->query_stage)
                        this->query_stage = 1;
                    auto hook = this->createReturnHook(info, &hidevm::ReturnNtDeviceIoControlFile_cb);
                    this->ret_hooks[hook_ID] = std::move(hook);
                }
            }
        }
    }

    return VMI_EVENT_RESPONSE_NONE;
}

static auto IWbemServices__ExecQuery_args()
{
    std::vector<std::unique_ptr<ArgumentPrinter>> args;
    args.emplace_back(std::make_unique<ArgumentPrinter>("This"));
    args.emplace_back(std::make_unique<ArgumentPrinter>("strQueryLanguage"));
    args.emplace_back(std::make_unique<ArgumentPrinter>("strQuery"));
    args.emplace_back(std::make_unique<ArgumentPrinter>("lFlags"));
    args.emplace_back(std::make_unique<ArgumentPrinter>("pCtx"));
    args.emplace_back(std::make_unique<ArgumentPrinter>("ppEnum"));

    return args;
}

static std::size_t check_object_name(std::string& query)
{
    const char* object_prefix1 = "win32_perfformatteddata";
    const char* object_prefix2 = "win32_perfrawdata";

    std::size_t sel_pos  = query.find("select");
    std::size_t from_pos = query.find("from");
    std::size_t obj_pos1 = query.find(object_prefix1);
    std::size_t obj_pos2 = query.find(object_prefix2);

    if (sel_pos != std::string::npos && from_pos != std::string::npos)
    {
        if (obj_pos1 != std::string::npos)
            return obj_pos1;
        if (obj_pos2 != std::string::npos)
            return obj_pos2;
    }

    return std::string::npos;
}

static bool replace_object_name(vmi_instance_t vmi, uint64_t cr3, addr_t addr_strQuery, std::size_t object_name_pos)
{
    unicode_string_t replacement_utf8;
    unicode_string_t replacement_utf16;
    bool result = false;

    replacement_utf8.contents = reinterpret_cast<uint8_t*>(strdup("Win32_BIOS"));

    if (replacement_utf8.contents)
    {
        replacement_utf8.encoding = "UTF-8";
        replacement_utf8.length = strlen(reinterpret_cast<char*>(replacement_utf8.contents)) + 1;

        if (VMI_SUCCESS == vmi_convert_str_encoding(&replacement_utf8, &replacement_utf16, "UTF-16LE"))
        {
            ACCESS_CONTEXT(ctx,
                .translate_mechanism = VMI_TM_PROCESS_DTB,
                .dtb = cr3,
                .addr = addr_strQuery + object_name_pos * 2
            );
            if (VMI_SUCCESS == vmi_write(vmi, &ctx, replacement_utf16.length, replacement_utf16.contents, nullptr))
            {
                result = true;
            }
            else
            {
                PRINT_DEBUG("[HIDEVM] IWbemServices::ExecQuery: failed to replace strQuery\n");
            }
            free(replacement_utf16.contents);
        }
        else
        {
            PRINT_DEBUG("[HIDEVM] IWbemServices::ExecQuery: failed to replace strQuery\n");
        }
        free(replacement_utf8.contents);
    }
    else
    {
        PRINT_DEBUG("[HIDEVM] IWbemServices::ExecQuery: failed to allocate memory for strQuery\n");
    }

    return result;
}

static void check_and_replace_query_string(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t addr_strQuery)
{
    hook_target_entry_t* target = (hook_target_entry_t*)info->trap->data;
    auto plugin = (hidevm*)target->plugin;
    auto vmi = vmi_lock_guard(drakvuf);

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = addr_strQuery
    );
    unicode_string_t* strQuery = drakvuf_read_wchar_string(drakvuf, &ctx);

    if (strQuery)
    {
        std::string query(reinterpret_cast<char*>(strQuery->contents), strQuery->length);
        std::transform(query.begin(), query.end(), query.begin(), [](unsigned char c)
        {
            return std::tolower(c);
        });

        std::size_t object_name_pos = check_object_name(query);

        if (object_name_pos != std::string::npos)
        {
            PRINT_DEBUG("[HIDEVM] IWbemServices::ExecQuery: WQL Query string: %s\n", strQuery->contents);
            if (replace_object_name(vmi, info->regs->cr3, addr_strQuery, object_name_pos))
            {
                fmt::print(plugin->format, "hidevm", drakvuf, info,
                    keyval("Reason", fmt::Qstr("WMI query spoofed")),
                    keyval("strQuery", fmt::Qstr(query.c_str()))
                );
            }
        }
        vmi_free_unicode_str(strQuery);
    }
    else
        PRINT_DEBUG("[HIDEVM] IWbemServices::ExecQuery: Failed to read strQuery parameter\n");
}

static event_response_t ExecQuery_handler(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    hook_target_entry_t* target = (hook_target_entry_t*)info->trap->data;
    if (target->pid != info->attached_proc_data.pid)
        return VMI_EVENT_RESPONSE_NONE;

    addr_t addr_strQuery = drakvuf_get_function_argument(drakvuf, info, 3);
    if (addr_strQuery)
        check_and_replace_query_string(drakvuf, info, addr_strQuery);
    else
        PRINT_DEBUG("[HIDEVM] IWbemServices::ExecQuery: strQuery is NULL\n");

    return VMI_EVENT_RESPONSE_NONE;
}

static void on_dll_discovered(drakvuf_t drakvuf, std::string const& dll_name, const dll_view_t* dll, void* extra)
{
    hidevm* plugin = (hidevm*)extra;

    plugin->wanted_hooks.visit_hooks_for(dll_name, [&](const auto& e)
    {
        drakvuf_request_usermode_hook(drakvuf, dll, &e, ExecQuery_handler, plugin);
    });
}

static void on_dll_hooked(drakvuf_t drakvuf, const dll_view_t* dll, const std::vector<hook_target_view_t>& targets, void* extra)
{
    PRINT_DEBUG("[HIDEVM] DLL hooked - done\n");
}

// ---------------------------------------------------------------------------
// Registry hiding for the Xen Platform PCI device (vendor ID 0x5853 == "XS").
//
// Al-khaser probes HKLM\SYSTEM\CurrentControlSet\Enum\PCI\VEN_5853* to detect
// Xen. We can't remove the PCI device itself (Xen PV drivers attach to it),
// so we hook the Nt registry-open paths and translate any open of a key whose
// path contains "\Enum\PCI\VEN_5853" into STATUS_OBJECT_NAME_NOT_FOUND.
// ---------------------------------------------------------------------------

static char* hidevm_get_key_path_from_attr(drakvuf_t drakvuf, drakvuf_trap_info_t* info,
    addr_t attr, addr_t objattr_root_off, addr_t objattr_name_off)
{
    if (!attr) return nullptr;

    auto vmi = vmi_lock_guard(drakvuf);

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3
    );

    addr_t key_handle = 0;
    ctx.addr = attr + objattr_root_off;
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &key_handle))
        return nullptr;

    addr_t key_name_addr = 0;
    ctx.addr = attr + objattr_name_off;
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &key_name_addr))
        return nullptr;

    gchar* key_root_p = drakvuf_reg_keyhandle_path(drakvuf, info, key_handle);
    unicode_string_t* us = drakvuf_read_unicode(drakvuf, info, key_name_addr);
    if (!us)
    {
        g_free(key_root_p);
        return nullptr;
    }

    char* key_path = g_strdup_printf("%s%s%s",
            key_root_p ?: "",
            key_root_p ? "\\" : "",
            (const char*)us->contents ?: "");
    g_free(key_root_p);
    vmi_free_unicode_str(us);

    return key_path;
}

static bool hidevm_is_xen_pci_key(const char* path)
{
    if (!path) return false;
    gchar* lower = g_ascii_strdown(path, -1);
    bool match = (g_strstr_len(lower, -1, HIDEVM_XEN_PCI_KEY_FRAGMENT) != nullptr);
    g_free(lower);
    return match;
}

event_response_t hidevm::HideKeyReturn_cb(drakvuf_t, drakvuf_trap_info_t* info)
{
    auto vmi = vmi_lock_guard(drakvuf);
    auto params = libhook::GetTrapParams(info);
    auto hook_ID = make_hook_id(info, params->target_rsp);

    if (this->hide_key_ret_hooks.count(hook_ID))
    {
        if (params->verifyResultCallParams(drakvuf, info))
        {
            if (VMI_FAILURE == vmi_set_vcpureg(vmi, STATUS_OBJECT_NAME_NOT_FOUND, RAX, info->vcpu))
            {
                PRINT_DEBUG("[HIDEVM] HideKey return: failed to set RAX to STATUS_OBJECT_NAME_NOT_FOUND\n");
            }
        }
        this->hide_key_ret_hooks.erase(hook_ID);
    }

    return VMI_EVENT_RESPONSE_NONE;
}

// Common entry-callback body for NtOpenKey / NtOpenKeyEx / NtCreateKey /
// NtOpenKeyTransacted / NtOpenKeyTransactedEx — all of these take
// POBJECT_ATTRIBUTES as their 3rd argument.
static event_response_t hidevm_open_key_entry(hidevm* plugin, drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    addr_t objattr = drakvuf_get_function_argument(drakvuf, info, 3);
    if (!objattr)
        return VMI_EVENT_RESPONSE_NONE;

    char* key_path = hidevm_get_key_path_from_attr(drakvuf, info, objattr,
            plugin->objattr_root, plugin->objattr_name);
    if (!key_path)
        return VMI_EVENT_RESPONSE_NONE;

    if (hidevm_is_xen_pci_key(key_path))
    {
        auto params = libhook::GetTrapParams(info);
        auto hook_ID = make_hook_id(info, params->target_rsp);

        // Avoid stacking duplicate return hooks on the same thread frame.
        if (!plugin->hide_key_ret_hooks.count(hook_ID))
        {
            auto hook = plugin->createReturnHook(info, &hidevm::HideKeyReturn_cb);
            if (hook)
            {
                plugin->hide_key_ret_hooks[hook_ID] = std::move(hook);
                fmt::print(plugin->format, "hidevm", drakvuf, info,
                    keyval("Reason", fmt::Qstr("Xen PCI registry key hidden")),
                    keyval("KeyName", fmt::Qstr(key_path))
                );
            }
        }
    }

    g_free(key_path);
    return VMI_EVENT_RESPONSE_NONE;
}

// ---------------------------------------------------------------------------
// MAP-1826: NtEnumerateKey filtering for sandbox device-tree subkeys.
//
// al-khaser walks \Enum\PCI / \Enum\IDE / \Enum\SCSI by index via
// RegEnumKeyExW (which lands at NtEnumerateKey) and substring-matches the
// returned subkey names against VEN_5853, QEMU, virtio, Xen, etc. The
// existing NtOpenKey hook above never sees these probes because al-khaser
// doesn't open the leaf keys by name. Here we install an entry+return hook
// pair on NtEnumerateKey: when the enumeration is rooted at one of the three
// device parent paths, the return callback overwrites any banned substrings
// in the WCHAR Name field of the output buffer with 'X' characters. The key
// still appears (downstream callers like PnP keep working) but al-khaser's
// case-insensitive substring search no longer matches.
// ---------------------------------------------------------------------------

static const char* HIDEVM_BANNED_SUBKEY_FRAGMENTS[] =
{
    "ven_5853",  // Xen Platform PCI device
    "qemu",
    "virtio",
    "xen",
    nullptr,
};

static bool hidevm_path_endswith(const char* path, const char* suffix)
{
    if (!path || !suffix) return false;
    size_t plen = strlen(path);
    size_t slen = strlen(suffix);
    if (slen > plen) return false;
    return g_ascii_strcasecmp(path + (plen - slen), suffix) == 0;
}

static bool hidevm_is_target_enum_parent(const char* path)
{
    return hidevm_path_endswith(path, HIDEVM_ENUM_PCI_PATH_FRAGMENT)
        || hidevm_path_endswith(path, HIDEVM_ENUM_IDE_PATH_FRAGMENT)
        || hidevm_path_endswith(path, HIDEVM_ENUM_SCSI_PATH_FRAGMENT);
}

// Munge any banned substring in the buffer's WCHAR name in place. Returns
// the matched fragment for logging (or nullptr if nothing matched).
static const char* hidevm_subkey_buffer_munge(drakvuf_t drakvuf, drakvuf_trap_info_t* info,
    addr_t name_addr, uint32_t name_length_bytes)
{
    if (!name_addr || name_length_bytes < 2)
        return nullptr;

    // Hard cap to keep the stack read bounded; subkey names in registry are
    // limited to 255 chars by the registry API anyway.
    if (name_length_bytes > 1024)
        name_length_bytes = 1024;

    auto vmi = vmi_lock_guard(drakvuf);

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3
    );

    std::vector<uint8_t> buf(name_length_bytes);
    ctx.addr = name_addr;
    if (VMI_FAILURE == vmi_read(vmi, &ctx, name_length_bytes, buf.data(), nullptr))
        return nullptr;

    // Decode WCHAR -> ASCII lowercase for substring matching. Non-ASCII
    // characters become '?'; this is fine because banned tokens are ASCII.
    size_t nchars = name_length_bytes / 2;
    std::string ascii(nchars, '?');
    for (size_t i = 0; i < nchars; i++)
    {
        uint16_t w = (uint16_t)buf[i*2] | ((uint16_t)buf[i*2 + 1] << 8);
        if (w < 128)
            ascii[i] = (char)g_ascii_tolower((char)w);
    }

    const char* matched = nullptr;
    for (const char** frag = HIDEVM_BANNED_SUBKEY_FRAGMENTS; *frag; frag++)
    {
        const char* hit = strstr(ascii.c_str(), *frag);
        if (!hit) continue;

        size_t off_chars = (size_t)(hit - ascii.c_str());
        size_t frag_chars = strlen(*frag);

        // Overwrite each matched WCHAR with 'X' (0x0058 0x0000 LE).
        for (size_t i = 0; i < frag_chars; i++)
        {
            buf[(off_chars + i) * 2]     = 'X';
            buf[(off_chars + i) * 2 + 1] = 0x00;
        }
        // Keep the lowercase view in sync so a second matching fragment in
        // the same name (rare) doesn't double-trip on the same bytes.
        for (size_t i = 0; i < frag_chars; i++)
            ascii[off_chars + i] = 'x';
        matched = *frag;
    }

    if (matched)
    {
        ctx.addr = name_addr;
        if (VMI_FAILURE == vmi_write(vmi, &ctx, name_length_bytes, buf.data(), nullptr))
        {
            PRINT_DEBUG("[HIDEVM] EnumerateKey: failed to write munged subkey name back to guest\n");
            return nullptr;
        }
    }
    return matched;
}

event_response_t hidevm::EnumerateKeyReturn_cb(drakvuf_t, drakvuf_trap_info_t* info)
{
    auto params = libhook::GetTrapParams<hidevm_enum_key_data>(info);
    auto hook_ID = make_hook_id(info, params->target_rsp);

    // Always clean up the per-call hook entry on the way out, regardless of
    // syscall outcome.
    auto cleanup = [this, &hook_ID]()
    {
        this->enum_key_ret_hooks.erase(hook_ID);
    };

    if (!this->enum_key_ret_hooks.count(hook_ID) || !params->verifyResultCallParams(drakvuf, info))
    {
        cleanup();
        return VMI_EVENT_RESPONSE_NONE;
    }

    if (info->regs->rax != STATUS_SUCCESS)
    {
        cleanup();
        return VMI_EVENT_RESPONSE_NONE;
    }

    addr_t name_offset_in_buf = 0;
    addr_t length_field_offset_in_buf = 0;
    if (params->info_class == KEY_BASIC_INFORMATION_CLASS)
    {
        length_field_offset_in_buf = KEY_BASIC_INFORMATION_NAME_LENGTH_OFFSET;
        name_offset_in_buf         = KEY_BASIC_INFORMATION_NAME_OFFSET;
    }
    else if (params->info_class == KEY_NODE_INFORMATION_CLASS)
    {
        length_field_offset_in_buf = KEY_NODE_INFORMATION_NAME_LENGTH_OFFSET;
        name_offset_in_buf         = KEY_NODE_INFORMATION_NAME_OFFSET;
    }
    else
    {
        // Other KEY_INFORMATION_CLASS values don't expose the subkey name.
        cleanup();
        return VMI_EVENT_RESPONSE_NONE;
    }

    uint32_t name_length_bytes = 0;
    {
        auto vmi = vmi_lock_guard(drakvuf);
        ACCESS_CONTEXT(ctx,
            .translate_mechanism = VMI_TM_PROCESS_DTB,
            .dtb = info->regs->cr3
        );
        ctx.addr = params->key_information + length_field_offset_in_buf;
        if (VMI_FAILURE == vmi_read_32(vmi, &ctx, &name_length_bytes))
        {
            cleanup();
            return VMI_EVENT_RESPONSE_NONE;
        }
    }

    if (name_length_bytes == 0 ||
        name_offset_in_buf + name_length_bytes > params->length)
    {
        cleanup();
        return VMI_EVENT_RESPONSE_NONE;
    }

    const char* matched = hidevm_subkey_buffer_munge(drakvuf, info,
            params->key_information + name_offset_in_buf, name_length_bytes);

    if (matched)
    {
        fmt::print(this->format, "hidevm", drakvuf, info,
            keyval("Reason", fmt::Qstr("Enum subkey name munged")),
            keyval("Match", fmt::Qstr(matched))
        );
    }

    cleanup();
    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t hidevm::NtEnumerateKey_cb(drakvuf_t, drakvuf_trap_info_t* info)
{
    // Cheap arg checks first — NtEnumerateKey is hot, so avoid the VMI page
    // walk in drakvuf_reg_keyhandle_path() for irrelevant enumerations.
    uint32_t info_class      = (uint32_t)drakvuf_get_function_argument(drakvuf, info, 3);
    if (info_class != KEY_BASIC_INFORMATION_CLASS && info_class != KEY_NODE_INFORMATION_CLASS)
        return VMI_EVENT_RESPONSE_NONE;

    addr_t key_handle        = drakvuf_get_function_argument(drakvuf, info, 1);
    addr_t key_information   = drakvuf_get_function_argument(drakvuf, info, 4);
    uint32_t length          = (uint32_t)drakvuf_get_function_argument(drakvuf, info, 5);
    if (!key_handle || !key_information)
        return VMI_EVENT_RESPONSE_NONE;

    gchar* parent_path = drakvuf_reg_keyhandle_path(drakvuf, info, key_handle);
    if (!parent_path)
        return VMI_EVENT_RESPONSE_NONE;

    gchar* parent_lower = g_ascii_strdown(parent_path, -1);
    bool is_target = hidevm_is_target_enum_parent(parent_lower);
    g_free(parent_lower);
    g_free(parent_path);

    if (!is_target)
        return VMI_EVENT_RESPONSE_NONE;

    auto hook = this->createReturnHook<hidevm_enum_key_data>(info, &hidevm::EnumerateKeyReturn_cb, info->trap->name);
    if (!hook)
        return VMI_EVENT_RESPONSE_NONE;

    auto params = libhook::GetTrapParams<hidevm_enum_key_data>(hook->trap_);
    params->info_class      = info_class;
    params->key_information = key_information;
    params->length          = length;

    auto hook_ID = make_hook_id(info, params->target_rsp);
    this->enum_key_ret_hooks[hook_ID] = std::move(hook);

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t hidevm::NtOpenKey_cb(drakvuf_t, drakvuf_trap_info_t* info)
{
    return hidevm_open_key_entry(this, this->drakvuf, info);
}

event_response_t hidevm::NtOpenKeyEx_cb(drakvuf_t, drakvuf_trap_info_t* info)
{
    return hidevm_open_key_entry(this, this->drakvuf, info);
}

event_response_t hidevm::NtCreateKey_cb(drakvuf_t, drakvuf_trap_info_t* info)
{
    return hidevm_open_key_entry(this, this->drakvuf, info);
}

event_response_t hidevm::NtOpenKeyTransacted_cb(drakvuf_t, drakvuf_trap_info_t* info)
{
    return hidevm_open_key_entry(this, this->drakvuf, info);
}

event_response_t hidevm::NtOpenKeyTransactedEx_cb(drakvuf_t, drakvuf_trap_info_t* info)
{
    return hidevm_open_key_entry(this, this->drakvuf, info);
}

hidevm::hidevm(drakvuf_t drakvuf, const hidevm_config* config, output_format_t output): pluginex(drakvuf, output), drakvuf(drakvuf), format(output)
{
    // Advance boot time
    if (config->delay)
    {
        vmi_lock_guard vmi(drakvuf);
        addr_t kuser = vmi_get_address_width(vmi) == 8 ? 0xFFFFF7800000000 : 0xFFDF0000;
        addr_t pkuser;
        if (VMI_SUCCESS != vmi_translate_kv2p(vmi, kuser, &pkuser))
        {
            PRINT_DEBUG("[HIDEVM] Failed to translate KUSER_SHARED_DATA to physical\n");
        }
        else
        {
            // Get TickCountMultiplier
            uint32_t multiplier = 0, ticks = 0;
            if (VMI_SUCCESS != vmi_read_32_pa(vmi, pkuser + 0x04, &multiplier) ||
                VMI_SUCCESS != vmi_read_32_pa(vmi, pkuser + 0x320, &ticks))
            {
                PRINT_DEBUG("[HIDEVM] Failed to read KUSER_SHARED_DATA\n");
            }
            else
            {
                // Convert delay from seconds to ms and to cicles
                uint64_t delay = (config->delay * 1000) << 32;
                ticks += static_cast<uint32_t>((delay / static_cast<uint64_t>(multiplier)) >> 8);
                if (VMI_SUCCESS != vmi_write_32_pa(vmi, pkuser + 0x320, &ticks))
                {
                    PRINT_DEBUG("[HIDEVM] Failed to write KUSER_SHARED_DATA\n");
                }
            }
        }
    }
    if (!drakvuf_get_kernel_struct_member_rva(drakvuf, "_OBJECT_ATTRIBUTES", "Length", &this->objattr_length))
    {
        PRINT_DEBUG("[HIDEVM] Failed to get nt!_OBJECT_ATTRIBUTES.Length offest\n");
        throw -1;
    }
    if (!drakvuf_get_kernel_struct_member_rva(drakvuf, "_OBJECT_ATTRIBUTES", "ObjectName", &this->objattr_name))
    {
        PRINT_DEBUG("[HIDEVM] Failed to get nt!_OBJECT_ATTRIBUTES.ObjectName offest\n");
        throw -1;
    }
    if (!drakvuf_get_kernel_struct_member_rva(drakvuf, "_OBJECT_ATTRIBUTES", "RootDirectory", &this->objattr_root))
    {
        PRINT_DEBUG("[HIDEVM] Failed to get nt!_OBJECT_ATTRIBUTES.RootDirectory offest\n");
        throw -1;
    }
    if (!drakvuf_get_kernel_struct_member_rva(drakvuf, "_IO_STATUS_BLOCK", "Information", &this->iostatusblock_information))
    {
        PRINT_DEBUG("[HIDEVM] Failed to get nt!_IO_STATUS_BLOCK.Information offest\n");
        throw -1;
    }

    this->NtDeviceIoControlFile_hook = createSyscallHook("NtDeviceIoControlFile", &hidevm::NtDeviceIoControlFile_cb);

    // Hide the Xen Platform PCI device from registry-based VM detection
    // (al-khaser HKLM\SYSTEM\CurrentControlSet\Enum\PCI\VEN_5853* probe).
    this->NtOpenKey_hook              = createSyscallHook("NtOpenKey", &hidevm::NtOpenKey_cb);
    this->NtOpenKeyEx_hook            = createSyscallHook("NtOpenKeyEx", &hidevm::NtOpenKeyEx_cb);
    this->NtCreateKey_hook            = createSyscallHook("NtCreateKey", &hidevm::NtCreateKey_cb);
    this->NtOpenKeyTransacted_hook    = createSyscallHook("NtOpenKeyTransacted", &hidevm::NtOpenKeyTransacted_cb);
    this->NtOpenKeyTransactedEx_hook  = createSyscallHook("NtOpenKeyTransactedEx", &hidevm::NtOpenKeyTransactedEx_cb);

    // Filter \Enum\PCI / \Enum\IDE / \Enum\SCSI subkey enumerations so banned
    // tokens (VEN_5853, qemu, virtio, xen) don't surface to user-mode
    // detection scanners (MAP-1826).
    this->NtEnumerateKey_hook         = createSyscallHook("NtEnumerateKey", &hidevm::NtEnumerateKey_cb);

    // Usermode hooking for WQL spoofing
    if (!drakvuf_are_userhooks_supported(drakvuf))
    {
        PRINT_DEBUG("[HIDEVM] Usermode hooking not supported, SELECT * Win32_* requests cannot be spoofed\n");
    }
    else
    {
        win_ver_t win_ver;
        {
            auto vmi = vmi_lock_guard(drakvuf);
            win_ver = vmi_get_winver(vmi);
        }
        const auto log = HookActions::empty();

        addr_t offset_IWbemServices__ExecQuery_win7_x64 = 0x7100;
        addr_t offset_IWbemServices__ExecQuery_win7_x32 = 0x1ebe0;

        addr_t offset_IWbemServices__ExecQuery_win10_x64 = 0x2b280;
        addr_t offset_IWbemServices__ExecQuery_win10_x32 = 0x30690;

        switch (win_ver)
        {
            case VMI_OS_WINDOWS_7:
                wanted_hooks.add_hook("System32\\wbem\\fastprox.dll", "IWbemServices::ExecQuery", offset_IWbemServices__ExecQuery_win7_x64, log, IWbemServices__ExecQuery_args());
                wanted_hooks.add_hook("SysWOW64\\wbem\\fastprox.dll", "IWbemServices::ExecQuery", offset_IWbemServices__ExecQuery_win7_x32, log, IWbemServices__ExecQuery_args());
                break;
            case VMI_OS_WINDOWS_10:
                wanted_hooks.add_hook("System32\\wbem\\fastprox.dll", "IWbemServices::ExecQuery", offset_IWbemServices__ExecQuery_win10_x64, log, IWbemServices__ExecQuery_args());
                wanted_hooks.add_hook("SysWOW64\\wbem\\fastprox.dll", "IWbemServices::ExecQuery", offset_IWbemServices__ExecQuery_win10_x32, log, IWbemServices__ExecQuery_args());
                break;
            default:
                break;
        }

        if (win_ver == VMI_OS_WINDOWS_7 || win_ver == VMI_OS_WINDOWS_10)
        {
            usermode_cb_registration reg =
            {
                .pre_cb = on_dll_discovered,
                .post_cb = on_dll_hooked,
                .extra = (void*)this
            };
            drakvuf_register_usermode_callback(drakvuf, &reg);
        }
        else
        {
            PRINT_DEBUG("[HIDEVM] WMI queries (Win32_PerfFormattedData, Win32_PerfRawData) spoofing not supported for this OS\n");
        }
    }
}

bool hidevm::stop_impl()
{
    return drakvuf_stop_userhooks(drakvuf) && pluginex::stop_impl();
}
