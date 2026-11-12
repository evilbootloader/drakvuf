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

#include <iostream>
#include <stdexcept>
#include <inttypes.h>
#include <assert.h>

#include <libvmi/libvmi.h>
#include <libvmi/peparse.h>

#include "plugins/output_format.h"
#include "plugins/helpers/object_attributes.h"
#include "apimon.h"
#include "crypto.h"



static event_response_t delete_process_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto plugin  = get_trap_plugin<apimon>(info);
    auto process = drakvuf_get_function_argument(drakvuf, info, 1);

    vmi_pid_t pid;
    if (!drakvuf_get_process_pid(drakvuf, process, &pid))
    {
        PRINT_DEBUG("[APIMON] Failed to read process pid\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    {
        std::lock_guard<std::mutex> lock(plugin->procs_mtx);
        plugin->procs.erase(pid);
    }
    {
        std::lock_guard<std::mutex> lock(plugin->unwind_mtx);
        auto& tables = plugin->unwind_tables;
        tables.erase(tables.lower_bound({ pid, 0 }), tables.upper_bound({ pid, ~addr_t(0) }));
    }
    plugin->returns.forget_process(pid);
    return VMI_EVENT_RESPONSE_NONE;
}


std::map<std::string, std::string> ThreadHandle_hook(
    drakvuf_t drakvuf,
    drakvuf_trap_info_t* info,
    addr_t thread_handle)
{
    std::map<std::string, std::string> ret;

    if (!thread_handle)
        return ret;

    addr_t process = drakvuf_get_current_process(
        drakvuf, info
    );

    if (!process)
        return ret;

    // Resolve the thread handle to its ETHREAD body
    addr_t ethread = 0;

    if (!drakvuf_obj_ref_by_handle(
            drakvuf,
            info,
            process,
            thread_handle,
            OBJ_MANAGER_THREAD_OBJECT,
            &ethread) || !ethread)
        return ret;

    // Resolve offsets from the Windows kernel profile
    addr_t cid_offset = 0;
    addr_t pid_offset = 0;

    if (!drakvuf_get_kernel_struct_member_rva(
            drakvuf, "_ETHREAD", "Cid", &cid_offset))
        return ret;

    if (!drakvuf_get_kernel_struct_member_rva(
            drakvuf, "_CLIENT_ID", "UniqueProcess",
            &pid_offset))
        return ret;

    addr_t pid = 0;

    {
        // Reads only: this vCPU's reader instance, not the main one under
        // the lock every other vCPU's callback would then wait for
        vmi_reader_guard vmi(drakvuf);

        if (VMI_SUCCESS != vmi_read_addr_va(
                vmi,
                ethread + cid_offset + pid_offset,
                0,
                &pid))
            return ret;
    }

    ret["ProcessId"] =
        std::to_string(static_cast<uint32_t>(pid));

    uint32_t tid = 0;

    if (drakvuf_get_tid_from_handle(
            drakvuf, info, thread_handle, &tid))
    {
        ret["ThreadId"] = std::to_string(tid);
    }

    return ret;
}


std::map<std::string, std::string> NtCreateUserProcess_hook(
    drakvuf_t drakvuf,
    drakvuf_trap_info_t* info,
    addr_t process_parameters)
{

    std::map<std::string, std::string> ret;

    if (!process_parameters)
        return ret;

    addr_t commandline_offset;

    if (!drakvuf_get_kernel_struct_member_rva(drakvuf, "_RTL_USER_PROCESS_PARAMETERS", "CommandLine", &commandline_offset))
    {
        PRINT_DEBUG("[APIMON] Failed to get CommandLine from _RTL_USER_PROCESS_PARAMETERS\n");
        return ret;
    }

    unicode_string_t* command_line = drakvuf_read_unicode(drakvuf, info, process_parameters + commandline_offset);
    if (!command_line)
        return ret;

    ret["CommandLine"] = command_line->contents ? (const char*)command_line->contents : "";

    vmi_free_unicode_str(command_line);

    return ret;
}

std::map<std::string, std::string> ShellExecuteExW_hook(
    drakvuf_t drakvuf,
    drakvuf_trap_info_t* info,
    addr_t exec_info)
{
    std::map<std::string, std::string> ret;

    if (!exec_info)
        return ret;

    // Native 32-bit Windows or WOW64 process
    const bool is32 =
        drakvuf_get_page_mode(drakvuf) != VMI_PM_IA32E ||
        drakvuf_is_wow64(drakvuf, info);

    const addr_t file_off   = is32 ? 0x10 : 0x18;
    const addr_t params_off = is32 ? 0x14 : 0x20;
    const addr_t show_off   = is32 ? 0x1C : 0x30;

    // Reads only: this vCPU's reader instance, whose translations the hook
    // flushed -- the main instance's may be older than the process's mappings
    vmi_reader_guard vmi(drakvuf);

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3
    );

    // Validate that the structure contains the requested fields
    uint32_t cbSize = 0;
    ctx.addr = exec_info;

    if (VMI_SUCCESS != vmi_read_32(vmi, &ctx, &cbSize) ||
        cbSize < show_off + sizeof(uint32_t))
        return ret;

    // Read a 32- or 64-bit guest pointer
    auto read_ptr = [&](addr_t offset, addr_t& value) -> bool
    {
        ctx.addr = exec_info + offset;

        if (is32)
        {
            uint32_t tmp = 0;
            if (VMI_SUCCESS != vmi_read_32(vmi, &ctx, &tmp))
                return false;
            value = tmp;
        }
        else
        {
            uint64_t tmp = 0;
            if (VMI_SUCCESS != vmi_read_64(vmi, &ctx, &tmp))
                return false;
            value = tmp;
        }

        return true;
    };

    // Read a UTF-16 string from guest memory
    auto read_string = [&](addr_t ptr) -> std::string
    {
        if (!ptr)
            return {};

        ctx.addr = ptr;

        unicode_string_t* us =
            drakvuf_read_wchar_string(drakvuf, &ctx);

        if (!us)
            return {};

        std::string result =
            us->contents ? (const char*)us->contents : "";

        vmi_free_unicode_str(us);
        return result;
    };

    addr_t ptr = 0;

    // lpFile
    if (read_ptr(file_off, ptr) && ptr)
        ret["FilePath"] = read_string(ptr);

    // lpParameters
    if (read_ptr(params_off, ptr) && ptr){
        ret["Parameters"] = read_string(ptr);
    }
    else
    {
        ret["Parameters"] = "";
    }
    
    // nShow
    uint32_t nShow = 0;
    ctx.addr = exec_info + show_off;

    if (VMI_SUCCESS == vmi_read_32(vmi, &ctx, &nShow))
        ret["Show"] =
            std::to_string(static_cast<int32_t>(nShow));

    return ret;
}


void apimon::usermode_print(drakvuf_trap_info* hit_info, const apimon_call& call, std::optional<uint64_t> return_value)
{
    hook_target_entry_t* target = call.target;
    const auto& module_name = call.module_name;

    // The output formatters emit the trap's name as Method, and at the return
    // the trap is the breakpoint shared by all calls returning there
    drakvuf_trap_t trap = *hit_info->trap;
    trap.name = target->target_name.c_str();
    drakvuf_trap_info_t call_info = *hit_info;
    call_info.trap = &trap;
    drakvuf_trap_info_t* info = &call_info;


    //const auto& api_name = target->target_name;

    //std::map < std::string, std::string > extra_data;

    //if (!strcmp(api_name, "CryptGenKey"))
    //    extra_data = CryptGenKey_hook(drakvuf, info, args);

    

    std::optional<fmt::Qstr<std::string>> clsid;

    if (!target->clsid.empty())
        clsid = fmt::Qstr(target->clsid);
    /*
    std::vector<fmt::Rstr<std::string>> fmt_args{};
    {
        const auto& printers = target->argument_printers;
        for (auto [arg, printer] = std::tuple(std::cbegin(args), std::cbegin(printers));
            arg != std::cend(args) && printer != std::cend(printers);
            ++arg, ++printer)
        {
            fmt_args.push_back(fmt::Rstr((*printer)->print(drakvuf, info, *arg)));
        }
    }
    
    std::map<std::string, fmt::Qstr<std::string>> fmt_extra{};
    for (const auto& extra : extra_data)
    {
        fmt_args.push_back(fmt::Rstr(extra.first + "=" + extra.second));
    }

    auto module_name = resolve_module(drakvuf, info->proc_data.base_addr, info->regs->rip, info->proc_data.pid);
    */
    std::optional<fmt::Qstr<std::string>> module_opt;
    if (module_name.has_value())
    {
        module_opt = module_name.value();
    }

    // An out parameter is printed now, at the return (at the hook only for a
    // no-retval hook, which has no return)
    std::vector<fmt::Rstr<std::string>> fmt_args{};
    fmt_args.reserve(call.args.size());
    for (const auto& arg : call.args)
        fmt_args.push_back(fmt::Rstr(arg.index
                ? print_argument(drakvuf, info, target->argument_printers, call.raw, *arg.index, return_value)
                : arg.text));

    // capemon's caller: the first return address outside the system DLLs
    // (find_caller). FromModule stays the module of the return address
    // itself. No parentcaller, the next such address: no CAPE signature
    // reads it (community, 2026-11-11), and an x64 one costs a second walk.
    fmt::print(m_output_format, "apimon", drakvuf, info,
        keyval("Event", fmt::Rstr("api_called")),
        keyval("CLSID", clsid),
        keyval("Caller", fmt::Xval(call.caller)),
        keyval("ReturnValue", fmt::Xval(info->regs->rax)),
        keyval("FromModule", module_opt),
        keyval("Arguments", fmt_args)//,
        //keyval("Extra", fmt_extra)
    );
}

static event_response_t usermode_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info* info)
{
    hook_target_entry_t* target = (hook_target_entry_t*)info->trap->data;
    auto plugin = (apimon*)target->plugin;

    if (target->pid != info->attached_proc_data.pid)
        return VMI_EVENT_RESPONSE_NONE;

    if (plugin->is_stopping())
        return VMI_EVENT_RESPONSE_NONE;

    // The arguments and the return address are read through this vCPU's reader
    // instance: flush its translations of the address space, not the main one's
    {
        vmi_reader_guard vmi(drakvuf);
        vmi_v2pcache_flush(vmi, info->regs->cr3);
    }

    addr_t ret_addr = drakvuf_get_function_return_address(drakvuf, info);

    if (!ret_addr)
    {
        PRINT_DEBUG("[APIMON-USER] Failed to read return address from the stack.\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    // Read at the hook: the registers holding the arguments are not preserved
    // across the call, and an in parameter may be freed or changed by then
    apimon_call call{ target, {}, {}, ret_addr, plugin->find_caller(drakvuf, info, ret_addr), std::nullopt };
    auto& fmt_args = call.args;
    const auto& printers = target->argument_printers;

    // All of them first: a buffer's length may be a later argument
    call.raw.reserve(printers.size());
    for (size_t i = 0; i < printers.size(); ++i)
        call.raw.push_back(drakvuf_get_function_argument(drakvuf, info, i + 1));

    for (size_t i = 0; i < printers.size(); ++i)
    {
        const uint64_t argument = call.raw[i];
        const auto& printer = printers[i];

        // An out parameter holds nothing yet: printed when the call is reported
        if (printer->reads_output())
            fmt_args.push_back(apimon_argument{ {}, i });
        else
            fmt_args.push_back(apimon_argument{ print_argument(drakvuf, info, printers, call.raw, i, std::nullopt), std::nullopt });

        const auto& api_name = target->target_name;
        const auto& name = printer->get_name();
        const auto& type = printer->get_type();

        // The first argument of an Nt/Zw Create* or Open* service is the
        // PHANDLE it returns the handle in: at the hook a pointer, not a handle
        const bool returned_handle = i == 0 &&
            (api_name.rfind("NtCreate", 0) == 0 || api_name.rfind("NtOpen", 0) == 0 ||
                api_name.rfind("ZwCreate", 0) == 0 || api_name.rfind("ZwOpen", 0) == 0);

        char* filename = nullptr;

        if ((name == "ObjectAttributes" && type == "lpvoid"))
        {
            // A file, a key, a mutex... by service, under capemon's name
            if (auto object = read_object_attributes(drakvuf, info, api_name.c_str(), name.c_str(),
                    argument, drakvuf_process_is32bit(drakvuf, info)))
                fmt_args.push_back(
                    apimon_argument{ std::string(object->label) + "=" + object->name, std::nullopt }
                );
        } else if (name == "FileHandle" && !returned_handle) {
            filename = drakvuf_get_filename_from_handle(
                drakvuf, info, argument
            );
            if (filename)
            {
                if (*filename)
                    fmt_args.push_back(
                        apimon_argument{ std::string("FileName=") + filename, std::nullopt }
                    );

                g_free(filename);
            }
        }
        if ((name == "hKey"  || name == "KeyHandle") && !returned_handle &&
                (type == "lpvoid" || type == "hkey") &&
                (api_name.compare(0, 3, "Reg") == 0 || 
                (api_name.size() >= 3 && api_name.compare(api_name.size() - 3, 3, "Key") == 0)))
        {
            gchar* key_path = drakvuf_reg_keyhandle_path(
                drakvuf, info, argument
            );

            if (key_path)
            {
                if (*key_path)
                    fmt_args.push_back(
                        apimon_argument{ std::string("Key=") + key_path, std::nullopt }
                    );

                g_free(key_path);
            }
        } else if (api_name == "ShellExecuteExW" && name == "pExecInfo") {
            auto extra = ShellExecuteExW_hook(drakvuf, info, argument);
            for (const auto& [key, value] : extra)
            {
                fmt_args.push_back(
                    apimon_argument{ key + "=" + value, std::nullopt }
                );
            }
        } else if (api_name == "NtCreateUserProcess" && name == "ProcessParameters")
        {
            auto extra = NtCreateUserProcess_hook(drakvuf, info, argument);
            for (const auto& [key, value] : extra)
            {
                fmt_args.push_back(
                    apimon_argument{ key + "=" + value, std::nullopt }
                );
            }
        } else if (name == "ThreadHandle" && type == "lpvoid" && !returned_handle)
        {
            auto extra = ThreadHandle_hook(
                drakvuf, info, argument
            );

            for (const auto& [key, value] : extra)
            {
                fmt_args.push_back(
                    apimon_argument{ key + "=" + value, std::nullopt }
                );
            }
        }
    } 
            
    call.module_name = plugin->resolve_module(drakvuf, info->proc_data.base_addr, ret_addr, info->proc_data.pid);
    const bool transient = !call.module_name;

    if (target->no_retval)
    {
        plugin->usermode_print(info, call, std::nullopt);
        return VMI_EVENT_RESPONSE_NONE;
    }

    // One breakpoint per return address, shared by the calls returning there.
    // Kept between calls only in code mapped from a file: writing to the page
    // of a breakpoint pauses the VM to copy it again, which JIT code does a lot.
    auto result = plugin->returns.track(drakvuf, info, ret_addr, std::move(call), transient);
    if (result != return_track_result::tracked)
        PRINT_DEBUG("[APIMON-USER] pid %d: no return breakpoint for %s at 0x%lx, not reported\n",
            info->proc_data.pid, target->target_name.c_str(), ret_addr);

    return VMI_EVENT_RESPONSE_NONE;
}

static void print_addresses(drakvuf_t drakvuf, apimon* plugin, const dll_view_t* dll, const std::vector<hook_target_view_t>& targets)
{
    unicode_string_t* dll_name;
    json_object* j_root;
    json_object* j_rvas;
    vmi_pid_t pid;
    auto vmi = vmi_lock_guard(drakvuf);

    dll_name = drakvuf_read_unicode_va(drakvuf, dll->mmvad.file_name_ptr, 0);

    if (plugin->m_output_format != OUTPUT_JSON)
        goto out;

    if (!dll_name || !dll_name->contents)
        goto out;

    vmi_dtb_to_pid(vmi, dll->dtb, &pid);

    j_root = json_object_new_object();
    j_rvas = json_object_new_object();

    for (auto const& target : targets)
    {
        if (target.state == HOOK_OK)
            json_object_object_add(j_rvas, target.target_name.c_str(), json_object_new_int(target.offset));
    }

    json_object_object_add(j_root, "Plugin", json_object_new_string("apimon"));
    json_object_object_add(j_root, "Event", json_object_new_string("dll_loaded"));
    json_object_object_add(j_root, "Rva", j_rvas);
    json_object_object_add(j_root, "DllBase", json_object_new_string_fmt("0x%lx", dll->real_dll_base));
    json_object_object_add(j_root, "DllName", json_object_new_string((const char*)dll_name->contents));
    json_object_object_add(j_root, "PID", json_object_new_int(pid));

    printf("%s\n", json_object_to_json_string(j_root));

    json_object_put(j_root);

out:
    if (dll_name)
        vmi_free_unicode_str(dll_name);
}

static void on_dll_discovered(drakvuf_t drakvuf, const std::string& dll_name, const dll_view_t* dll, void* extra)
{
    apimon* plugin = (apimon*)extra;

    vmi_pid_t pid;
    {
        auto vmi = vmi_lock_guard(drakvuf);
        vmi_dtb_to_pid(vmi, dll->dtb, &pid);
    }

    fmt::print(plugin->m_output_format, "apimon", drakvuf, nullptr,
        keyval("Event", fmt::Rstr("dll_discovered")),
        keyval("DllName", fmt::Estr(dll_name)),
        keyval("DllBase", fmt::Xval(dll->real_dll_base)),
        keyval("PID", fmt::Nval(pid))
    );

    plugin->wanted_hooks.visit_hooks_for(dll_name, [&](const auto& e)
    {
        drakvuf_request_usermode_hook(drakvuf, dll, &e, usermode_hook_cb, plugin, true);
    });
}

static void on_dll_hooked(drakvuf_t drakvuf, const dll_view_t* dll, const std::vector<hook_target_view_t>& targets, void* extra)
{
    apimon* plugin = (apimon*)extra;
    print_addresses(drakvuf, plugin, dll, targets);
    PRINT_DEBUG("[APIMON] DLL hooked - done\n");
}

/*
 * A file only the system can have written, and a DLL: a frame in it is
 * skipped looking for the caller (find_caller). When unsure, no -- a system
 * DLL taken for the caller misleads no signature, a sample's module taken
 * for a system DLL hides the sample's frame.
 *
 * FILE_OBJECT names are volume relative (\Windows\System32\ntdll.dll), so
 * the path is anchored at the root, and only the directories users cannot
 * write count: System32 and SysWOW64 themselves and their wbem (WMI's
 * client DLLs), not other subdirectories -- spool\drivers\color, Tasks,
 * com\dmp... are writable by any user -- and WinSxS. Never an executable:
 * a process's own image is its code wherever it lies, as for capemon,
 * whose DLL ranges leave out the base image.
 *
 * KNOWN GAPS: a path on another volume -- a mounted ISO holding
 * \Windows\System32\x.dll -- reads the same; a DLL an administrator-level
 * sample wrote into System32 counts (its write is in filetracer's records);
 * a system DLL whose code was overwritten (module stomping) or whose
 * section was made from a modified file (phantom DLL hollowing) counts.
 */
static bool is_system_path(const std::string& path)
{
    gchar* lower = g_ascii_strdown(path.c_str(), -1);
    const std::string p = lower ? lower : "";
    g_free(lower);

    if (p.size() < 4 || p.compare(p.size() - 4, 4, ".dll") != 0)
        return false;
    if (p.rfind("\\windows\\winsxs\\", 0) == 0)
        return true;

    const auto dir = p.substr(0, p.find_last_of('\\') + 1);
    for (const char* system : { "\\windows\\system32\\", "\\windows\\syswow64\\" })
    {
        const std::string d = system;
        if (dir == d || dir == d + "wbem\\")
            return true;
    }
    return false;
}

std::optional<apimon_module> apimon::find_module(drakvuf_t drakvuf, addr_t process, addr_t addr, vmi_pid_t pid)
{
    auto lookup = [&]() -> std::optional<apimon_module>
    {
        std::lock_guard<std::mutex> lock(this->procs_mtx);
        const auto& mods = this->procs.find(pid);
        if (mods != this->procs.end())
        {
            for (const auto& module : mods->second)
            {
                if (addr >= module.base && addr < module.base + module.size)
                {
                    return module;
                }
            }
        }
        return {};
    };
    if (auto module = lookup())
    {
        return module;
    }
    // Didn't find in cache, try to resolve.
    //
    if (mmvad_info_t mmvad{}; drakvuf_find_mmvad(drakvuf, process, addr, &mmvad))
    {
        if (mmvad.file_name_ptr)
        {
            if (auto u_name = drakvuf_read_unicode_va(drakvuf, mmvad.file_name_ptr, 0))
            {
                std::string name = (const char*)u_name->contents;
                vmi_free_unicode_str(u_name);
                const bool system = is_system_path(name);

                if (auto sub = name.find_last_of("/\\"); sub != std::string::npos)
                {
                    name.erase(0, sub + 1);
                }

                // ending_vpn is the VAD's last page, not the one past it
                apimon_module module
                {
                    .name = name,
                    .base = mmvad.starting_vpn << 12,
                    .size = (mmvad.ending_vpn - mmvad.starting_vpn + 1) << 12,
                    .system = system
                };
                std::lock_guard<std::mutex> lock(this->procs_mtx);
                this->procs[pid].push_back(module);
                return module;
            }
        }
    }
    return {};
}

std::optional<std::string> apimon::resolve_module(drakvuf_t drakvuf, addr_t process, addr_t addr, vmi_pid_t pid)
{
    if (auto module = find_module(drakvuf, process, addr, pid))
        return module->name;
    return {};
}

std::shared_ptr<const std::vector<x64_unwind::runtime_function>> apimon::unwind_table(
    drakvuf_t drakvuf, drakvuf_trap_info* info, const apimon_module& module)
{
    // A .pdata page the process has not touched has no valid PTE, so it
    // cannot be read until the process uses it (an exception, a stack walk):
    // tried again then, not on every call meanwhile
    constexpr auto RETRY = std::chrono::seconds(1);
    // Larger than any system DLL's (ntdll's is under 100 KiB)
    constexpr size_t MAX_PDATA = 4 * 1024 * 1024;

    const auto key = std::make_pair(info->proc_data.pid, module.base);
    const auto now = std::chrono::steady_clock::now();
    {
        std::lock_guard<std::mutex> lock(this->unwind_mtx);
        if (auto it = this->unwind_tables.find(key); it != this->unwind_tables.end())
        {
            if (it->second.table || now - it->second.failed_at < RETRY)
                return it->second.table;
        }
    }

    auto read = [&]() -> std::shared_ptr<const std::vector<x64_unwind::runtime_function>>
    {
        ACCESS_CONTEXT(ctx,
            .translate_mechanism = VMI_TM_PROCESS_DTB,
            .dtb = info->regs->cr3,
            .addr = module.base
        );
        vmi_reader_guard vmi(drakvuf);

        constexpr int MAX_HEADER_BYTES = 1024;   // as userhook reads them
        uint8_t image[MAX_HEADER_BYTES];
        if (VMI_SUCCESS != peparse_get_image(vmi, &ctx, MAX_HEADER_BYTES, image))
            return nullptr;

        void* optional_header = nullptr;
        uint16_t magic = 0;
        peparse_assign_headers(image, NULL, NULL, &magic, &optional_header, NULL, NULL);
        if (magic != IMAGE_PE32_PLUS_MAGIC)
            return nullptr;
        const addr_t rva = peparse_get_idd_rva(IMAGE_DIRECTORY_ENTRY_EXCEPTION, &magic, optional_header, NULL, NULL);
        const size_t size = peparse_get_idd_size(IMAGE_DIRECTORY_ENTRY_EXCEPTION, &magic, optional_header, NULL, NULL);
        if (!rva || !size || rva >= module.size || size > module.size - rva || size > MAX_PDATA)
            return nullptr;

        std::vector<x64_unwind::runtime_function> table(size / sizeof(x64_unwind::runtime_function));
        const size_t length = table.size() * sizeof(x64_unwind::runtime_function);
        size_t got = 0;
        ctx.addr = module.base + rva;
        if (VMI_SUCCESS != vmi_read(vmi, &ctx, length, table.data(), &got) || got != length)
            return nullptr;
        return std::make_shared<const std::vector<x64_unwind::runtime_function>>(std::move(table));
    };

    auto table = read();
    std::lock_guard<std::mutex> lock(this->unwind_mtx);
    this->unwind_tables[key] = apimon_unwind_table{ table, now };
    return table;
}

/*
 * capemon's `caller` (hooking.c, set_caller_info): the first return address
 * on the stack outside the system DLLs -- the sample's code that made the
 * call, however many system DLLs it went through on the way. Memory no file
 * backs counts as the sample's, as it does for capemon.
 *
 * Found at the hook, before the function has run: the stack and the
 * registers are the caller's. A 32-bit process is followed along its EBP
 * frame chain; an x64 one is unwound with each system DLL's .pdata, as
 * RtlVirtualUnwind would (unwind.h). Where the stack cannot be followed --
 * unwind data not readable yet, a frame without a frame pointer -- the
 * return address itself, which is capemon's fallback too.
 */
addr_t apimon::find_caller(drakvuf_t drakvuf, drakvuf_trap_info* info, addr_t ret_addr)
{
    // Deeper than a call from the sample normally is: system code on its
    // own (a thread pool, the loader) goes to the stack's end without one
    constexpr unsigned MAX_FRAMES = 32;
    // A frame pointer beyond this from the hook's stack pointer is EBP used
    // as a general register (Windows' default stack reserve is 1 MiB)
    constexpr addr_t MAX_STACK = 16 * 1024 * 1024;

    const vmi_pid_t pid = info->proc_data.pid;
    const addr_t process = info->proc_data.base_addr;

    auto module = find_module(drakvuf, process, ret_addr, pid);
    if (!module || !module->system)
        return ret_addr;

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3
    );
    const x64_unwind::reader read = [&](uint64_t addr, void* buf, size_t size) -> bool
    {
        vmi_reader_guard vmi(drakvuf);
        ctx.addr = addr;
        size_t got = 0;
        return VMI_SUCCESS == vmi_read(vmi, &ctx, size, buf, &got) && got == size;
    };

    if (drakvuf_process_is32bit(drakvuf, info))
    {
        // [ebp] the caller's saved EBP, [ebp+4] its return address
        const uint32_t esp = info->regs->rsp;
        uint32_t floor = esp;
        uint32_t frame = info->regs->rbp;
        for (unsigned i = 0; i < MAX_FRAMES; ++i)
        {
            if (frame <= floor || frame - esp > MAX_STACK)
                break;
            uint32_t link[2];
            if (!read(frame, link, sizeof(link)) || !link[1])
                break;
            module = find_module(drakvuf, process, link[1], pid);
            if (!module || !module->system)
                return link[1];
            floor = frame;
            frame = link[0];
        }
        return ret_addr;
    }

    x64_unwind::context frame{};
    frame.rip = ret_addr;
    const auto* regs = info->regs;
    const uint64_t values[16] =
    {
        regs->rax, regs->rcx, regs->rdx, regs->rbx, regs->rsp + 8, regs->rbp, regs->rsi, regs->rdi,
        regs->r8, regs->r9, regs->r10, regs->r11, regs->r12, regs->r13, regs->r14, regs->r15
    };
    memcpy(frame.regs, values, sizeof(values));

    for (unsigned i = 0; i < MAX_FRAMES; ++i)
    {
        module = find_module(drakvuf, process, frame.rip, pid);
        if (!module || !module->system)
            return frame.rip;
        auto table = unwind_table(drakvuf, info, *module);
        if (!table)
            break;
        const auto* entry = x64_unwind::lookup(*table, frame.rip - module->base);
        if (!x64_unwind::step(read, module->base, entry, frame) || !frame.rip)
            break;
    }
    return ret_addr;
}

apimon::apimon(drakvuf_t drakvuf, const apimon_config* c, output_format_t output)
    : pluginex(drakvuf, output)
    , returns(*this, return_tracker_mode::user, "apimon return",
          [this](drakvuf_t drakvuf_, drakvuf_trap_info_t* info, apimon_call& call)
{
    // The return may come on another vCPU than the call: its reader instance
    // may hold translations of the address space older than the call's
    {
        vmi_reader_guard vmi(drakvuf_);
        vmi_v2pcache_flush(vmi, info->regs->cr3);
    }
    this->usermode_print(info, call, info->regs->rax);
},
// Like the hook callbacks, on several vCPU threads at once
true)
{
    if (!drakvuf_are_userhooks_supported(drakvuf))
    {
        PRINT_DEBUG("[APIMON] Usermode hooking not supported.\n");
        return;
    }

    try
    {
        auto noLog = [](const auto& entry)
        {
            return !entry.actions.log;
        };
        drakvuf_load_dll_hook_config(drakvuf, c->dll_hooks_list, c->print_no_addr, noLog, this->wanted_hooks);
    }
    catch (const std::runtime_error& exc)
    {
        std::cerr << "Loading DLL hook configuration for APIMON plugin failed\n"
            << "Reason: " << exc.what() << "\n";
        throw -1;
    }

    if (this->wanted_hooks.empty())
    {
        // don't load this plugin if there is nothing to do
        return;
    }

    usermode_cb_registration reg =
    {
        .pre_cb = on_dll_discovered,
        .post_cb = on_dll_hooked,
        .extra = (void*)this
    };
    drakvuf_register_usermode_callback(drakvuf, &reg);

    breakpoint_in_system_process_searcher bp;
    register_trap(nullptr, delete_process_cb, bp.for_syscall_name("PspProcessDelete"));
}

bool apimon::stop_impl()
{
    return drakvuf_stop_userhooks(drakvuf) && pluginex::stop_impl();
}

apimon::~apimon()
{

}
