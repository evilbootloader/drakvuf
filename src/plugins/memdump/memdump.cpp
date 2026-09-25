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
#include "linux.h"
#include "private.h"

#define DUMP_NAME_PLACEHOLDER "(not configured)"

static void save_file_metadata(const drakvuf_trap_info_t* info,
    const char* file_path,
    const char* data_file_name,
    size_t dump_size,
    addr_t dump_address,
    const char* method,
    const char* dump_reason,
    int sequence_number,
    extras_t* extras)
{
    char* file = NULL;
    if ( asprintf(&file, "%s.metadata", file_path) < 0 )
        return;

    FILE* fp = fopen(file, "w");
    free(file);
    if (!fp)
        return;

    json_object* jobj = json_object_new_object();
    json_object_object_add(jobj, "Method", json_object_new_string(method ? method : ""));
    json_object_object_add(jobj, "DumpReason", json_object_new_string(dump_reason ? dump_reason : ""));
    json_object_object_add(jobj, "DumpAddress", json_object_new_string_fmt("0x%" PRIx64, dump_address));
    json_object_object_add(jobj, "DumpSize", json_object_new_string_fmt("0x%" PRIx64, dump_size));
    json_object_object_add(jobj, "PID", json_object_new_int(info->attached_proc_data.pid));
    json_object_object_add(jobj, "PPID", json_object_new_int(info->attached_proc_data.ppid));
    json_object_object_add(jobj, "ProcessName", json_object_new_string(info->attached_proc_data.name ? info->attached_proc_data.name : ""));

    if (extras && extras->type == WriteVirtualMemoryExtras)
    {
        json_object_object_add(jobj, "TargetPID", json_object_new_int(extras->write_virtual_memory_extras.target_pid));
        json_object_object_add(jobj, "TargetProcessName", json_object_new_string(extras->write_virtual_memory_extras.target_name));
        json_object_object_add(jobj, "TargetBaseAddress", json_object_new_string_fmt("0x%" PRIx64, extras->write_virtual_memory_extras.base_address));
    }

    json_object_object_add(jobj, "DataFileName", json_object_new_string(data_file_name));
    json_object_object_add(jobj, "SequenceNumber", json_object_new_int(sequence_number));

    fprintf(fp, "%s\n", json_object_get_string(jobj));
    fclose(fp);

    json_object_put(jobj);
}

bool dump_memory_region(
    drakvuf_t drakvuf,
    vmi_instance_t vmi,
    drakvuf_trap_info_t* info,
    memdump* plugin,
    access_context_t* ctx,
    size_t len_bytes,
    const char* reason,
    extras_t* extras,
    bool print_extras)
{
    char* metafile = nullptr;
    char* file = nullptr;
    char* file_path = nullptr;
    char* tmp_file_path = nullptr;
    const char* display_file = nullptr;
    void** access_ptrs = nullptr;
    FILE* fp = nullptr;
    bool ret = false;

    const gchar* chk_str = nullptr;

    addr_t dump_addr = ctx->addr;
    addr_t aligned_addr;
    addr_t intra_page_offset;
    size_t num_pages;

    GChecksum* checksum = nullptr;

    size_t tmp_len_bytes = len_bytes;

    std::optional<fmt::Nval<decltype(extras->write_virtual_memory_extras.target_pid)>> target_pid;
    std::optional<fmt::Xval<decltype(extras->write_virtual_memory_extras.base_address)>> write_addr;

    int sequence_number = ++plugin->dumps_count;

    if (!plugin->memdump_dir)
    {
        ret = true;
        display_file = DUMP_NAME_PLACEHOLDER;
        goto printout;
    }

    aligned_addr = ctx->addr & ~(VMI_PS_4KB - 1);
    intra_page_offset = ctx->addr & (VMI_PS_4KB - 1);

    num_pages = (intra_page_offset + len_bytes + VMI_PS_4KB - 1) / VMI_PS_4KB;

    ctx->addr = aligned_addr;

    access_ptrs = (void**)g_malloc(num_pages * sizeof(void*));

    if (VMI_SUCCESS != vmi_mmap_guest(vmi, ctx, num_pages, PROT_READ, access_ptrs))
        goto done;

    checksum = g_checksum_new(G_CHECKSUM_SHA256);

    if (asprintf(&tmp_file_path, "%s/dump.tmp", plugin->memdump_dir) < 0)
        goto done;

    fp = fopen(tmp_file_path, "w");

    if (!fp)
        goto done;
    for (size_t i = 0; i < num_pages; i++)
    {
        size_t write_length = tmp_len_bytes;

        if (write_length > VMI_PS_4KB - intra_page_offset)
            write_length = VMI_PS_4KB - intra_page_offset;

        if (access_ptrs[i])
        {
            fwrite((char*)access_ptrs[i] + intra_page_offset, write_length, 1, fp);
            g_checksum_update(checksum, (const guchar*)access_ptrs[i] + intra_page_offset, write_length);
            munmap(access_ptrs[i], VMI_PS_4KB);
        }
        else
        {
            uint8_t zeros[VMI_PS_4KB] = {};
            fwrite(zeros + intra_page_offset, write_length, 1, fp);
            g_checksum_update(checksum, (const guchar*)zeros + intra_page_offset, write_length);
        }

        intra_page_offset = 0;
        tmp_len_bytes -= write_length;
    }

    fclose(fp);

    chk_str = g_checksum_get_string(checksum);

    // The file name format for the memory dump file is:
    // <dump base address>_<contents hash>
    // This was set in order to satisfy the following issues:
    // * when disassembling, it is required to know the dump's image base, here it could be obtained
    //   just by looking at the file name which is handy both for humans and automated processing
    // * de-duplication - sometimes, different heuristics may want to dump the same piece of memory;
    //   unless there is a change in image base or contents, repeated memory dumps would get exactly
    //   the same file name
    if (asprintf(&file, "%llx_%.16s", (unsigned long long) dump_addr, chk_str) < 0)
        goto done;

    if (asprintf(&file_path, "%s/%s", plugin->memdump_dir, file) < 0)
        goto done;

    display_file = (const char*)file;

    if (rename(tmp_file_path, file_path) != 0)
        goto done;

    if (asprintf(&metafile, "%s/memdump.%06d", plugin->memdump_dir, sequence_number) < 0)
        goto done;

    save_file_metadata(info, metafile, file, len_bytes, dump_addr, info->trap->name, reason, sequence_number, extras);

    ret = true;

printout:
    {
        auto default_print = std::make_tuple(
                keyval("DumpReason", fmt::Qstr(reason)),
                keyval("DumpPID", fmt::Nval(info->attached_proc_data.pid)),
                keyval("DumpAddr", fmt::Xval(dump_addr, false)),
                keyval("DumpSize", fmt::Xval(len_bytes)),
                keyval("DumpFilename", fmt::Qstr(display_file)),
                keyval("DumpsCount", fmt::Nval(sequence_number))
            );
        if (print_extras)
        {
            target_pid = fmt::Nval(extras->write_virtual_memory_extras.target_pid);
            write_addr = fmt::Xval(extras->write_virtual_memory_extras.base_address, false);
            auto extra_arguments = std::make_tuple(
                    keyval("TargetPID", target_pid),
                    keyval("WriteAddr", write_addr)
                );
            fmt::print(plugin->m_output_format, "memdump", drakvuf, info, default_print, extra_arguments);
        }
        else
        {
            fmt::print(plugin->m_output_format, "memdump", drakvuf, info, default_print);
        }
    }

done:
    free(file);
    free(file_path);
    free(tmp_file_path);
    free(metafile);
    g_free(access_ptrs);
    g_checksum_free(checksum);
    return ret;
}

bool is_kernel_addr(drakvuf_t drakvuf, addr_t addr)
{
    bool const is_os_64bit = (drakvuf_get_page_mode(drakvuf) == VMI_PM_IA32E);
    return is_os_64bit ? VMI_GET_BIT(addr, 47) : VMI_GET_BIT(addr, 31);
}

bool inspect_stack_ptr(drakvuf_t drakvuf, drakvuf_trap_info_t* info, memdump* plugin, bool is_32bit, addr_t stack_ptr)
{
    auto vmi = vmi_lock_guard(drakvuf);

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = stack_ptr
    );

    size_t bytes_read = 0;
    uint8_t buf[512];

    (void)vmi_read(vmi, &ctx, 512, buf, &bytes_read);

    size_t stack_width = is_32bit ? 4 : 8;
    for (size_t i = 0; i < bytes_read; i += stack_width)
    {
        uint64_t stack_val = 0;
        memcpy(&stack_val, buf+i, stack_width);

        mmvad_info_t mmvad;
        if (!drakvuf_find_mmvad(drakvuf, info->attached_proc_data.base_addr, stack_val, &mmvad))
            continue;

        addr_t begin = mmvad.starting_vpn << 12;
        size_t len = (mmvad.ending_vpn - mmvad.starting_vpn + 1) << 12;

        page_info_t p_info = {};

        if (vmi_pagetable_lookup_extended(vmi, info->regs->cr3, stack_val, &p_info) != VMI_SUCCESS)
            continue;

        bool page_valid = (p_info.x86_ia32e.pte_value & (1UL << 0)) != 0;
        bool page_execute = (p_info.x86_ia32e.pte_value & (1UL << 63)) == 0;

        if (page_valid && page_execute && mmvad.file_name_ptr)
        {
            sptr_type_t res = check_module_linked(drakvuf, vmi, plugin, info, mmvad.starting_vpn << 12);

            if (res == ERROR)
            {
                PRINT_DEBUG("[MEMDUMP] Something is corrupted\n");
                continue;
            }

            if (res == LINKED)
            {
                PRINT_DEBUG("[MEMDUMP] Linked stack entry %llx\n", (unsigned long long) stack_val);
                continue;
            }
            else if (res == UNLINKED)
            {
                PRINT_DEBUG("[MEMDUMP] UNLINKED stack entry %llx\n", (unsigned long long) stack_val);
            }
            else if (res == MAIN)
            {
                PRINT_DEBUG("[MEMDUMP] MAIN stack entry %llx\n", (unsigned long long) stack_val);
            }
        }

        if (page_valid && page_execute)
        {
            PRINT_DEBUG("[MEMDUMP] VX stack entry %llx\n", (unsigned long long) stack_val);

            ctx.addr = begin;

            if (!dump_memory_region(drakvuf, vmi, info, plugin, &ctx, len, "Stack heuristic",
                    nullptr, false))
            {
                PRINT_DEBUG("[MEMDUMP] Failed to save memory dump - internal error\n");
            }

            break;
        }
    }

    PRINT_DEBUG("[MEMDUMP] Done stack walk\n");

    return VMI_EVENT_RESPONSE_NONE;
}

bool dump_from_stack(drakvuf_t drakvuf, drakvuf_trap_info_t* info, memdump* plugin)
{
    bool is_32bit = drakvuf_process_is32bit(drakvuf, info);
    addr_t stack_ptr;
    addr_t frame_ptr;

    if (is_kernel_addr(drakvuf, info->regs->rip))
    {
        bool result = false;
        if (is_32bit)
        {
            result = drakvuf_get_user_stack32(drakvuf, info, &stack_ptr, &frame_ptr);
        }
        else
        {
            result = drakvuf_get_user_stack64(drakvuf, info, &stack_ptr);
        }
        if (!result)
        {
            PRINT_DEBUG("[MEMDUMP] Failed to get stack pointer\n");
            return VMI_EVENT_RESPONSE_NONE;
        }
    }
    else
    {
        stack_ptr = info->regs->rsp;
    }

    PRINT_DEBUG("[MEMDUMP] Got stack pointer: %llx\n", (unsigned long long)stack_ptr);
    return inspect_stack_ptr(drakvuf, info, plugin, is_32bit, stack_ptr);
}

bool dotnet_assembly_native_load_image_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info, memdump* plugin)
{
    const auto ptr_size = drakvuf_get_process_address_width(drakvuf, info);

    auto vmi = vmi_lock_guard(drakvuf);
    vmi_v2pcache_flush(vmi, info->regs->cr3);

    addr_t addr = drakvuf_get_function_argument_ex(drakvuf, info, 1, CALLING_CONV_FASTCALL) + ptr_size;

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = addr
    );

    addr_t data_size = 0;
    if (vmi_read(vmi, &ctx, ptr_size, &data_size, nullptr) != VMI_SUCCESS)
    {
        PRINT_DEBUG("[MEMDUMP.NET] failed to read size of dump from memory.");
        return false;
    }

    PRINT_DEBUG("[MEMDUMP.NET] dumping assembly from memory (size = %lu)\n", data_size);

    ctx.addr += ptr_size;

    if (!dump_memory_region(drakvuf, vmi, info, plugin, &ctx, data_size, ".NET AssemblyNative::LoadImage", nullptr, false))
    {
        PRINT_DEBUG("[MEMDUMP] Failed to store memory dump due to an internal error\n");
        return false;
    }

    return true;
}

void memdump::setup_usermode_dotnet_hooks(const memdump_config* c)
{
    if (c->clr_profile)
        this->setup_dotnet_hooks("clr.dll", c->clr_profile, true);
    else
        PRINT_DEBUG("clr.dll 32 profile not found, memdump will proceed without some .NET hooks\n");

    if (c->clr_profile_64)
        this->setup_dotnet_hooks("clr.dll", c->clr_profile_64, false);
    else
        PRINT_DEBUG("clr.dll 64 profile not found, memdump will proceed without some .NET hooks\n");

    if (c->mscorwks_profile)
        this->setup_dotnet_hooks("mscorwks.dll", c->mscorwks_profile, true);
    else
        PRINT_DEBUG("mscorwks.dll profile not found, memdump will proceed without some .NET hooks\n");
}

memdump::memdump(drakvuf_t drakvuf, const memdump_config* c, output_format_t output)
    : pluginex(drakvuf, output)
    , dumps_count()
    , memdump_dir(c->memdump_dir)
    , dll_base_rva(0)
    , dll_base_wow_rva(0)
{
    auto os = drakvuf_get_os_type(drakvuf);
    PRINT_DEBUG("[MEMDUMP] Initializing memdump, OS type: %d\n", os);
    if (os == VMI_OS_WINDOWS)
    {
        PRINT_DEBUG("[MEMDUMP] Creating Windows memdump\n");
        this->wm = std::make_unique<win_memdump>(drakvuf, c, output, this);
        // Copy RVAs for stack_util.cpp compatibility
        this->dll_base_rva = this->wm->dll_base_rva;
        this->dll_base_wow_rva = this->wm->dll_base_wow_rva;
    }
    else
    {
        PRINT_DEBUG("[MEMDUMP] Creating Linux memdump\n");
        this->lm = std::make_unique<linux_memdump>(drakvuf, c, output, this);
    }
    PRINT_DEBUG("[MEMDUMP] Memdump initialization complete\n");
}

memdump::~memdump()
{
    userhook_destroy();
}

bool memdump::stop_impl()
{
    return this->userhooks_stop() && pluginex::stop_impl();
}
