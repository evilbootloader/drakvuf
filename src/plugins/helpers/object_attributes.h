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
#pragma once

/*
 * What an OBJECT_ATTRIBUTES argument names, and the name CAPE's monitor
 * (capemon) logs it under: shared by apimon, which reads it in the calling
 * process, and the syscalls plugin, which reads it at the kernel's entry.
 *
 * The object is a file only for the file services. For a key the root is a
 * key handle, for a mutant, event or section usually the \BaseNamedObjects
 * directory: reading either as a FILE_OBJECT, as
 * drakvuf_get_filename_from_object_attributes does for every root, reads
 * another structure at FILE_OBJECT's offsets.
 */

#include <cstdint>
#include <cstring>
#include <optional>
#include <string>

#include <glib.h>
#include <libdrakvuf/libdrakvuf.h>

#include "plugins/helpers/vmi_lock_guard.h"

struct object_attributes_name
{
    const char* label;
    std::string name;
};

namespace object_attributes_detail
{

enum class root_kind
{
    file,   // RootDirectory is a file or directory handle, joined to the name
    key,    // a key handle, joined to the name
    none,   // the name alone, as the caller gave it (capemon's unistr_from_objattr)
};

struct entry
{
    const char* name;
    const char* label;
    root_kind root;
};

// The `ObjectAttributes` argument, by service without its Nt/Zw prefix.
// capemon logs the name as FileName/PipeName/MutexName/EventName, and in
// place of ObjectAttributes everywhere else; `Key` is regmon's and apimon's
// name for a key's full path, which the postprocessing turns into FullName.
inline const entry services[] =
{
    { "CreateFile", "FileName", root_kind::file },
    { "OpenFile", "FileName", root_kind::file },
    { "DeleteFile", "FileName", root_kind::file },
    { "QueryAttributesFile", "FileName", root_kind::file },
    { "QueryFullAttributesFile", "FileName", root_kind::file },
    { "CreateNamedPipeFile", "PipeName", root_kind::file },
    { "CreateMailslotFile", "MailslotName", root_kind::file },
    { "CreateKey", "Key", root_kind::key },
    { "CreateKeyTransacted", "Key", root_kind::key },
    { "OpenKey", "Key", root_kind::key },
    { "OpenKeyEx", "Key", root_kind::key },
    { "OpenKeyTransacted", "Key", root_kind::key },
    { "OpenKeyTransactedEx", "Key", root_kind::key },
    { "CreateMutant", "MutexName", root_kind::none },
    { "OpenMutant", "MutexName", root_kind::none },
    { "CreateEvent", "EventName", root_kind::none },
    { "OpenEvent", "EventName", root_kind::none },
};

// OBJECT_ATTRIBUTES arguments under another name (the syscalls table's)
inline const entry arguments[] =
{
    { "TargetKey", "TargetKeyName", root_kind::key },
    { "SourceFile", "SourceFileName", root_kind::file },
    { "NewFile", "NewFileName", root_kind::file },
    { "OldFile", "OldFileName", root_kind::file },
};

inline entry lookup(const char* service, const char* argument)
{
    if (strcmp(argument, "ObjectAttributes"))
    {
        for (const auto& e : arguments)
            if (!strcmp(e.name, argument))
                return e;
        return { argument, "ObjectName", root_kind::none };
    }

    if (!strncmp(service, "Nt", 2) || !strncmp(service, "Zw", 2))
        service += 2;
    for (const auto& e : services)
        if (!strcmp(e.name, service))
            return e;
    return { service, "ObjectName", root_kind::none };
}

} // namespace object_attributes_detail

/*
 * The object named by `attrs`, an OBJECT_ATTRIBUTES pointer passed to
 * `service` as `argument`, or nothing when it names none (a NULL ObjectName,
 * as process and thread services pass).
 *
 * `is32`: the structure's layout -- the calling process's bitness in user
 * mode, the kernel's at a syscall (WoW64 hands the kernel 64-bit structures).
 */
inline std::optional<object_attributes_name> read_object_attributes(
    drakvuf_t drakvuf, drakvuf_trap_info_t* info,
    const char* service, const char* argument, addr_t attrs, bool is32)
{
    using namespace object_attributes_detail;

    if (!attrs)
        return {};

    // ULONG Length; HANDLE RootDirectory; PUNICODE_STRING ObjectName; ...
    addr_t root = 0;
    addr_t name_ptr = 0;
    {
        vmi_reader_guard vmi(drakvuf);
        ACCESS_CONTEXT(ctx,
            .translate_mechanism = VMI_TM_PROCESS_DTB,
            .dtb = info->regs->cr3
        );
        auto read_ptr = [&](addr_t offset, addr_t& value) -> bool
        {
            ctx.addr = attrs + offset;
            if (!is32)
                return VMI_SUCCESS == vmi_read_64(vmi, &ctx, &value);
            uint32_t value32 = 0;
            if (VMI_SUCCESS != vmi_read_32(vmi, &ctx, &value32))
                return false;
            value = value32;
            return true;
        };
        if (!read_ptr(is32 ? 8 : 16, name_ptr) || !name_ptr)
            return {};
        if (!read_ptr(is32 ? 4 : 8, root))
            root = 0;
    }

    unicode_string_t* us = is32
        ? drakvuf_read_unicode32(drakvuf, info, name_ptr)
        : drakvuf_read_unicode(drakvuf, info, name_ptr);
    if (!us)
        return {};
    std::string name = us->contents ? (const char*)us->contents : "";
    vmi_free_unicode_str(us);
    if (name.empty())
        return {};

    const entry e = lookup(service, argument);

    char* root_path = nullptr;
    if (root && e.root == root_kind::file)
        root_path = drakvuf_get_filename_from_handle(drakvuf, info, root);
    else if (root && e.root == root_kind::key)
        root_path = drakvuf_reg_keyhandle_path(drakvuf, info, root);
    if (root_path)
    {
        if (*root_path)
            name = std::string(root_path) + "\\" + name;
        g_free(root_path);
    }

    return object_attributes_name{ e.label, std::move(name) };
}
