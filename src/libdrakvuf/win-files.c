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

#include <libvmi/libvmi.h>

#include "win.h"
#include "private.h"
#include "win-offsets.h"

// CSHORT Type, the first member of the I/O manager's structures
#define IO_TYPE_DEVICE 3
#define IO_TYPE_FILE 5

// Object directories from a device up to the root: \Device\HarddiskVolume2
// has one, \Device\Harddisk0\DR0 two
#define OBJECT_PATH_MAX_DEPTH 8

/*
 * The device a FILE_OBJECT was opened on, by its path in the object
 * namespace: "\Device\HarddiskVolume2", "\Device\NamedPipe". As
 * ObQueryNameString builds it: the name in each object's
 * _OBJECT_HEADER_NAME_INFO, then that of the Directory it is in, up to
 * ObpRootDirectoryObject.
 *
 * NULL unless every step is what it should be -- `file` is a FILE_OBJECT, its
 * DeviceObject a DEVICE_OBJECT, and the directories end at the root: a handle
 * to anything else is read here as well, and a guess would be printed as a
 * path.
 */
static char* win_get_file_device_path(drakvuf_t drakvuf, addr_t file)
{
    vmi_instance_t vmi = drakvuf_vmi(drakvuf);

    if (!drakvuf->ob_root_directory || !drakvuf->offsets[FILEOBJECT_DEVICEOBJECT])
        return NULL;

    uint16_t type = 0;
    if (VMI_SUCCESS != vmi_read_16_va(vmi, file, 0, &type) || type != IO_TYPE_FILE)
        return NULL;

    addr_t object = 0;
    if (VMI_SUCCESS != vmi_read_addr_va(vmi, file + drakvuf->offsets[FILEOBJECT_DEVICEOBJECT], 0, &object) || !object)
        return NULL;

    if (VMI_SUCCESS != vmi_read_16_va(vmi, object, 0, &type) || type != IO_TYPE_DEVICE)
        return NULL;

    GString* path = g_string_new(NULL);
    for (int depth = 0; depth < OBJECT_PATH_MAX_DEPTH; depth++)
    {
        addr_t name_info = win_get_object_name_info(drakvuf, object);
        if (!name_info)
            break;

        addr_t directory = 0;
        if (VMI_SUCCESS != vmi_read_addr_va(vmi, name_info + drakvuf->offsets[OBJECT_HEADER_NAME_INFO_DIRECTORY], 0, &directory) || !directory)
            break;

        unicode_string_t* name = drakvuf_read_unicode_va(drakvuf, name_info + drakvuf->offsets[OBJECT_HEADER_NAME_INFO_NAME], 0);
        if (!name || !name->contents || !name->contents[0])
        {
            if (name)
                vmi_free_unicode_str(name);
            break;
        }
        g_string_prepend(path, (const char*)name->contents);
        g_string_prepend(path, "\\");
        vmi_free_unicode_str(name);

        if (directory == drakvuf->ob_root_directory)
            return g_string_free(path, FALSE);
        object = directory;
    }

    g_string_free(path, TRUE);
    return NULL;
}

char* win_get_filename_from_handle(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t handle)
{
    addr_t process = drakvuf_get_current_process(drakvuf, info);
    if (!process) return NULL;

    addr_t obj = drakvuf_get_obj_by_handle(drakvuf, process, handle);
    if (!obj) return NULL;

    addr_t file = obj + drakvuf->offsets[OBJECT_HEADER_BODY];
    unicode_string_t* us = drakvuf_read_unicode(drakvuf, info, file + drakvuf->offsets[FILEOBJECT_NAME]);
    if (!us) return NULL;

    char* filename = (char*)us->contents;
    us->contents = NULL;
    vmi_free_unicode_str(us);

    // FileName is the path on the volume, "\Users\x\a.tmp": the same file
    // named by a path argument has its drive. With the device it is the name
    // the kernel keeps for a process's image, "\Device\HarddiskVolume2\...".
    // A name relative to another file object (no leading backslash: it was
    // opened with a RootDirectory) is not a path on the device, and stays.
    if (filename && (!filename[0] || filename[0] == '\\'))
    {
        char* device = win_get_file_device_path(drakvuf, file);
        if (device)
        {
            char* full = g_strconcat(device, filename, NULL);
            g_free(device);
            g_free(filename);
            filename = full;
        }
    }

    return filename;
}

char* win_get_filename_from_object_attributes(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t attrs)
{
    vmi_instance_t vmi = drakvuf_vmi(drakvuf);

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3
    );

    addr_t file_root_handle = 0;
    ctx.addr = attrs + drakvuf->offsets[OBJECT_ATTRIBUTES_ROOTDIRECTORY];
    if (VMI_SUCCESS != vmi_read_addr(vmi, &ctx, &file_root_handle))
        return NULL;

    ctx.addr = attrs + drakvuf->offsets[OBJECT_ATTRIBUTES_OBJECTNAME];
    addr_t file_name_addr = 0;
    if (VMI_SUCCESS != vmi_read_addr(vmi, &ctx, &file_name_addr))
        return NULL;

    char* file_root = drakvuf_get_filename_from_handle(drakvuf, info, file_root_handle);
    unicode_string_t* file_name_us = drakvuf_read_unicode(drakvuf, info, file_name_addr);

    if (!file_name_us)
    {
        g_free(file_root);
        return NULL;
    }

    char* file_path = g_strdup_printf("%s%s%s",
            file_root ?: "",
            file_root ? "\\" : "",
            file_name_us->contents);

    vmi_free_unicode_str(file_name_us);
    g_free(file_root);

    return file_path;
}
