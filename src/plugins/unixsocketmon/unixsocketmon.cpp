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

#include <libdrakvuf/libdrakvuf.h>
#include <libvmi/libvmi.h>

#include "unixsocketmon.h"
#include "private.h"
#include "plugins/output_format.h"

static bool is_printable_string(const std::vector<uint8_t>& message)
{
    if (message.empty() || message.front() == 0x00)
        return false;

    // symbol codes from 0x00 to 0x1f excluding \t, \r, \n
    std::vector<uint8_t> unprintable
    {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0b,
        0x0c, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
        0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    auto it = std::find_first_of(message.begin(), message.end(), unprintable.begin(), unprintable.end());

    // termination zeroes check
    return std::all_of(it, message.end(), [](uint8_t i)
    {
        return i == 0x00;
    });
}

bool unixsocketmon::get_socket_family_type(drakvuf_t drakvuf, drakvuf_trap_info_t* info, uint32_t* family_type)
{
    addr_t sock = drakvuf_get_function_argument(drakvuf, info, 1);

    auto vmi = vmi_lock_guard(drakvuf);
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = sock + this->socket_ops
    );

    addr_t ops;
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &ops))
    {
        PRINT_DEBUG("[UNIXSOCKETMON] Failed to read proto_ops from socket struct\n");
        return false;
    }

    ctx.addr = ops + this->proto_ops_family;
    if (VMI_FAILURE == vmi_read_32(vmi, &ctx, family_type))
    {
        PRINT_DEBUG("[UNIXSOCKETMON] Failed to get socket family type\n");
        return false;
    }

    return true;
}

// Segments read from one message, beyond which the payload is cut even under the size limit
#define MAX_SEGMENTS 64

/*
 * The message's size is the iterator's count, which covers every segment: a
 * sendmsg() with several buffers, as D-Bus sends, is one request. Its first
 * print_max_size bytes are read across the segments, from an array of iovecs
 * or kvecs, or from the single user buffer of an ITER_UBUF (6.x kernels).
 * Other iterator types (pages, pipes) have a size and no payload here.
 */
std::vector<uint8_t> unixsocketmon::get_socket_message(drakvuf_t drakvuf, drakvuf_trap_info_t* info, uint64_t* ret_size)
{
    if (!this->have_message)
        return {};

    addr_t iter = drakvuf_get_function_argument(drakvuf, info, 2) + this->msghdr_msg_iter;

    auto vmi = vmi_lock_guard(drakvuf);
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3
    );

    uint8_t type = 0;
    uint64_t count = 0;
    addr_t ptr = 0;
    ctx.addr = iter + this->iov_iter_type;
    if (VMI_FAILURE == vmi_read_8(vmi, &ctx, &type))
        return {};
    ctx.addr = iter + this->iov_iter_count;
    if (VMI_FAILURE == vmi_read_64(vmi, &ctx, &count))
        return {};
    ctx.addr = iter + this->iov_iter_iov;
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &ptr))
        return {};
    if (ret_size)
        *ret_size = count;

    uint64_t wanted = std::min(count, this->print_max_size);
    std::vector<uint8_t> data;
    auto append = [&](addr_t buf, uint64_t len) -> bool
    {
        size_t old = data.size();
        data.resize(old + len);
        size_t bytes_read = 0;
        ctx.addr = buf;
        vmi_read(vmi, &ctx, len, data.data() + old, &bytes_read);
        data.resize(old + bytes_read);
        return bytes_read == len;
    };

    if (wanted == 0)
        return data;

    if (type == this->iter_ubuf)
    {
        append(ptr, wanted);
        return data;
    }
    if (type != this->iter_iovec && type != this->iter_kvec)
        return data;

    uint64_t nr_segs = 0;
    ctx.addr = iter + this->iov_iter_nr_segs;
    if (VMI_FAILURE == vmi_read_64(vmi, &ctx, &nr_segs))
        return data;

    for (uint64_t i = 0; i < nr_segs && i < MAX_SEGMENTS && data.size() < wanted; i++)
    {
        addr_t seg = ptr + i * this->iovec_size;
        addr_t base = 0;
        uint64_t len = 0;
        ctx.addr = seg + this->iovec_iov_base;
        if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &base))
            break;
        ctx.addr = seg + this->iovec_iov_len;
        if (VMI_FAILURE == vmi_read_64(vmi, &ctx, &len))
            break;
        if (len && !append(base, std::min(len, wanted - data.size())))
            break;
    }
    return data;
}

event_response_t unixsocketmon::sock_send_msg_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    uint32_t family_type;
    if (!get_socket_family_type(drakvuf, info, &family_type))
        return VMI_EVENT_RESPONSE_NONE;
    auto socket_family_str = socket_family_to_str((socket_family_t)family_type);

    uint64_t size = 0;
    auto message = get_socket_message(drakvuf, info, &size);

    unicode_string_t msg =
    {
        .length = message.size(),
        .contents = message.data(),
        .encoding = "UTF-8"
    };

    unicode_string_t out;
    status_t rc = vmi_convert_str_encoding(&msg, &out, "UTF-8");

    if (VMI_FAILURE == rc || !is_printable_string(message))
    {
        fmt::print(this->m_output_format, "unixsocketmon", drakvuf, info,
            keyval("Type", fmt::Rstr(socket_family_str)),
            keyval("Size", fmt::Nval(size)),
            keyval("Value", fmt::BinaryString(message.data(), message.size()))
        );
    }
    else
    {
        fmt::print(this->m_output_format, "unixsocketmon", drakvuf, info,
            keyval("Type", fmt::Rstr(socket_family_str)),
            keyval("Size", fmt::Nval(size)),
            keyval("Value", fmt::Estr(reinterpret_cast<char*>(out.contents)))
        );
    }

    g_free(out.contents);

    return VMI_EVENT_RESPONSE_NONE;
}

// A constant of an enum in the kernel's JSON profile
static bool kernel_enum_value(drakvuf_t drakvuf, const char* enum_name, const char* constant, int64_t* value)
{
    auto vmi = vmi_lock_guard(drakvuf);
    json_object* profile = vmi_get_kernel_json(vmi);
    json_object* enums = nullptr;
    json_object* type = nullptr;
    json_object* constants = nullptr;
    json_object* found = nullptr;
    if (!profile
        || !json_object_object_get_ex(profile, "enums", &enums)
        || !json_object_object_get_ex(enums, enum_name, &type)
        || !json_object_object_get_ex(type, "constants", &constants)
        || !json_object_object_get_ex(constants, constant, &found))
        return false;
    *value = json_object_get_int64(found);
    return true;
}

/*
 * Where struct iov_iter keeps its count and its buffers. The pointer to the
 * buffers is in an anonymous union, which dwarf2json names only
 * "unnamed_field_N", so it is found from the members around it:
 *   5.x  iter_type, ..., iov_offset, count, union { iov, kvec, ... }, union { nr_segs, ... }
 *   6.x  iter_type, ..., iov_offset, union { ..., struct { union { __iov, kvec, ..., ubuf }, count } }, union { nr_segs, ... }
 * A profile that names the pointer (`iov`, `__iov`) is taken at its word.
 */
bool unixsocketmon::find_iov_iter_layout(drakvuf_t drakvuf)
{
    addr_t iov_offset = 0;
    if (!drakvuf_get_kernel_struct_member_rva(drakvuf, "iov_iter", "iter_type", &iov_iter_type)
        || !drakvuf_get_kernel_struct_member_rva(drakvuf, "iov_iter", "iov_offset", &iov_offset))
        return false;

    if (drakvuf_get_kernel_struct_member_rva(drakvuf, "iov_iter", "count", &iov_iter_count))
        iov_iter_iov = iov_iter_count + sizeof(uint64_t);
    else
    {
        iov_iter_iov = iov_offset + sizeof(uint64_t);
        iov_iter_count = iov_iter_iov + sizeof(addr_t);
    }
    addr_t named = 0;
    if (drakvuf_get_kernel_struct_member_rva(drakvuf, "iov_iter", "iov", &named)
        || drakvuf_get_kernel_struct_member_rva(drakvuf, "iov_iter", "__iov", &named))
        iov_iter_iov = named;
    if (!drakvuf_get_kernel_struct_member_rva(drakvuf, "iov_iter", "nr_segs", &iov_iter_nr_segs))
        iov_iter_nr_segs = std::max(iov_iter_iov, iov_iter_count) + sizeof(uint64_t);

    // Their values differ between kernels: ITER_IOVEC is 0 on 5.15 and 1 on 6.x, where ITER_UBUF is 0
    kernel_enum_value(drakvuf, "iter_type", "ITER_IOVEC", &iter_iovec);
    kernel_enum_value(drakvuf, "iter_type", "ITER_KVEC", &iter_kvec);
    kernel_enum_value(drakvuf, "iter_type", "ITER_UBUF", &iter_ubuf);
    if (iter_iovec < 0 && iter_kvec < 0 && iter_ubuf < 0)
        return false;

    size_t size = 0;
    if (drakvuf_get_kernel_struct_size(drakvuf, "iovec", &size) && size)
        iovec_size = size;
    return drakvuf_get_kernel_struct_member_rva(drakvuf, "iovec", "iov_base", &iovec_iov_base)
        && drakvuf_get_kernel_struct_member_rva(drakvuf, "iovec", "iov_len", &iovec_iov_len);
}

/*
 * The family is required: without it there is nothing to print. The message
 * is not: a profile this cannot read the iterator from still gets one record
 * per message, without size or payload. Either failure is said on stderr --
 * printed only to the debug log, the iterator lookup failed silently on
 * Ubuntu 22.04's kernel and the plugin hooked nothing at all.
 */
unixsocketmon::unixsocketmon(drakvuf_t drakvuf, const unixsocketmon_config* config, output_format_t output)
    :pluginex(drakvuf, output), print_max_size{config->print_max_size}
{
    if (!drakvuf_get_kernel_struct_member_rva(drakvuf, "socket", "ops", &socket_ops)
        || !drakvuf_get_kernel_struct_member_rva(drakvuf, "proto_ops", "family", &proto_ops_family))
    {
        fprintf(stderr, "[UNIXSOCKETMON] The kernel profile lacks socket.ops or proto_ops.family, not hooking\n");
        return;
    }

    this->have_message = drakvuf_get_kernel_struct_member_rva(drakvuf, "msghdr", "msg_iter", &msghdr_msg_iter)
        && this->find_iov_iter_layout(drakvuf);
    if (!this->have_message)
        fprintf(stderr, "[UNIXSOCKETMON] Cannot read struct iov_iter from this profile, messages have no size or payload\n");

    /*
     * Not sock_sendmsg itself: net/socket.c inlines it into __sys_sendto,
     * ____sys_sendmsg and sock_write_iter, so a breakpoint on the exported
     * copy saw no send at all on Ubuntu 22.04's 5.15 kernel. The LSM hook it
     * calls first is in another file, takes the same socket and message,
     * and runs for every send. A kernel built without LSM hooks has no such
     * function, and there sock_sendmsg is the next best place.
     */
    sockethook = createSyscallHook("security_socket_sendmsg", &unixsocketmon::sock_send_msg_cb, "sock_sendmsg");
    if (!sockethook)
        sockethook = createSyscallHook("sock_sendmsg", &unixsocketmon::sock_send_msg_cb);
    if (!sockethook)
        fprintf(stderr, "[UNIXSOCKETMON] Failed to hook security_socket_sendmsg and sock_sendmsg\n");
}