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

// After private.h, whose enum socket_family names the AF_* constants these define as macros
#include <arpa/inet.h>

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
    iter_snapshot iter = snapshot_message(drakvuf, info, drakvuf_get_function_argument(drakvuf, info, 2));
    if (!iter.valid)
        return {};
    if (ret_size)
        *ret_size = iter.count;
    return read_message(drakvuf, info, iter, std::min(iter.count, this->print_max_size));
}

iter_snapshot unixsocketmon::snapshot_message(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t msghdr)
{
    iter_snapshot out;
    if (!this->have_message || !msghdr)
        return out;

    addr_t iter = msghdr + this->msghdr_msg_iter;
    auto vmi = vmi_lock_guard(drakvuf);
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3
    );
    ctx.addr = iter + this->iov_iter_type;
    if (VMI_FAILURE == vmi_read_8(vmi, &ctx, &out.type))
        return out;
    ctx.addr = iter + this->iov_iter_count;
    if (VMI_FAILURE == vmi_read_64(vmi, &ctx, &out.count))
        return out;
    ctx.addr = iter + this->iov_iter_iov;
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &out.ptr))
        return out;
    if (out.type != this->iter_ubuf)
    {
        ctx.addr = iter + this->iov_iter_nr_segs;
        if (VMI_FAILURE == vmi_read_64(vmi, &ctx, &out.nr_segs))
            out.nr_segs = 0;
    }
    out.valid = true;
    return out;
}

std::vector<uint8_t> unixsocketmon::read_message(drakvuf_t drakvuf, drakvuf_trap_info_t* info, const iter_snapshot& iter, uint64_t wanted)
{
    const uint8_t type = iter.type;
    const addr_t ptr = iter.ptr;

    auto vmi = vmi_lock_guard(drakvuf);
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3
    );
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

    for (uint64_t i = 0; i < iter.nr_segs && i < MAX_SEGMENTS && data.size() < wanted; i++)
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

/*
 * struct sock_common begins with two anonymous unions the JSON profile does
 * not name: the address pair (skc_daddr, skc_rcv_saddr) at 0 and, after the
 * 4-byte hash, the port pair (skc_dport in network order, skc_num in host
 * order) at 12. That layout has not changed since 2.6; it is trusted only
 * when the named skc_family sits where it puts it, at 16, and struct sock
 * starts with its sock_common.
 */
#define SKC_DADDR       0
#define SKC_RCV_SADDR   4
#define SKC_DPORT       12
#define SKC_NUM         14
#define SKC_FAMILY      16
#define UNIX_PATH_MAX   108

std::vector<std::pair<std::string, socket_endpoints::value_t>> socket_endpoints::keyvals() const
{
    std::vector<std::pair<std::string, value_t>> out;
    if (!protocol.empty())
        out.emplace_back("Protocol", fmt::Estr(protocol));
    if (!local_ip.empty())
        out.emplace_back("LocalIp", fmt::Estr(local_ip));
    if (local_port >= 0)
        out.emplace_back("LocalPort", fmt::Nval(local_port));
    if (!remote_ip.empty())
        out.emplace_back("RemoteIp", fmt::Estr(remote_ip));
    if (remote_port >= 0)
        out.emplace_back("RemotePort", fmt::Nval(remote_port));
    // An unnamed end has no path, and no key: an empty string prints as "(null)"
    if (!local_path.empty())
        out.emplace_back("LocalPath", fmt::Estr(local_path));
    if (!remote_path.empty())
        out.emplace_back("RemotePath", fmt::Estr(remote_path));
    if (connected >= 0)
        out.emplace_back("Connected", fmt::Nval(connected));
    return out;
}

static std::string ip_string(int family, const void* addr)
{
    char buf[INET6_ADDRSTRLEN] = {0};
    if (!inet_ntop(family, addr, buf, sizeof(buf)))
        return {};
    return buf;
}

static std::string protocol_string(uint16_t protocol)
{
    switch (protocol)
    {
        case IPPROTO_TCP:
            return "TCP";
        case IPPROTO_UDP:
            return "UDP";
        case IPPROTO_ICMP:
            return "ICMP";
        case IPPROTO_ICMPV6:
            return "ICMPv6";
        default:
            return std::to_string(protocol);
    }
}

/*
 * sun_path as a string. A pathname ends at its NUL: connect() is commonly
 * given the whole sizeof(struct sockaddr_un), with whatever was on the stack
 * after it. An abstract name starts with a NUL and is exactly as long as the
 * address says, NULs included, which are printed as '@' like ss(8) does.
 */
static std::string unix_path_string(const uint8_t* path, size_t len)
{
    if (!len)
        return {};
    if (path[0] != 0)
        return std::string((const char*)path, strnlen((const char*)path, len));
    std::string out = "@";
    for (size_t i = 1; i < len; i++)
        out += path[i] ? (char)path[i] : '@';
    return out;
}

std::string unixsocketmon::read_unix_path(vmi_instance_t vmi, access_context_t* ctx, addr_t unix_sock)
{
    addr_t address = 0;
    ctx->addr = unix_sock + this->unix_sock_addr;
    if (VMI_FAILURE == vmi_read_addr(vmi, ctx, &address) || !address)
        return {};
    int32_t len = 0;
    ctx->addr = address + this->unix_address_len;
    if (VMI_FAILURE == vmi_read_32(vmi, ctx, (uint32_t*)&len) || len <= (int32_t)sizeof(uint16_t))
        return {};
    uint8_t path[UNIX_PATH_MAX] = {0};
    size_t n = std::min<size_t>(len - sizeof(uint16_t), UNIX_PATH_MAX);
    size_t bytes_read = 0;
    ctx->addr = address + this->unix_address_name + sizeof(uint16_t);
    vmi_read(vmi, ctx, n, path, &bytes_read);
    return unix_path_string(path, bytes_read);
}

void unixsocketmon::read_sockaddr(vmi_instance_t vmi, access_context_t* ctx, addr_t addr, uint32_t len, socket_endpoints& ep)
{
    uint8_t buf[sizeof(uint16_t) + UNIX_PATH_MAX] = {0};
    size_t bytes_read = 0;
    ctx->addr = addr;
    if (VMI_FAILURE == vmi_read(vmi, ctx, std::min<size_t>(len, sizeof(buf)), buf, &bytes_read) || bytes_read < 2)
        return;
    uint16_t family = 0;
    memcpy(&family, buf, sizeof(family));
    uint16_t port = 0;
    memcpy(&port, buf + 2, sizeof(port));
    if (family == AF_INET && bytes_read >= 8)
    {
        ep.remote_ip = ip_string(AF_INET, buf + 4);
        ep.remote_port = ntohs(port);
    }
    else if (family == AF_INET6 && bytes_read >= 24)
    {
        ep.remote_ip = ip_string(AF_INET6, buf + 8);
        ep.remote_port = ntohs(port);
    }
    else if (family == AF_LOCAL)
        ep.remote_path = unix_path_string(buf + 2, bytes_read - 2);
}

socket_endpoints unixsocketmon::read_endpoints(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t socket, uint32_t family)
{
    addr_t sk = 0;
    {
        auto vmi = vmi_lock_guard(drakvuf);
        ACCESS_CONTEXT(ctx,
            .translate_mechanism = VMI_TM_PROCESS_DTB,
            .dtb = info->regs->cr3,
            .addr = socket + this->socket_sk
        );
        if (!this->have_inet && !this->have_unix)
            return {};
        if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &sk) || !sk)
            return {};
    }
    return read_endpoints_sk(drakvuf, info, sk, family);
}

socket_endpoints unixsocketmon::read_endpoints_sk(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t sk, uint32_t family)
{
    socket_endpoints ep;
    bool inet = family == AF_INET || family == AF_INET6;
    if (!(inet && this->have_inet) && !(family == AF_LOCAL && this->have_unix))
        return ep;

    auto vmi = vmi_lock_guard(drakvuf);
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3
    );

    if (family == AF_LOCAL)
    {
        // struct unix_sock begins with its struct sock
        ep.unix_socket = true;
        ep.local_path = read_unix_path(vmi, &ctx, sk);
        addr_t peer = 0;
        ctx.addr = sk + this->unix_sock_peer;
        if (VMI_SUCCESS == vmi_read_addr(vmi, &ctx, &peer))
        {
            ep.connected = peer != 0;
            if (peer)
                ep.remote_path = read_unix_path(vmi, &ctx, peer);
        }
        return ep;
    }

    ep.inet = true;
    uint16_t protocol = 0;
    ctx.addr = sk + this->sock_protocol;
    if (VMI_SUCCESS == vmi_read_16(vmi, &ctx, &protocol))
        ep.protocol = protocol_string(protocol);

    uint16_t dport = 0, num = 0;
    ctx.addr = sk + SKC_DPORT;
    vmi_read_16(vmi, &ctx, &dport);
    ctx.addr = sk + SKC_NUM;
    vmi_read_16(vmi, &ctx, &num);
    ep.local_port = num;

    uint8_t remote[16] = {0}, local[16] = {0};
    size_t len = family == AF_INET ? 4 : 16;
    size_t bytes_read = 0;
    ctx.addr = sk + (family == AF_INET ? SKC_DADDR : this->skc_v6_daddr);
    vmi_read(vmi, &ctx, len, remote, &bytes_read);
    ctx.addr = sk + (family == AF_INET ? SKC_RCV_SADDR : this->skc_v6_rcv_saddr);
    vmi_read(vmi, &ctx, len, local, &bytes_read);

    bool has_peer = dport != 0 || std::any_of(remote, remote + len, [](uint8_t c) { return c != 0; });
    ep.connected = has_peer;
    ep.local_ip = ip_string(family, local);
    if (has_peer)
    {
        ep.remote_ip = ip_string(family, remote);
        ep.remote_port = ntohs(dport);
    }
    return ep;
}

event_response_t unixsocketmon::sock_send_msg_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    uint32_t family_type;
    if (!get_socket_family_type(drakvuf, info, &family_type))
        return VMI_EVENT_RESPONSE_NONE;
    uint64_t size = 0;
    auto message = get_socket_message(drakvuf, info, &size);

    addr_t sock = drakvuf_get_function_argument(drakvuf, info, 1);
    socket_endpoints ep = read_endpoints(drakvuf, info, sock, family_type);
    // An unconnected socket names its destination per message (sendto)
    if ((ep.inet || ep.unix_socket) && ep.connected != 1 && this->have_msg_name)
    {
        addr_t msghdr = drakvuf_get_function_argument(drakvuf, info, 2);
        auto vmi = vmi_lock_guard(drakvuf);
        ACCESS_CONTEXT(ctx,
            .translate_mechanism = VMI_TM_PROCESS_DTB,
            .dtb = info->regs->cr3
        );
        addr_t name = 0;
        uint32_t namelen = 0;
        ctx.addr = msghdr + this->msghdr_msg_name;
        if (VMI_SUCCESS == vmi_read_addr(vmi, &ctx, &name) && name)
        {
            ctx.addr = msghdr + this->msghdr_msg_namelen;
            if (VMI_SUCCESS == vmi_read_32(vmi, &ctx, &namelen) && namelen)
                read_sockaddr(vmi, &ctx, name, namelen, ep);
        }
    }

    print_message(drakvuf, info, family_type, ep, size, message);
    return VMI_EVENT_RESPONSE_NONE;
}

// A message's record, sent or received: its endpoints, size and first
// print_max_size bytes, as text when they are, else as a binary string
void unixsocketmon::print_message(drakvuf_t drakvuf, drakvuf_trap_info_t* info, uint32_t family,
    const socket_endpoints& ep, uint64_t size, const std::vector<uint8_t>& message)
{
    auto socket_family_str = socket_family_to_str((socket_family_t)family);
    unicode_string_t msg =
    {
        .length = message.size(),
        .contents = const_cast<uint8_t*>(message.data()),
        .encoding = "UTF-8"
    };

    unicode_string_t out{};
    status_t rc = vmi_convert_str_encoding(&msg, &out, "UTF-8");

    if (VMI_FAILURE == rc || !is_printable_string(message))
    {
        fmt::print(this->m_output_format, "unixsocketmon", drakvuf, info,
            keyval("Type", fmt::Rstr(socket_family_str)),
            ep.keyvals(),
            keyval("Size", fmt::Nval(size)),
            keyval("Value", fmt::BinaryString(message.data(), message.size()))
        );
    }
    else
    {
        fmt::print(this->m_output_format, "unixsocketmon", drakvuf, info,
            keyval("Type", fmt::Rstr(socket_family_str)),
            ep.keyvals(),
            keyval("Size", fmt::Nval(size)),
            keyval("Value", fmt::Estr(reinterpret_cast<char*>(out.contents)))
        );
    }

    g_free(out.contents);
}

/*
 * int security_socket_connect(struct socket *sock, struct sockaddr *address, int addrlen)
 *
 * Every connect() passes here with the destination copied into the kernel,
 * before the protocol starts connecting. The result is the syscall's, in its
 * sysret record; the local end is in the sends that follow, once bound.
 */
event_response_t unixsocketmon::connect_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    uint32_t family_type;
    if (!get_socket_family_type(drakvuf, info, &family_type))
        return VMI_EVENT_RESPONSE_NONE;
    if (family_type != AF_INET && family_type != AF_INET6 && family_type != AF_LOCAL)
        return VMI_EVENT_RESPONSE_NONE;

    addr_t sock = drakvuf_get_function_argument(drakvuf, info, 1);
    addr_t address = drakvuf_get_function_argument(drakvuf, info, 2);
    uint32_t addrlen = (uint32_t)drakvuf_get_function_argument(drakvuf, info, 3);

    socket_endpoints ep = read_endpoints(drakvuf, info, sock, family_type);
    ep.remote_ip.clear();
    ep.remote_port = -1;
    ep.remote_path.clear();
    ep.connected = -1;
    // Not bound yet, as for most connects: the local end is chosen by the connect
    if (ep.local_port == 0)
    {
        ep.local_ip.clear();
        ep.local_port = -1;
    }
    {
        auto vmi = vmi_lock_guard(drakvuf);
        ACCESS_CONTEXT(ctx,
            .translate_mechanism = VMI_TM_PROCESS_DTB,
            .dtb = info->regs->cr3
        );
        if (address && addrlen)
            read_sockaddr(vmi, &ctx, address, addrlen, ep);
    }

    fmt::print(this->m_output_format, "unixsocketmon", drakvuf, info,
        keyval("Type", fmt::Rstr(socket_family_to_str((socket_family_t)family_type))),
        ep.keyvals()
    );
    return VMI_EVENT_RESPONSE_NONE;
}

/*
 * int security_socket_bind(struct socket *sock, struct sockaddr *address, int addrlen)
 *
 * The address the socket is about to be bound to, copied into the kernel:
 * its local end, which a listening socket keeps. A port 0 is the kernel's to
 * choose, and is printed as 0.
 */
event_response_t unixsocketmon::bind_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    uint32_t family_type;
    if (!get_socket_family_type(drakvuf, info, &family_type))
        return VMI_EVENT_RESPONSE_NONE;
    if (family_type != AF_INET && family_type != AF_INET6 && family_type != AF_LOCAL)
        return VMI_EVENT_RESPONSE_NONE;

    addr_t sock = drakvuf_get_function_argument(drakvuf, info, 1);
    addr_t address = drakvuf_get_function_argument(drakvuf, info, 2);
    uint32_t addrlen = (uint32_t)drakvuf_get_function_argument(drakvuf, info, 3);

    // The protocol, from the socket; the address, from the call
    socket_endpoints ep = read_endpoints(drakvuf, info, sock, family_type);
    socket_endpoints bound;
    {
        auto vmi = vmi_lock_guard(drakvuf);
        ACCESS_CONTEXT(ctx,
            .translate_mechanism = VMI_TM_PROCESS_DTB,
            .dtb = info->regs->cr3
        );
        if (address && addrlen)
            read_sockaddr(vmi, &ctx, address, addrlen, bound);
    }
    ep.local_ip = bound.remote_ip;
    ep.local_port = bound.remote_port;
    ep.local_path = bound.remote_path;
    ep.remote_ip.clear();
    ep.remote_port = -1;
    ep.remote_path.clear();
    ep.connected = -1;

    fmt::print(this->m_output_format, "unixsocketmon", drakvuf, info,
        keyval("Type", fmt::Rstr(socket_family_to_str((socket_family_t)family_type))),
        ep.keyvals()
    );
    return VMI_EVENT_RESPONSE_NONE;
}

/*
 * int security_socket_listen(struct socket *sock, int backlog)
 *
 * The socket is bound by now (an unbound one is bound to an ephemeral port
 * first): its local end is the one connections will come to.
 */
event_response_t unixsocketmon::listen_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    uint32_t family_type;
    if (!get_socket_family_type(drakvuf, info, &family_type))
        return VMI_EVENT_RESPONSE_NONE;
    if (family_type != AF_INET && family_type != AF_INET6 && family_type != AF_LOCAL)
        return VMI_EVENT_RESPONSE_NONE;

    addr_t sock = drakvuf_get_function_argument(drakvuf, info, 1);
    int backlog = (int)drakvuf_get_function_argument(drakvuf, info, 2);
    socket_endpoints ep = read_endpoints(drakvuf, info, sock, family_type);
    ep.remote_ip.clear();
    ep.remote_port = -1;
    ep.remote_path.clear();
    ep.connected = -1;

    fmt::print(this->m_output_format, "unixsocketmon", drakvuf, info,
        keyval("Type", fmt::Rstr(socket_family_to_str((socket_family_t)family_type))),
        ep.keyvals(),
        keyval("Backlog", fmt::Nval(backlog))
    );
    return VMI_EVENT_RESPONSE_NONE;
}

/*
 * void security_sock_graft(struct sock *sk, struct socket *parent)
 *
 * An accepted connection joined to the socket accept() returns: inet_accept
 * and unix_accept (sock_graft) call it once the connection exists, so its
 * struct sock has both ends -- what security_socket_accept, called before
 * any connection is taken, cannot know.
 */
event_response_t unixsocketmon::graft_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    // The family from the struct sock itself: trusted only where
    // find_endpoint_layout found sock_common where it expects it
    if (!this->have_inet)
        return VMI_EVENT_RESPONSE_NONE;
    addr_t sk = drakvuf_get_function_argument(drakvuf, info, 1);
    uint16_t family = 0;
    {
        auto vmi = vmi_lock_guard(drakvuf);
        ACCESS_CONTEXT(ctx,
            .translate_mechanism = VMI_TM_PROCESS_DTB,
            .dtb = info->regs->cr3,
            .addr = sk + SKC_FAMILY
        );
        if (!sk || VMI_FAILURE == vmi_read_16(vmi, &ctx, &family))
            return VMI_EVENT_RESPONSE_NONE;
    }
    if (family != AF_INET && family != AF_INET6 && family != AF_LOCAL)
        return VMI_EVENT_RESPONSE_NONE;

    socket_endpoints ep = read_endpoints_sk(drakvuf, info, sk, family);
    fmt::print(this->m_output_format, "unixsocketmon", drakvuf, info,
        keyval("Type", fmt::Rstr(socket_family_to_str((socket_family_t)family))),
        ep.keyvals()
    );
    return VMI_EVENT_RESPONSE_NONE;
}

/*
 * int inet_recvmsg(struct socket *sock, struct msghdr *msg, size_t size, int flags)
 * and the same for inet6, unix stream and unix datagram sockets
 *
 * The protocols' own recvmsg, called through sock->ops: not inlined, as
 * sock_recvmsg is into its callers. The bytes exist only at the return,
 * where the message's iterator has moved past them: where they go is taken
 * here, and read there.
 */
event_response_t unixsocketmon::recvmsg_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    uint32_t family_type;
    if (!get_socket_family_type(drakvuf, info, &family_type))
        return VMI_EVENT_RESPONSE_NONE;
    if (family_type != AF_INET && family_type != AF_INET6 && family_type != AF_LOCAL)
        return VMI_EVENT_RESPONSE_NONE;

    addr_t sock = drakvuf_get_function_argument(drakvuf, info, 1);
    addr_t msghdr = drakvuf_get_function_argument(drakvuf, info, 2);

    auto hook = this->createReturnHook<recvmsg_result>(info, &unixsocketmon::recvmsg_ret_cb, "sock_recvmsg");
    if (!hook)
        return VMI_EVENT_RESPONSE_NONE;
    auto params = libhook::GetTrapParams<recvmsg_result>(hook->trap_);
    params->family = family_type;
    params->ep = read_endpoints(drakvuf, info, sock, family_type);
    params->iter = snapshot_message(drakvuf, info, msghdr);
    params->msghdr = msghdr;
    this->ret_hooks[make_hook_id(info, params->target_rsp)] = std::move(hook);
    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t unixsocketmon::recvmsg_ret_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto params = libhook::GetTrapParams<recvmsg_result>(info);
    if (!params->verifyResultCallParams(drakvuf, info))
        return VMI_EVENT_RESPONSE_NONE;

    // An int: the bytes received, or -errno
    const int received = (int)info->regs->rax;
    if (received > 0)
    {
        socket_endpoints ep = params->ep;
        // An unconnected socket learns the sender per message (recvfrom)
        if ((ep.inet || ep.unix_socket) && ep.connected != 1 && this->have_msg_name && params->msghdr)
        {
            auto vmi = vmi_lock_guard(drakvuf);
            ACCESS_CONTEXT(ctx,
                .translate_mechanism = VMI_TM_PROCESS_DTB,
                .dtb = info->regs->cr3
            );
            addr_t name = 0;
            uint32_t namelen = 0;
            ctx.addr = params->msghdr + this->msghdr_msg_name;
            if (VMI_SUCCESS == vmi_read_addr(vmi, &ctx, &name) && name)
            {
                ctx.addr = params->msghdr + this->msghdr_msg_namelen;
                if (VMI_SUCCESS == vmi_read_32(vmi, &ctx, &namelen) && namelen)
                    read_sockaddr(vmi, &ctx, name, namelen, ep);
            }
        }
        std::vector<uint8_t> message;
        if (params->iter.valid)
            message = read_message(drakvuf, info, params->iter, std::min<uint64_t>(received, this->print_max_size));
        print_message(drakvuf, info, params->family, ep, received, message);
    }

    this->ret_hooks.erase(make_hook_id(info, params->target_rsp));
    return VMI_EVENT_RESPONSE_NONE;
}

void unixsocketmon::find_endpoint_layout(drakvuf_t drakvuf)
{
    addr_t family = 0, common = 0;
    bool have_sk = drakvuf_get_kernel_struct_member_rva(drakvuf, "socket", "sk", &socket_sk);
    this->have_inet = have_sk
        && drakvuf_get_kernel_struct_member_rva(drakvuf, "sock", "sk_protocol", &sock_protocol)
        && drakvuf_get_kernel_struct_member_rva(drakvuf, "sock", "__sk_common", &common) && common == 0
        && drakvuf_get_kernel_struct_member_rva(drakvuf, "sock_common", "skc_family", &family) && family == SKC_FAMILY
        && drakvuf_get_kernel_struct_member_rva(drakvuf, "sock_common", "skc_v6_daddr", &skc_v6_daddr)
        && drakvuf_get_kernel_struct_member_rva(drakvuf, "sock_common", "skc_v6_rcv_saddr", &skc_v6_rcv_saddr);
    this->have_unix = have_sk
        && drakvuf_get_kernel_struct_member_rva(drakvuf, "unix_sock", "addr", &unix_sock_addr)
        && drakvuf_get_kernel_struct_member_rva(drakvuf, "unix_sock", "peer", &unix_sock_peer)
        && drakvuf_get_kernel_struct_member_rva(drakvuf, "unix_address", "len", &unix_address_len)
        && drakvuf_get_kernel_struct_member_rva(drakvuf, "unix_address", "name", &unix_address_name);
    this->have_msg_name = drakvuf_get_kernel_struct_member_rva(drakvuf, "msghdr", "msg_name", &msghdr_msg_name)
        && drakvuf_get_kernel_struct_member_rva(drakvuf, "msghdr", "msg_namelen", &msghdr_msg_namelen);
    if (!this->have_inet)
        fprintf(stderr, "[UNIXSOCKETMON] Cannot read struct sock from this profile, IP sockets have no addresses\n");
    if (!this->have_unix)
        fprintf(stderr, "[UNIXSOCKETMON] Cannot read struct unix_sock from this profile, Unix sockets have no paths\n");
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
    this->find_endpoint_layout(drakvuf);

    // The same reason as security_socket_sendmsg below: __sys_connect_file is inlined into __sys_connect
    connecthook = createSyscallHook("security_socket_connect", &unixsocketmon::connect_cb, "connect");
    if (!connecthook)
        fprintf(stderr, "[UNIXSOCKETMON] Failed to hook security_socket_connect, connects are not recorded\n");

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

    // The rest of a socket's life, for what the syscall plugin would have:
    // where it is bound and listens, what it accepts, what it receives.
    // LSM hooks for the same reason as above; the receives in the protocols.
    bindhook = createSyscallHook("security_socket_bind", &unixsocketmon::bind_cb, "bind");
    listenhook = createSyscallHook("security_socket_listen", &unixsocketmon::listen_cb, "listen");
    accepthook = createSyscallHook("security_sock_graft", &unixsocketmon::graft_cb, "accept");
    if (!bindhook || !listenhook || !accepthook)
        fprintf(stderr, "[UNIXSOCKETMON] Failed to hook security_socket_bind/listen or security_sock_graft, "
            "binds, listens or accepts are not recorded\n");
    for (const char* recv : { "inet_recvmsg", "inet6_recvmsg", "unix_stream_recvmsg", "unix_dgram_recvmsg" })
    {
        if (auto hook = createSyscallHook(recv, &unixsocketmon::recvmsg_cb, "sock_recvmsg"))
            recvhooks.push_back(std::move(hook));
        else
            fprintf(stderr, "[UNIXSOCKETMON] Failed to hook %s, its receives are not recorded\n", recv);
    }
}