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

#include "printers.hpp"
#include "utils.hpp"
#include <algorithm>
#include <array>
#include <string>
#include <sstream>
#include <iomanip>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <libvmi/libvmi.h>
#include <libdrakvuf/libdrakvuf.h>
#include "plugins/plugins.h"

ArgumentPrinter::ArgumentPrinter(std::string arg_name, PrinterConfig config) :
    config(config), name(arg_name)
{
    // intentionally empty
}

std::string ArgumentPrinter::get_name() const
{
    return name;
}

std::string ArgumentPrinter::print(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t argument) const
{
    std::stringstream stream;
    stream << name << "=";
    if (config.numeric_format == PrinterConfig::NumericFormat::HEX)
        stream << "0x" << std::hex;
    stream << argument;
    return stream.str();
}

ArgumentPrinter::~ArgumentPrinter() {}

NarrowIntegerPrinter::NarrowIntegerPrinter(std::string arg_name, unsigned bits, PrinterConfig config) :
    ArgumentPrinter(std::move(arg_name), config), bits(bits)
{
    // intentionally empty
}

std::string NarrowIntegerPrinter::print(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t argument) const
{
    return ArgumentPrinter::print(drakvuf, info, value(drakvuf, info, argument));
}

uint64_t NarrowIntegerPrinter::value(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t argument) const
{
    return argument & ((1ULL << bits) - 1);
}

std::string StringPrinterInterface::print(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t argument) const
{
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = argument
    );
    std::string str = getBuffer(drakvuf, &ctx);
    std::stringstream stream;
    stream << name << "=";
    if (!config.print_no_addr)
        stream << "0x" << std::hex << argument << ":";
    stream << "\"" << escape_str(str) << "\"";
    return stream.str();
}

std::string AsciiPrinter::getBuffer(drakvuf_t drakvuf, const access_context_t* ctx) const
{
    vmi_reader_guard vmi(drakvuf);
    char* str = vmi_read_str(vmi, ctx);
    std::string ret = str ? str : "";
    g_free(str);
    return ret;
}

std::string WideStringPrinter::getBuffer(drakvuf_t drakvuf, const access_context_t* ctx) const
{
    vmi_reader_guard vmi(drakvuf);
    auto str_obj = drakvuf_read_wchar_string(drakvuf, ctx);
    std::string ret = str_obj == NULL ? "" : (char*)str_obj->contents;
    if (str_obj)
        vmi_free_unicode_str(str_obj);
    return ret;
}

std::string Binary16StringPrinter::print(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t argument) const
{
    vmi_reader_guard vmi(drakvuf);
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = argument
    );
    std::stringstream stream;
    stream << name << "=";
    if (!config.print_no_addr)
        stream << "0x" << std::hex << argument << ":";
    stream << "\"";
    const size_t BUF_SIZE = 16;
    std::array<uint8_t, BUF_SIZE> buffer;
    if (VMI_SUCCESS == vmi_read(vmi, &ctx, 16, buffer.data(), nullptr))
    {
        for (auto i: buffer)
            stream << std::setw(2) << std::setfill('0') << (int)i;
    }
    stream << "\"";
    return stream.str();
}

std::string UnicodePrinter::print(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t argument) const
{
    bool is32bit = drakvuf_process_is32bit(drakvuf, info);

    unicode_string_t* str_us = is32bit ? drakvuf_read_unicode32(drakvuf, info, argument)
        : drakvuf_read_unicode(drakvuf, info, argument);

    std::string str = str_us ? (char*)str_us->contents : "";
    if (str_us)
        vmi_free_unicode_str(str_us);

    std::stringstream stream;
    stream << name << "=";
    if (!config.print_no_addr)
        stream << "0x" << std::hex << argument << ":";
    stream << "\"" << escape_str(str) << "\"";
    return stream.str();
}

std::string AnsiStringPrinter::print(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t argument) const
{
    if (!argument)
        return ArgumentPrinter::print(drakvuf, info, argument);

    const bool is32bit = drakvuf_process_is32bit(drakvuf, info);
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = argument
    );
    uint8_t header[16] = {};
    size_t got = 0;
    uint16_t length = 0;
    uint64_t buffer = 0;
    std::string str;
    {
        vmi_reader_guard vmi(drakvuf);
        vmi_read(vmi, &ctx, is32bit ? 8 : 16, header, &got);
        if (!parse_ansi_string(header, got, is32bit, &length, &buffer) || !buffer)
            return ArgumentPrinter::print(drakvuf, info, argument);

        // Length counts bytes and no terminator. What precedes an unmapped
        // page is printed.
        str.resize(std::min<size_t>(length, MAX_BYTES));
        got = 0;
        ctx.addr = buffer;
        if (!str.empty())
            vmi_read(vmi, &ctx, str.size(), str.data(), &got);
        str.resize(got);
    }

    std::stringstream stream;
    stream << name << "=";
    if (!config.print_no_addr)
        stream << "0x" << std::hex << argument << ":";
    stream << "\"" << escape_str(str) << "\"";
    return stream.str();
}

std::string UlongPrinter::print(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t argument) const
{
    return ArgumentPrinter::print(drakvuf, info, value(drakvuf, info, argument));
}

uint64_t UlongPrinter::value(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t argument) const
{
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = argument
    );
    vmi_reader_guard vmi(drakvuf);
    uint32_t value;
    if (vmi_read_32(vmi, &ctx, &value) != VMI_SUCCESS)
        value = 0;
    return value;
}

std::string UlongLongPrinter::print(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t argument) const
{
    return ArgumentPrinter::print(drakvuf, info, value(drakvuf, info, argument));
}

uint64_t UlongLongPrinter::value(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t argument) const
{
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = argument
    );
    vmi_reader_guard vmi(drakvuf);
    uint64_t value;
    if (vmi_read_64(vmi, &ctx, &value) != VMI_SUCCESS)
        value = 0;
    return value;
}

std::string SockaddrPrinter::print(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t argument) const
{
    if (!argument)
        return ArgumentPrinter::print(drakvuf, info, argument);

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = argument
    );
    // The largest decoded: sockaddr_un, a family and a 108-byte path. What
    // precedes an unmapped page is still read, and enough for a short one.
    uint8_t buf[2 + 108] = {};
    size_t got = 0;
    {
        vmi_reader_guard vmi(drakvuf);
        vmi_read(vmi, &ctx, sizeof(buf), buf, &got);
    }

    auto text = format_sockaddr(buf, got, drakvuf_get_os_type(drakvuf) == VMI_OS_LINUX);
    if (!text)
        return ArgumentPrinter::print(drakvuf, info, argument);

    std::stringstream stream;
    stream << name << "=";
    if (!config.print_no_addr)
        stream << "0x" << std::hex << argument << ":";
    stream << "\"" << escape_str(*text) << "\"";
    return stream.str();
}

std::string PointerToSockaddrPrinter::print(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t argument) const
{
    if (!argument)
        return ArgumentPrinter::print(drakvuf, info, argument);

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = argument
    );
    addr_t sockaddr = 0;
    if (drakvuf_read_addr(drakvuf, info, &ctx, &sockaddr) != VMI_SUCCESS || !sockaddr)
        return ArgumentPrinter::print(drakvuf, info, argument);
    return SockaddrPrinter::print(drakvuf, info, sockaddr);
}

std::string PointerToPointerPrinter::print(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t argument) const
{
    return ArgumentPrinter::print(drakvuf, info, value(drakvuf, info, argument));
}

uint64_t PointerToPointerPrinter::value(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t argument) const
{
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = argument
    );

    addr_t value = 0;
    int ret = drakvuf_read_addr(drakvuf, info, &ctx, &value);
    if (ret != VMI_SUCCESS)
        value = 0;
    return value;
}

// -- buffers and the structures signatures read through -----------------------

BufferPrinter::BufferPrinter(std::string arg_name, std::string length_name, bool output, PrinterConfig config) :
    ArgumentPrinter(std::move(arg_name), config), length_name(std::move(length_name)), output(output)
{
    // intentionally empty
}

std::string BufferPrinter::print_bytes(const std::string& name, const PrinterConfig& config, uint64_t argument,
    const uint8_t* data, size_t size)
{
    std::stringstream stream;
    stream << name << "=";
    if (!config.print_no_addr)
        stream << "0x" << std::hex << argument << ":";
    stream << "\"" << escape_bytes(data, size) << "\"";
    return stream.str();
}

std::string BufferPrinter::print_sized(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t argument, uint64_t length) const
{
    if (!argument)
        return ArgumentPrinter::print(drakvuf, info, argument);
    std::vector<uint8_t> data(std::min<uint64_t>(length, MAX_BYTES));
    size_t got = 0;
    if (!data.empty())
    {
        ACCESS_CONTEXT(ctx,
            .translate_mechanism = VMI_TM_PROCESS_DTB,
            .dtb = info->regs->cr3,
            .addr = argument
        );
        vmi_reader_guard vmi(drakvuf);
        // What precedes an unmapped page is printed: a partial buffer
        vmi_read(vmi, &ctx, data.size(), data.data(), &got);
    }
    return print_bytes(name, config, argument, data.data(), got);
}

std::string WsaBufPrinter::print(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t argument) const
{
    if (!argument)
        return ArgumentPrinter::print(drakvuf, info, argument);

    // WSABUF { ULONG len; CHAR* buf; }: the pointer at 4 or 8
    const bool is32 = drakvuf_process_is32bit(drakvuf, info);
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = argument
    );
    uint32_t len = 0;
    addr_t buf = 0;
    {
        vmi_reader_guard vmi(drakvuf);
        if (vmi_read_32(vmi, &ctx, &len) != VMI_SUCCESS)
            return ArgumentPrinter::print(drakvuf, info, argument);
    }
    ctx.addr = argument + (is32 ? 4 : 8);
    if (drakvuf_read_addr(drakvuf, info, &ctx, &buf) != VMI_SUCCESS || !buf)
        return ArgumentPrinter::print(drakvuf, info, argument);

    std::vector<uint8_t> data(std::min<uint64_t>(len, BufferPrinter::MAX_BYTES));
    size_t got = 0;
    if (!data.empty())
    {
        ctx.addr = buf;
        vmi_reader_guard vmi(drakvuf);
        vmi_read(vmi, &ctx, data.size(), data.data(), &got);
    }
    return BufferPrinter::print_bytes(name, config, argument, data.data(), got);
}

std::string SecBufferDescPrinter::print(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t argument) const
{
    if (!argument)
        return ArgumentPrinter::print(drakvuf, info, argument);

    // SecBufferDesc { ULONG ulVersion; ULONG cBuffers; PSecBuffer pBuffers; }
    // SecBuffer { ULONG cbBuffer; ULONG BufferType; PVOID pvBuffer; }: the
    // pointers at 8 on both widths, a SecBuffer 12 bytes on 32-bit, 16 on 64
    const bool is32 = drakvuf_process_is32bit(drakvuf, info);
    const size_t secbuffer_size = is32 ? 12 : 16;
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = argument + 4
    );
    uint32_t count = 0;
    {
        vmi_reader_guard vmi(drakvuf);
        if (vmi_read_32(vmi, &ctx, &count) != VMI_SUCCESS)
            return ArgumentPrinter::print(drakvuf, info, argument);
    }
    addr_t buffers = 0;
    ctx.addr = argument + 8;
    if (drakvuf_read_addr(drakvuf, info, &ctx, &buffers) != VMI_SUCCESS || !buffers)
        return ArgumentPrinter::print(drakvuf, info, argument);

    for (uint32_t i = 0; i < std::min(count, MAX_BUFFERS); ++i)
    {
        const addr_t entry = buffers + i * secbuffer_size;
        uint32_t header[2] = {};    // cbBuffer, BufferType
        size_t got = 0;
        ctx.addr = entry;
        {
            vmi_reader_guard vmi(drakvuf);
            if (vmi_read(vmi, &ctx, sizeof(header), header, &got) != VMI_SUCCESS || got != sizeof(header))
                break;
        }
        if ((header[1] & ~SECBUFFER_ATTRMASK) != SECBUFFER_DATA)
            continue;

        addr_t data_addr = 0;
        ctx.addr = entry + 8;
        if (drakvuf_read_addr(drakvuf, info, &ctx, &data_addr) != VMI_SUCCESS || !data_addr)
            break;
        std::vector<uint8_t> data(std::min<uint64_t>(header[0], BufferPrinter::MAX_BYTES));
        got = 0;
        if (!data.empty())
        {
            ctx.addr = data_addr;
            vmi_reader_guard vmi(drakvuf);
            vmi_read(vmi, &ctx, data.size(), data.data(), &got);
        }
        return BufferPrinter::print_bytes(name, config, argument, data.data(), got);
    }
    return ArgumentPrinter::print(drakvuf, info, argument);
}

std::string ClientIdPrinter::print(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t argument) const
{
    if (!argument)
        return ArgumentPrinter::print(drakvuf, info, argument);

    // CLIENT_ID { HANDLE UniqueProcess; HANDLE UniqueThread; }
    const size_t width = drakvuf_get_process_address_width(drakvuf, info);
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = argument
    );
    addr_t pid = 0, tid = 0;
    if (drakvuf_read_addr(drakvuf, info, &ctx, &pid) != VMI_SUCCESS)
        return ArgumentPrinter::print(drakvuf, info, argument);
    ctx.addr = argument + width;
    if (drakvuf_read_addr(drakvuf, info, &ctx, &tid) != VMI_SUCCESS)
        tid = 0;

    std::stringstream stream;
    stream << name << "=";
    if (!config.print_no_addr)
        stream << "0x" << std::hex << argument << ":";
    stream << "\"" << std::dec << pid << ":" << tid << "\"";
    return stream.str();
}

std::string LargeIntegerPrinter::print(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t argument) const
{
    if (!argument)
        return ArgumentPrinter::print(drakvuf, info, argument);

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = argument
    );
    uint64_t value = 0;
    {
        vmi_reader_guard vmi(drakvuf);
        if (vmi_read_64(vmi, &ctx, &value) != VMI_SUCCESS)
            return ArgumentPrinter::print(drakvuf, info, argument);
    }
    std::stringstream stream;
    stream << name << "=";
    if (!config.print_no_addr)
        stream << "0x" << std::hex << argument << ":";
    stream << "\"" << std::dec << static_cast<int64_t>(value) << "\"";
    return stream.str();
}

namespace
{

// Reads of one call's process memory, at its pointer width
struct process_reader
{
    drakvuf_t drakvuf;
    drakvuf_trap_info* info;
    bool is32;

    bool ptr(addr_t addr, addr_t& value) const
    {
        ACCESS_CONTEXT(ctx,
            .translate_mechanism = VMI_TM_PROCESS_DTB,
            .dtb = info->regs->cr3,
            .addr = addr
        );
        value = 0;
        return VMI_SUCCESS == drakvuf_read_addr(drakvuf, info, &ctx, &value);
    }
    size_t bytes(addr_t addr, void* buf, size_t size) const
    {
        ACCESS_CONTEXT(ctx,
            .translate_mechanism = VMI_TM_PROCESS_DTB,
            .dtb = info->regs->cr3,
            .addr = addr
        );
        size_t got = 0;
        vmi_reader_guard vmi(drakvuf);
        vmi_read(vmi, &ctx, size, buf, &got);
        return got;
    }
};

// Lists walked at most: a resolver's answers, an argv
constexpr unsigned MAX_NODES = 32;
constexpr unsigned MAX_ARGV = 64;
constexpr size_t MAX_ARGV_TEXT = 4096;

std::string quoted(const std::string& name, const PrinterConfig& config, uint64_t argument, const std::string& text)
{
    std::stringstream stream;
    stream << name << "=";
    if (!config.print_no_addr)
        stream << "0x" << std::hex << argument << ":";
    stream << "\"" << escape_str(text) << "\"";
    return stream.str();
}

// "203.0.113.7:443" -> "203.0.113.7", "[2001:db8::1]:0" -> "2001:db8::1"
std::string address_only(const std::string& endpoint)
{
    auto colon = endpoint.rfind(':');
    std::string ip = colon == std::string::npos ? endpoint : endpoint.substr(0, colon);
    if (ip.size() > 1 && ip.front() == '[' && ip.back() == ']')
        ip = ip.substr(1, ip.size() - 2);
    return ip;
}

void add_unique(std::vector<std::string>& list, const std::string& value)
{
    if (!value.empty() && std::find(list.begin(), list.end(), value) == list.end())
        list.push_back(value);
}

std::string joined(const std::vector<std::string>& list, const char* separator)
{
    std::string out;
    for (const auto& item : list)
        out += (out.empty() ? "" : separator) + item;
    return out;
}

} // namespace

AddrinfoPrinter::AddrinfoPrinter(std::string arg_name, bool ex, PrinterConfig config) :
    ArgumentPrinter(std::move(arg_name), config), ex(ex)
{
    // intentionally empty
}

std::string AddrinfoPrinter::print(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t argument) const
{
    const bool linux = drakvuf_get_os_type(drakvuf) == VMI_OS_LINUX;
    const process_reader read{ drakvuf, info, drakvuf_process_is32bit(drakvuf, info) };
    const size_t p = read.is32 ? 4 : 8;
    /*
     * Four ints, then on Windows ai_addrlen (size_t), ai_canonname, ai_addr,
     * [ADDRINFOEX: ai_blob, ai_bloblen, ai_provider,] ai_next; on Linux
     * ai_addrlen (socklen_t, padded), ai_addr, ai_canonname, ai_next.
     */
    const addr_t addr_off = linux ? 24 : 16 + 2 * p;
    const addr_t next_off = linux ? 40 : 16 + (ex ? 6 : 3) * p;

    addr_t node = 0;
    if (!argument || !read.ptr(argument, node))
        return ArgumentPrinter::print(drakvuf, info, argument);

    std::vector<std::string> addresses;
    for (unsigned i = 0; node && i < MAX_NODES; ++i)
    {
        addr_t sockaddr = 0;
        if (read.ptr(node + addr_off, sockaddr) && sockaddr)
        {
            uint8_t buf[28] = {};
            if (auto text = format_sockaddr(buf, read.bytes(sockaddr, buf, sizeof(buf)), linux))
                add_unique(addresses, address_only(*text));
        }
        if (!read.ptr(node + next_off, node))
            break;
    }
    return quoted(name, config, argument, joined(addresses, ","));
}

std::string DnsRecordPrinter::print(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t argument) const
{
    const process_reader read{ drakvuf, info, drakvuf_process_is32bit(drakvuf, info) };
    const size_t p = read.is32 ? 4 : 8;
    // DNS_RECORD: pNext, pName, WORD wType, WORD wDataLength, DWORD Flags,
    // DWORD dwTtl, DWORD dwReserved, then Data
    const addr_t type_off = 2 * p;
    const addr_t data_off = 2 * p + 16;
    constexpr uint16_t DNS_TYPE_A = 1, DNS_TYPE_AAAA = 28;

    addr_t record = 0;
    if (!argument || !read.ptr(argument, record))
        return ArgumentPrinter::print(drakvuf, info, argument);

    std::vector<std::string> addresses;
    for (unsigned i = 0; record && i < MAX_NODES; ++i)
    {
        uint16_t type = 0;
        uint8_t data[16] = {};
        char text[INET6_ADDRSTRLEN] = {};
        if (read.bytes(record + type_off, &type, sizeof(type)) == sizeof(type))
        {
            if (type == DNS_TYPE_A && read.bytes(record + data_off, data, 4) == 4
                && inet_ntop(AF_INET, data, text, sizeof(text)))
                add_unique(addresses, text);
            else if (type == DNS_TYPE_AAAA && read.bytes(record + data_off, data, 16) == 16
                && inet_ntop(AF_INET6, data, text, sizeof(text)))
                add_unique(addresses, text);
        }
        if (!read.ptr(record, record))
            break;
    }
    return quoted(name, config, argument, joined(addresses, ","));
}

std::string ArgvPrinter::print(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t argument) const
{
    const process_reader read{ drakvuf, info, drakvuf_process_is32bit(drakvuf, info) };
    const size_t p = read.is32 ? 4 : 8;
    if (!argument)
        return ArgumentPrinter::print(drakvuf, info, argument);

    std::vector<std::string> args;
    size_t total = 0;
    for (unsigned i = 0; i < MAX_ARGV && total < MAX_ARGV_TEXT; ++i)
    {
        addr_t str = 0;
        if (!read.ptr(argument + i * p, str) || !str)
            break;
        ACCESS_CONTEXT(ctx,
            .translate_mechanism = VMI_TM_PROCESS_DTB,
            .dtb = info->regs->cr3,
            .addr = str
        );
        vmi_reader_guard vmi(drakvuf);
        char* s = vmi_read_str(vmi, &ctx);
        std::string arg = s ? s : "";
        g_free(s);
        arg.resize(std::min(arg.size(), MAX_ARGV_TEXT - total));
        total += arg.size() + 1;
        args.push_back(std::move(arg));
    }
    return quoted(name, config, argument, joined(args, " "));
}

std::string ContextPrinter::print(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t argument) const
{
    if (!argument)
        return ArgumentPrinter::print(drakvuf, info, argument);
    const process_reader read{ drakvuf, info, drakvuf_process_is32bit(drakvuf, info) };

    // CONTEXT: x64 Dr0-Dr3 at 0x48, Dr6 0x68, Dr7 0x70, Rip 0xf8; x86 Dr0-Dr3
    // at 0x4, Dr6 0x14, Dr7 0x18, Eip 0xb8
    struct reg
    {
        const char* name;
        addr_t offset;
    };
    static const reg x64[] = { {"Dr0", 0x48}, {"Dr1", 0x50}, {"Dr2", 0x58}, {"Dr3", 0x60}, {"Dr6", 0x68}, {"Dr7", 0x70}, {"Rip", 0xf8} };
    static const reg x86[] = { {"Dr0", 0x4}, {"Dr1", 0x8}, {"Dr2", 0xc}, {"Dr3", 0x10}, {"Dr6", 0x14}, {"Dr7", 0x18}, {"Eip", 0xb8} };

    std::vector<std::string> fields;
    for (const auto& r : read.is32 ? x86 : x64)
    {
        uint64_t value = 0;
        const size_t size = read.is32 ? 4 : 8;
        if (read.bytes(argument + r.offset, &value, size) != size)
            return ArgumentPrinter::print(drakvuf, info, argument);
        std::stringstream field;
        field << r.name << "=0x" << std::hex << value;
        fields.push_back(field.str());
    }
    return quoted(name, config, argument, joined(fields, ";"));
}

std::string print_argument(drakvuf_t drakvuf, drakvuf_trap_info* info,
    const std::vector<std::unique_ptr<ArgumentPrinter>>& printers, const std::vector<uint64_t>& arguments,
    size_t i, std::optional<uint64_t> return_value)
{
    const auto& printer = printers[i];
    if (printer->length_from_return())
    {
        if (!return_value)
            return printer->print(drakvuf, info, arguments[i]);
        // A negative return is a failure (-1, SOCKET_ERROR): nothing was read.
        // Windows' recv returns an int, so -1 is 0xffffffff in rax: a
        // length of 2 GiB or more is not a buffer's.
        if (static_cast<int64_t>(*return_value) < 0 || static_cast<int32_t>(*return_value) < 0)
            return printer->print_sized(drakvuf, info, arguments[i], 0);
        return printer->print_sized(drakvuf, info, arguments[i], *return_value);
    }
    if (auto length = printer->length_argument(); length && *length < arguments.size() && *length < printers.size())
        return printer->print_sized(drakvuf, info, arguments[i],
                printers[*length]->value(drakvuf, info, arguments[*length]));
    return printer->print(drakvuf, info, arguments[i]);
}

std::string GuidPrinter::print(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t argument) const
{
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = argument
    );

    struct
    {
        uint32_t Data1;
        uint16_t Data2;
        uint16_t Data3;
        uint8_t Data4[8];
    } __attribute__((packed, aligned(4))) guid;

    vmi_reader_guard vmi(drakvuf);
    if (vmi_read(vmi, &ctx, sizeof(guid), &guid, nullptr) != VMI_SUCCESS)
        memset(&guid, 0, sizeof(guid));

    const int sz = 64;
    char stream[sz] = {0};
    snprintf(stream, sz, "\"%08X-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX\"",
        guid.Data1, guid.Data2, guid.Data3, guid.Data4[0], guid.Data4[1],
        guid.Data4[2], guid.Data4[3], guid.Data4[4],
        guid.Data4[5], guid.Data4[6], guid.Data4[7]);
    return name + "=" + std::string(stream);
}

BitMaskPrinter::BitMaskPrinter(
    std::string arg_name,
    std::map < uint64_t, std::string > dict,
    PrinterConfig config)
    : ArgumentPrinter(arg_name, config)
    , dict(dict)
{
    // intentionally empty
}

std::string BitMaskPrinter::print(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t argument) const
{
    std::stringstream stream;
    stream << name << "=0x" << std::hex << argument << ": ";
    if (argument == 0 && this->dict.find(0) != this->dict.end())
    {
        stream << this->dict.at(0);
    }
    else
    {
        bool first = true;
        for (std::pair<uint64_t, std::string> element : this->dict)
        {
            if (argument & element.first)
            {
                if (first)
                {
                    first = false;
                }
                else
                {
                    stream << "|";
                }
                stream << element.second;
            }
        }
    }
    return stream.str();
}
