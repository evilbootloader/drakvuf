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

#include <cstring>
#include <sstream>

#include <arpa/inet.h>
#include <sys/socket.h>

#include "utils.hpp"


std::string escape_str(const std::string& s)
{
    char const* const hexdig = "0123456789ABCDEF";
    std::stringstream os;

    for (unsigned char c : s)
    {
        switch (c)
        {
            case '\\':
                os << "\\\\";
                break;
            case '\t':
                os << "\\t";
                break;
            case '\r':
                os << "\\r";
                break;
            case '\n':
                os << "\\n";
                break;
            case '"':
                os << "\\\"";
                break;
            default:
                if (c < ' ')
                    os << "\\x" << hexdig[c >> 4] << hexdig[c & 0xF];
                else
                    os << c;
                break;
        }
    }

    return os.str();
}

std::string escape_bytes(const uint8_t* data, size_t size)
{
    char const* const hexdig = "0123456789ABCDEF";
    std::string out;
    out.reserve(size);
    for (size_t i = 0; i < size; ++i)
    {
        const unsigned char c = data[i];
        switch (c)
        {
            case '\\':
                out += "\\\\";
                break;
            case '\t':
                out += "\\t";
                break;
            case '\r':
                out += "\\r";
                break;
            case '\n':
                out += "\\n";
                break;
            case '"':
                out += "\\\"";
                break;
            default:
                if (c < ' ' || c > '~')
                {
                    out += "\\x";
                    out += hexdig[c >> 4];
                    out += hexdig[c & 0xF];
                }
                else
                    out += static_cast<char>(c);
                break;
        }
    }
    return out;
}

bool parse_ansi_string(const uint8_t* buf, size_t len, bool is32bit, uint16_t* length, uint64_t* buffer)
{
    const size_t at = is32bit ? 4 : 8;
    const size_t width = is32bit ? 4 : 8;
    if (len < at + width)
        return false;

    *length = buf[0] | (buf[1] << 8);
    *buffer = 0;
    for (size_t i = 0; i < width; i++)
        *buffer |= static_cast<uint64_t>(buf[at + i]) << (8 * i);
    return true;
}

std::optional<std::string> format_sockaddr(const uint8_t* buf, size_t len, bool linux)
{
    if (len < 2)
        return {};

    // sa_family: a little-endian 16-bit number on both systems
    const unsigned family = buf[0] | (buf[1] << 8);
    const unsigned af_inet6 = linux ? 10 : 23;
    auto port = [&]()
    {
        return std::to_string((buf[2] << 8) | buf[3]);
    };
    char text[INET6_ADDRSTRLEN] = {};

    if (family == 2 && len >= 8)
    {
        if (!inet_ntop(AF_INET, buf + 4, text, sizeof(text)))
            return {};
        return std::string(text) + ":" + port();
    }
    if (family == af_inet6 && len >= 24)
    {
        if (!inet_ntop(AF_INET6, buf + 8, text, sizeof(text)))
            return {};
        return "[" + std::string(text) + "]:" + port();
    }
    if (family == 1 && len > 2)
    {
        // sun_path: NUL-terminated, or on Linux a NUL then an abstract name
        const char* path = reinterpret_cast<const char*>(buf + 2);
        const size_t max = len - 2;
        if (path[0])
            return std::string(path, strnlen(path, max));
        if (linux && max > 1 && path[1])
            return "@" + std::string(path + 1, strnlen(path + 1, max - 1));
        return {};
    }
    return {};
}
