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

/*
 * Where a Windows syscall was made from, read off the code around its frames (win.cpp,
 * get_origin): what a stub that ran `syscall` is, what the call before a return address called,
 * and whether code looks like a syscall stub of its own. Through a reader, so that check.cpp can
 * hand them made-up code.
 */

#ifndef SYSCALLS_ORIGIN_H
#define SYSCALLS_ORIGIN_H

#include <cstdint>
#include <cstring>
#include <functional>
#include <optional>
#include <vector>

namespace syscalls_origin
{

using address = uint64_t;
// Up to `size` bytes at `at` in the thread's address space into `buffer`; how many were read
using reader = std::function<size_t(address at, void* buffer, size_t size)>;

inline int32_t rel32(const uint8_t* bytes)
{
    int32_t value;
    memcpy(&value, bytes, sizeof(value));
    return value;
}

/*
 * ntdll's and win32u's stubs on 64-bit Windows 10 and 11, up to the instruction after `syscall`
 * (frame 0, at 0x14):
 *   4c 8b d1                    mov r10, rcx
 *   b8 nn nn nn nn              mov eax, service
 *   f6 04 25 08 03 fe 7f 01     test byte ptr [SharedUserData+308h], 1
 *   75 03                       jne (int 2Eh)
 *   0f 05                       syscall
 * then ret, int 2Eh, ret: 0x20 bytes a stub.
 */
constexpr address STUB64_CALLER = 0x14;
constexpr address STUB64_SIZE = 0x20;

// The service of the stub `caller` is frame 0 in; nothing for code that is not such a stub, one a
// hook was put in included
inline std::optional<uint32_t> stub64_service(const reader& read, address caller)
{
    uint8_t code[STUB64_CALLER];
    if (caller < STUB64_CALLER || read(caller - STUB64_CALLER, code, sizeof(code)) != sizeof(code))
        return {};
    if (code[0] != 0x4c || code[1] != 0x8b || code[2] != 0xd1 || code[3] != 0xb8 ||
        code[STUB64_CALLER - 2] != 0x0f || code[STUB64_CALLER - 1] != 0x05)
        return {};
    return static_cast<uint32_t>(rel32(code + 4));
}

/*
 * ntdll's and win32u's stubs in a WoW64 process, up to the instruction after the call that goes on
 * to Wow64Transition (frame 0 of the 32-bit call, at 0xc):
 *   b8 nn nn nn nn              mov eax, service
 *   ba nn nn nn nn              mov edx, offset Wow64SystemServiceCall
 *   ff d2                       call edx
 * then ret.
 */
constexpr address STUB32_CALLER = 0xc;

inline bool is_stub32(const reader& read, address caller)
{
    uint8_t code[STUB32_CALLER];
    return caller >= STUB32_CALLER && read(caller - STUB32_CALLER, code, sizeof(code)) == sizeof(code) &&
        code[0] == 0xb8 && code[5] == 0xba && code[10] == 0xff && code[11] == 0xd2;
}

// A stub's eax: the table's bit, set for win32k's, and the number in that table
constexpr uint32_t SERVICE_MASK = 0x1fff;
constexpr uint32_t SERVICE_WIN32K = 0x1000;

// A service routine's entry as a stub's eax names it
inline uint32_t service_of(uint32_t number, bool ntos)
{
    return (ntos ? 0 : SERVICE_WIN32K) | (number & (SERVICE_WIN32K - 1));
}

/*
 * Whether a stub for `stub` ran a syscall the kernel dispatched to another service's routine:
 * `dispatched` is every entry of the routine about to run, since the linker folds identical
 * routines into one and its address does not say which entry was asked for. Compared with what
 * is dispatched and not with KTHREAD.SystemCallNumber: on a thread's first win32k syscall the
 * kernel converts it to a GUI thread first, and the callbacks and Zw calls of that overwrite the
 * number before the service is dispatched.
 */
inline bool other_service(uint32_t stub, const std::vector<uint32_t>& dispatched)
{
    if (dispatched.empty())
        return false;
    for (uint32_t service : dispatched)
        if ((service & SERVICE_MASK) == (stub & SERVICE_MASK))
            return false;
    return true;
}

/*
 * The address the call instruction that ends at `ret` called, past the jump thunks it went
 * through -- an import's jmp [__imp_X], an incremental link's jmp rel32 -- stopping at `stop`.
 * 0 when no call decodes there: a call through a register, or through memory a register points
 * to, CFG's included.
 */
inline address call_target(const reader& read, address ret, bool is32, address stop)
{
    constexpr int MAX_THUNKS = 3;
    const size_t width = is32 ? 4 : 8;
    auto pointer_at = [&](address at) -> address
    {
        uint64_t value = 0;
        return read(at, &value, width) == width ? value : 0;
    };
    auto wrap = [&](address at) -> address
    {
        return is32 ? at & 0xffffffff : at;
    };

    // ff 15 disp32: call [rip+disp32], or call [disp32] in 32-bit code. e8 rel32: call rel32.
    uint8_t code[6];
    if (ret < sizeof(code) || read(ret - sizeof(code), code, sizeof(code)) != sizeof(code))
        return 0;
    address target = 0;
    if (code[0] == 0xff && code[1] == 0x15)
        target = pointer_at(is32 ? static_cast<uint32_t>(rel32(code + 2)) : ret + rel32(code + 2));
    else if (code[1] == 0xe8)
        target = wrap(ret + rel32(code + 2));

    for (int hop = 0; target && target != stop && hop < MAX_THUNKS; ++hop)
    {
        uint8_t thunk[7] = {};
        const size_t got = read(target, thunk, sizeof(thunk));
        // ff 25 disp32: jmp [rip+disp32], or jmp [disp32]; with a REX prefix, 48 ff 25
        const size_t at = !is32 && got && (thunk[0] & 0xf0) == 0x40 ? 1 : 0;
        if (got >= at + 6 && thunk[at] == 0xff && thunk[at + 1] == 0x25)
            target = pointer_at(is32 ? static_cast<uint32_t>(rel32(thunk + at + 2)) : target + at + 6 + rel32(thunk + at + 2));
        else if (got >= 5 && thunk[0] == 0xe9)
            target = wrap(target + 5 + rel32(thunk + 1));
        else if (got >= 2 && thunk[0] == 0xeb)
            target = wrap(target + 2 + static_cast<int8_t>(thunk[1]));
        else
            break;
    }
    return target;
}

/*
 * Code that makes a syscall of its own and jumps on to the instruction: `mov r10, rcx`, which only
 * the syscall calling convention needs, and a jmp within the next 16 bytes -- the way indirect
 * syscall stubs end (HellsHall, SysWhispers3, RecycledGate). A wrapper that tail-calls an ntdll
 * export leaves rcx where it is. Bytes are matched, not decoded: an operand holding them matches.
 */
inline bool looks_like_syscall_stub(const reader& read, address at)
{
    // SysWhispers3's jumper moves r10 at 0x47
    constexpr size_t WINDOW = 0x80;
    constexpr size_t REACH = 16;
    uint8_t code[WINDOW];
    const size_t got = read(at, code, sizeof(code));
    for (size_t i = 0; i + 3 <= got; ++i)
    {
        // 4c 8b d1 or 49 89 ca: mov r10, rcx
        if (!((code[i] == 0x4c && code[i + 1] == 0x8b && code[i + 2] == 0xd1) ||
                (code[i] == 0x49 && code[i + 1] == 0x89 && code[i + 2] == 0xca)))
            continue;
        for (size_t j = i + 3; j < got && j < i + 3 + REACH; ++j)
        {
            // e9: jmp rel32; ff /4: jmp r/m
            if (code[j] == 0xe9 || (code[j] == 0xff && j + 1 < got && (code[j + 1] & 0x38) == 0x20))
                return true;
        }
    }
    return false;
}

/*
 * What the call before `ret` called, when it was not `stub` -- the stub the syscall ran in -- but
 * that stub past its start, or 64-bit code that looks like a syscall stub of its own: an indirect
 * syscall. 0 otherwise, and when the call does not decode.
 */
inline address indirect_call(const reader& read, address ret, address stub, address stub_size, bool is32)
{
    const address target = call_target(read, ret, is32, stub);
    if (!target || target == stub)
        return 0;
    if (target > stub && target < stub + stub_size)
        return target;
    if (!is32 && looks_like_syscall_stub(read, target))
        return target;
    return 0;
}

} // namespace syscalls_origin

#endif
