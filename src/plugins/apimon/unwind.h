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
 * x64 stack unwinding with an image's unwind data -- .pdata and the
 * UNWIND_INFO its entries point to -- as Windows' RtlVirtualUnwind does it,
 * reading guest memory through a callback. Only what finding the next return
 * address needs: the stack pointer and the integer registers a prologue
 * saves, one of which may be the frame pointer of the next frame up.
 *
 * https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64
 */

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <vector>

namespace x64_unwind
{

struct runtime_function
{
    uint32_t begin;
    uint32_t end;
    uint32_t unwind_info;
};
static_assert(sizeof(runtime_function) == 12, "RUNTIME_FUNCTION is 12 bytes");

// Register numbers of UNWIND_CODE and UNWIND_INFO.FrameRegister (prefixed:
// libvmi.h defines RAX, RSP... as macros)
enum reg
{
    GPR_RAX, GPR_RCX, GPR_RDX, GPR_RBX, GPR_RSP, GPR_RBP, GPR_RSI, GPR_RDI,
    GPR_R8, GPR_R9, GPR_R10, GPR_R11, GPR_R12, GPR_R13, GPR_R14, GPR_R15
};

// A frame's state: where it executes and its integer registers
struct context
{
    uint64_t rip;
    uint64_t regs[16];
};

// Reads `size` bytes of guest memory at `addr`: false when any is unreadable
using reader = std::function<bool(uint64_t addr, void* buf, size_t size)>;

// The entry of a sorted .pdata covering `rva`, or nullptr: a leaf function,
// which has no prologue to undo
inline const runtime_function* lookup(const std::vector<runtime_function>& table, uint32_t rva)
{
    auto it = std::upper_bound(table.begin(), table.end(), rva,
            [](uint32_t value, const runtime_function& f)
    {
        return value < f.begin;
    });
    if (it == table.begin())
        return nullptr;
    --it;
    return rva < it->end ? &*it : nullptr;
}

enum op
{
    PUSH_NONVOL, ALLOC_LARGE, ALLOC_SMALL, SET_FPREG, SAVE_NONVOL, SAVE_NONVOL_FAR,
    EPILOG, SPARE, SAVE_XMM128, SAVE_XMM128_FAR, PUSH_MACHFRAME
};

constexpr uint8_t UNW_FLAG_CHAININFO = 4;
// Chained and indirect entries followed per frame, against loops
constexpr unsigned MAX_ENTRIES = 32;

// UNWIND_CODE slots an operation takes, its own included
inline unsigned code_slots(uint8_t op, uint8_t info)
{
    switch (op)
    {
        case ALLOC_LARGE:
            return info ? 3 : 2;
        case SAVE_NONVOL:
        case SAVE_XMM128:
        case EPILOG:
            return 2;
        case SAVE_NONVOL_FAR:
        case SAVE_XMM128_FAR:
            return 3;
        default:
            return 1;
    }
}

/*
 * Undo the prologue of `entry`, the function of the image at `base` that
 * ctx.rip is in. False when its unwind data cannot be read or is not
 * understood.
 *
 * ctx.rip is a return address, past the prologue. One inside it would need
 * only the codes of the instructions run so far; that does not happen at a
 * call -- __chkstk aside, which calls nothing -- so it is refused rather than
 * handled. One at an epilogue (a call right before `add rsp`) needs no
 * special case: none of the epilogue has run.
 */
inline bool undo_prologue(const reader& read, uint64_t base, runtime_function entry, context& ctx)
{
    bool primary = true;

    for (unsigned n = 0; n < MAX_ENTRIES; ++n)
    {
        // An indirect entry points to the entry that describes the function
        if (entry.unwind_info & 1)
        {
            if (!read(base + (entry.unwind_info & ~1u), &entry, sizeof(entry)))
                return false;
            continue;
        }

        uint8_t header[4];
        if (!read(base + entry.unwind_info, header, sizeof(header)))
            return false;
        const uint8_t version = header[0] & 7;
        const uint8_t flags = header[0] >> 3;
        const uint8_t prolog_size = header[1];
        const uint8_t count = header[2];
        const uint8_t frame_reg = header[3] & 0xf;
        const uint8_t frame_offset = header[3] >> 4;
        if (version != 1 && version != 2)
            return false;
        if (primary && ctx.rip - base - entry.begin < prolog_size)
            return false;

        // The codes, padded to an even count, then a chained entry
        const size_t slots = (count + 1u) & ~1u;
        uint8_t codes[256 * 2 + sizeof(runtime_function)];
        const size_t length = slots * 2 + ((flags & UNW_FLAG_CHAININFO) ? sizeof(runtime_function) : 0);
        if (length && !read(base + entry.unwind_info + sizeof(header), codes, length))
            return false;
        auto slot = [&](size_t i) -> uint32_t
        {
            return codes[i * 2] | (uint32_t(codes[i * 2 + 1]) << 8);
        };

        // What SAVE_NONVOL offsets are from: the base of the fixed
        // allocation, which the frame pointer marks when there is one (the
        // stack pointer may have moved below it since, by alloca)
        const uint64_t frame = frame_reg ? ctx.regs[frame_reg] - frame_offset * 16u : ctx.regs[GPR_RSP];

        // In reverse order of the prologue's instructions
        for (size_t i = 0; i < count;)
        {
            const uint8_t op = codes[i * 2 + 1] & 0xf;
            const uint8_t info = codes[i * 2 + 1] >> 4;
            const unsigned size = code_slots(op, info);
            if (i + size > count)
                return false;

            switch (op)
            {
                case PUSH_NONVOL:
                    if (!read(ctx.regs[GPR_RSP], &ctx.regs[info], 8))
                        return false;
                    ctx.regs[GPR_RSP] += 8;
                    break;
                case ALLOC_LARGE:
                    ctx.regs[GPR_RSP] += info ? (slot(i + 1) | (slot(i + 2) << 16)) : slot(i + 1) * 8u;
                    break;
                case ALLOC_SMALL:
                    ctx.regs[GPR_RSP] += info * 8u + 8;
                    break;
                case SET_FPREG:
                    ctx.regs[GPR_RSP] = ctx.regs[frame_reg] - frame_offset * 16u;
                    break;
                case SAVE_NONVOL:
                    if (!read(frame + slot(i + 1) * 8u, &ctx.regs[info], 8))
                        return false;
                    break;
                case SAVE_NONVOL_FAR:
                    if (!read(frame + (slot(i + 1) | (slot(i + 2) << 16)), &ctx.regs[info], 8))
                        return false;
                    break;
                case EPILOG:
                case SAVE_XMM128:
                case SAVE_XMM128_FAR:
                    break;
                default:
                    // PUSH_MACHFRAME: an interrupt or exception frame, which
                    // a hooked call does not return through
                    return false;
            }
            i += size;
        }

        if (!(flags & UNW_FLAG_CHAININFO))
            return true;
        memcpy(&entry, codes + slots * 2, sizeof(entry));
        primary = false;
    }
    return false;
}

/*
 * From the frame `ctx` describes to its caller's, at the call: undo the
 * prologue of `entry` (nullptr for a leaf function, whose return address is
 * where the stack pointer points), then pop the return address.
 */
inline bool step(const reader& read, uint64_t base, const runtime_function* entry, context& ctx)
{
    if (entry && !undo_prologue(read, base, *entry, ctx))
        return false;
    if (!read(ctx.regs[GPR_RSP], &ctx.rip, 8))
        return false;
    ctx.regs[GPR_RSP] += 8;
    return true;
}

} // namespace x64_unwind
