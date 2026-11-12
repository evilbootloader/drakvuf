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
#include "unwind.h"

#include <cstdlib>
#include <map>

#include <check.h>

using namespace x64_unwind;

// Guest memory as runs of bytes at addresses; a read touching any byte not
// in it fails, as one of an unmapped page does
struct memory
{
    std::map<uint64_t, uint8_t> bytes;

    void put(uint64_t addr, const void* data, size_t size)
    {
        for (size_t i = 0; i < size; ++i)
            bytes[addr + i] = static_cast<const uint8_t*>(data)[i];
    }
    void put64(uint64_t addr, uint64_t value)
    {
        put(addr, &value, sizeof(value));
    }
    reader reader_fn() const
    {
        return [this](uint64_t addr, void* buf, size_t size)
        {
            for (size_t i = 0; i < size; ++i)
            {
                auto it = bytes.find(addr + i);
                if (it == bytes.end())
                    return false;
                static_cast<uint8_t*>(buf)[i] = it->second;
            }
            return true;
        };
    }
};

static constexpr uint64_t BASE = 0x7ff800000000;

static context at(uint32_t rva, uint64_t rsp)
{
    context ctx{};
    ctx.rip = BASE + rva;
    ctx.regs[GPR_RSP] = rsp;
    return ctx;
}

START_TEST(test_lookup)
{
    const std::vector<runtime_function> table =
    {
        { 0x1000, 0x1080, 0x2000 },
        { 0x1080, 0x1100, 0x2010 },
        { 0x1200, 0x1300, 0x2020 },
    };
    ck_assert(lookup(table, 0x0fff) == nullptr);
    ck_assert(lookup(table, 0x1000) == &table[0]);
    ck_assert(lookup(table, 0x107f) == &table[0]);
    ck_assert(lookup(table, 0x1080) == &table[1]);
    ck_assert(lookup(table, 0x1150) == nullptr);       // between functions: a leaf
    ck_assert(lookup(table, 0x12ff) == &table[2]);
    ck_assert(lookup(table, 0x1300) == nullptr);
    ck_assert(lookup({}, 0x1000) == nullptr);
}
END_TEST

// push rbp; push rbx; sub rsp, 28h
START_TEST(test_pushes_and_allocation)
{
    memory m;
    const uint8_t info[] = { 0x01, 0x06, 0x03, 0x00,
                             0x06, 0x42,     // ALLOC_SMALL 4*8+8
                             0x02, 0x30,     // PUSH_NONVOL rbx
                             0x01, 0x50,     // PUSH_NONVOL rbp
                             0x00, 0x00
                           };
    m.put(BASE + 0x2000, info, sizeof(info));
    m.put64(0x7028, 0xbbbb);
    m.put64(0x7030, 0x5555);
    m.put64(0x7038, 0x401234);

    context ctx = at(0x1050, 0x7000);
    const runtime_function f{ 0x1000, 0x1100, 0x2000 };
    ck_assert(step(m.reader_fn(), BASE, &f, ctx));
    ck_assert_uint_eq(ctx.rip, 0x401234);
    ck_assert_uint_eq(ctx.regs[GPR_RSP], 0x7040);
    ck_assert_uint_eq(ctx.regs[GPR_RBX], 0xbbbb);
    ck_assert_uint_eq(ctx.regs[GPR_RBP], 0x5555);
}
END_TEST

// push rbp; sub rsp, 40h; lea rbp, [rsp+20h] -- then alloca moved rsp down
START_TEST(test_frame_pointer)
{
    memory m;
    const uint8_t info[] = { 0x01, 0x09, 0x03, 0x25,   // frame register rbp, offset 2*16
                             0x09, 0x03,     // SET_FPREG
                             0x05, 0x72,     // ALLOC_SMALL 7*8+8
                             0x01, 0x50,     // PUSH_NONVOL rbp
                             0x00, 0x00
                           };
    m.put(BASE + 0x2000, info, sizeof(info));
    m.put64(0x8040, 0x6666);
    m.put64(0x8048, 0x505050);

    context ctx = at(0x1050, 0x7f00);
    ctx.regs[GPR_RBP] = 0x8020;
    const runtime_function f{ 0x1000, 0x1100, 0x2000 };
    ck_assert(step(m.reader_fn(), BASE, &f, ctx));
    ck_assert_uint_eq(ctx.rip, 0x505050);
    ck_assert_uint_eq(ctx.regs[GPR_RSP], 0x8050);
    ck_assert_uint_eq(ctx.regs[GPR_RBP], 0x6666);
}
END_TEST

// A function in two parts: the second's codes chain to the first's
START_TEST(test_chained_large_allocation_and_save)
{
    memory m;
    const uint8_t part[] = { 0x21, 0x10, 0x04, 0x00,   // version 1, UNW_FLAG_CHAININFO
                             0x10, 0x64,     // SAVE_NONVOL rsi
                             0x10, 0x00,     //   at [frame + 10h*8]
                             0x08, 0x01,     // ALLOC_LARGE, 16-bit
                             0x00, 0x02,     //   200h*8 = 1000h
                             0x00, 0x30, 0x00, 0x00, 0x00, 0x31, 0x00, 0x00, 0x00, 0x21, 0x00, 0x00
                           };
    const uint8_t first[] = { 0x01, 0x01, 0x01, 0x00,
                              0x01, 0x70,    // PUSH_NONVOL rdi
                              0x00, 0x00
                            };
    m.put(BASE + 0x2200, part, sizeof(part));
    m.put(BASE + 0x2100, first, sizeof(first));
    m.put64(0x9080, 0x5151);
    m.put64(0xa000, 0x7171);
    m.put64(0xa008, 0x606060);

    context ctx = at(0x1250, 0x9000);
    const runtime_function f{ 0x1200, 0x1300, 0x2200 };
    ck_assert(step(m.reader_fn(), BASE, &f, ctx));
    ck_assert_uint_eq(ctx.regs[GPR_RSI], 0x5151);
    ck_assert_uint_eq(ctx.regs[GPR_RDI], 0x7171);
    ck_assert_uint_eq(ctx.rip, 0x606060);
    ck_assert_uint_eq(ctx.regs[GPR_RSP], 0xa010);
}
END_TEST

START_TEST(test_indirect_entry)
{
    memory m;
    const runtime_function described{ 0x1000, 0x1100, 0x2000 };
    const uint8_t info[] = { 0x01, 0x01, 0x01, 0x00, 0x01, 0x50, 0x00, 0x00 };   // push rbp
    m.put(BASE + 0x3000, &described, sizeof(described));
    m.put(BASE + 0x2000, info, sizeof(info));
    m.put64(0x7000, 0x5555);
    m.put64(0x7008, 0x401000);

    context ctx = at(0x1050, 0x7000);
    const runtime_function f{ 0x1040, 0x1060, 0x3001 };
    ck_assert(step(m.reader_fn(), BASE, &f, ctx));
    ck_assert_uint_eq(ctx.rip, 0x401000);
    ck_assert_uint_eq(ctx.regs[GPR_RBP], 0x5555);
}
END_TEST

START_TEST(test_leaf)
{
    memory m;
    m.put64(0x7000, 0x401000);

    context ctx = at(0x1050, 0x7000);
    ck_assert(step(m.reader_fn(), BASE, nullptr, ctx));
    ck_assert_uint_eq(ctx.rip, 0x401000);
    ck_assert_uint_eq(ctx.regs[GPR_RSP], 0x7008);
}
END_TEST

START_TEST(test_refused)
{
    memory m;
    const uint8_t info[] = { 0x01, 0x06, 0x01, 0x00, 0x01, 0x50, 0x00, 0x00 };
    m.put(BASE + 0x2000, info, sizeof(info));
    m.put64(0x7000, 0x5555);
    m.put64(0x7008, 0x401000);
    const runtime_function f{ 0x1000, 0x1100, 0x2000 };

    // Inside the prologue
    context ctx = at(0x1003, 0x7000);
    ck_assert(!step(m.reader_fn(), BASE, &f, ctx));

    // Unwind data not readable: a page the process has not touched
    const runtime_function elsewhere{ 0x1000, 0x1100, 0x4000 };
    ctx = at(0x1050, 0x7000);
    ck_assert(!step(m.reader_fn(), BASE, &elsewhere, ctx));

    // An interrupt frame
    const uint8_t machframe[] = { 0x01, 0x00, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x00 };
    m.put(BASE + 0x2100, machframe, sizeof(machframe));
    const runtime_function handler{ 0x1000, 0x1100, 0x2100 };
    ctx = at(0x1050, 0x7000);
    ck_assert(!step(m.reader_fn(), BASE, &handler, ctx));

    // Chained entries that loop
    const uint8_t loop[] = { 0x21, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x22, 0x00, 0x00 };
    m.put(BASE + 0x2200, loop, sizeof(loop));
    const runtime_function looping{ 0x1000, 0x1100, 0x2200 };
    ctx = at(0x1050, 0x7000);
    ck_assert(!step(m.reader_fn(), BASE, &looping, ctx));
}
END_TEST

static Suite* unwind_suite(void)
{
    Suite* s = suite_create("apimon x64 unwind");
    TCase* tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_lookup);
    tcase_add_test(tc_core, test_pushes_and_allocation);
    tcase_add_test(tc_core, test_frame_pointer);
    tcase_add_test(tc_core, test_chained_large_allocation_and_save);
    tcase_add_test(tc_core, test_indirect_entry);
    tcase_add_test(tc_core, test_leaf);
    tcase_add_test(tc_core, test_refused);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    SRunner* sr = srunner_create(unwind_suite());

    srunner_run_all(sr, CK_NORMAL);
    int number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
