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

#include <check.h>

#include <algorithm>
#include <map>
#include <vector>

#include "../../libdrakvuf/libdrakvuf.h"
#include "private.h"
#include "origin.h"

START_TEST(test_syscall_arg_type_parameters)
{
    for (size_t i = 0; i < syscalls_ns::arg_type_t::__ARG_TYPE_MAX; i++)
        ck_assert_msg(syscalls_ns::arg_types.find((syscalls_ns::arg_type_t)i) != syscalls_ns::arg_types.end(), "information missing for syscall argument type %zu", i);
}
END_TEST

Suite* syscall_parameters_suite(void)
{
    Suite* s;
    TCase* tc_core;

    s = suite_create("Check known syscall argument parameters");

    /* Core test case */
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_syscall_arg_type_parameters);
    suite_add_tcase(s, tc_core);

    return s;
}

/* --- syscalls_origin: made-up code --------------------------------------------------------- */

using syscalls_origin::address;
using bytes = std::vector<uint8_t>;

// Regions of bytes; a read stops where its region ends, as vmi_read stops at a page not present
struct memory
{
    std::map<address, bytes> regions;

    void put(address at, bytes code)
    {
        regions[at] = std::move(code);
    }

    syscalls_origin::reader reader() const
    {
        return [this](address at, void* buffer, size_t size) -> size_t
        {
            auto it = regions.upper_bound(at);
            if (it == regions.begin())
                return 0;
            --it;
            if (at >= it->first + it->second.size())
                return 0;
            const size_t n = std::min<size_t>(size, it->first + it->second.size() - at);
            memcpy(buffer, it->second.data() + (at - it->first), n);
            return n;
        };
    }
};

static bytes le(uint64_t value, size_t width)
{
    bytes out;
    for (size_t i = 0; i < width; i++)
        out.push_back(static_cast<uint8_t>(value >> (8 * i)));
    return out;
}

static bytes cat(std::initializer_list<bytes> parts)
{
    bytes out;
    for (const auto& part : parts)
        out.insert(out.end(), part.begin(), part.end());
    return out;
}

// A rel32 or disp32 from the end of the instruction at `end` to `to`
static bytes rel(address end, address to)
{
    return le(static_cast<uint32_t>(static_cast<int32_t>(to - end)), 4);
}

static constexpr address STUB = 0x7ff812341000;          // ntdll!NtAllocateVirtualMemory
static constexpr address FRAME0 = STUB + syscalls_origin::STUB64_CALLER;
static constexpr address APP = 0x7ff812000000;           // the sample's image

static const bytes NTDLL_STUB =
{
    0x4c, 0x8b, 0xd1, 0xb8, 0x18, 0x00, 0x00, 0x00, 0xf6, 0x04, 0x25, 0x08, 0x03, 0xfe, 0x7f, 0x01,
    0x75, 0x03, 0x0f, 0x05, 0xc3, 0xcd, 0x2e, 0xc3, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,
};

// The sample's code calling `to` at `at` with e8 rel32; the return address
static address call_rel32(memory& m, address at, address to)
{
    m.put(at, cat({ { 0x90 }, { 0xe8 }, rel(at + 6, to) }));
    return at + 6;
}

START_TEST(test_origin_stub64)
{
    memory m;
    m.put(STUB, NTDLL_STUB);
    ck_assert(syscalls_origin::stub64_service(m.reader(), FRAME0) == 0x18u);
    // Not the instruction after `syscall`
    ck_assert(!syscalls_origin::stub64_service(m.reader(), STUB + 0x10));
    // A stub a hook was put in
    bytes hooked = NTDLL_STUB;
    hooked[0] = 0xe9;
    m.put(STUB, hooked);
    ck_assert(!syscalls_origin::stub64_service(m.reader(), FRAME0));
    // Code that is not there
    ck_assert(!syscalls_origin::stub64_service(m.reader(), 0x10));
}
END_TEST

START_TEST(test_origin_calls_that_reach_the_stub)
{
    memory m;
    m.put(STUB, NTDLL_STUB);
    const auto read = m.reader();

    // call rel32 straight to the stub, as ntdll's own code calls it
    address ret = call_rel32(m, APP, STUB);
    ck_assert_uint_eq(syscalls_origin::call_target(read, ret, false, STUB), STUB);
    ck_assert_uint_eq(syscalls_origin::indirect_call(read, ret, STUB, syscalls_origin::STUB64_SIZE, false), 0);

    // call [rip+disp32] through the import address table, as kernelbase calls it
    const address iat = APP + 0x3000;
    m.put(iat, le(STUB, 8));
    m.put(APP + 0x100, cat({ { 0xff, 0x15 }, rel(APP + 0x106, iat) }));
    ret = APP + 0x106;
    ck_assert_uint_eq(syscalls_origin::call_target(read, ret, false, STUB), STUB);
    ck_assert_uint_eq(syscalls_origin::indirect_call(read, ret, STUB, syscalls_origin::STUB64_SIZE, false), 0);

    // call rel32 to an import thunk, jmp [rip+disp32]: code built without dllimport
    const address thunk = APP + 0x200;
    m.put(thunk, cat({ { 0xff, 0x25 }, rel(thunk + 6, iat) }));
    ret = call_rel32(m, APP + 0x300, thunk);
    ck_assert_uint_eq(syscalls_origin::indirect_call(read, ret, STUB, syscalls_origin::STUB64_SIZE, false), 0);

    // The same thunk with a REX prefix, behind an incremental link's jmp rel32
    const address rex_thunk = APP + 0x400;
    m.put(rex_thunk, cat({ { 0x48, 0xff, 0x25 }, rel(rex_thunk + 7, iat) }));
    const address ilt = APP + 0x500;
    m.put(ilt, cat({ { 0xe9 }, rel(ilt + 5, rex_thunk) }));
    ret = call_rel32(m, APP + 0x600, ilt);
    ck_assert_uint_eq(syscalls_origin::call_target(read, ret, false, STUB), STUB);

    // call rax: nothing decodes
    m.put(APP + 0x700, { 0x90, 0x90, 0x90, 0x90, 0xff, 0xd0 });
    ck_assert_uint_eq(syscalls_origin::call_target(read, APP + 0x706, false, STUB), 0);
}
END_TEST

START_TEST(test_origin_indirect_syscalls)
{
    memory m;
    m.put(STUB, NTDLL_STUB);
    const auto read = m.reader();

    // A call straight to ntdll's `syscall`, past the stub's start
    address ret = call_rel32(m, APP, STUB + 0x12);
    ck_assert_uint_eq(syscalls_origin::indirect_call(read, ret, STUB, syscalls_origin::STUB64_SIZE, false), STUB + 0x12);

    // HellsHall: mov r10, rcx; mov eax, [rip+x]; jmp [rip+y] to ntdll's `syscall`
    const address hellshall = APP + 0x1000;
    m.put(hellshall, { 0x4c, 0x8b, 0xd1, 0x8b, 0x05, 0x10, 0x20, 0x00, 0x00, 0xff, 0x25, 0x0a, 0x20, 0x00, 0x00, 0xc3 });
    ret = call_rel32(m, APP + 0x100, hellshall);
    ck_assert_uint_eq(syscalls_origin::indirect_call(read, ret, STUB, syscalls_origin::STUB64_SIZE, false), hellshall);

    // SysWhispers3's jumper: registers saved, two calls, then mov r10, rcx; jmp r11 at 0x47
    const address jumper = APP + 0x2000;
    m.put(jumper,
    {
        0x48, 0x89, 0x4c, 0x24, 0x08, 0x48, 0x89, 0x54, 0x24, 0x10, 0x4c, 0x89, 0x44, 0x24, 0x18,
        0x4c, 0x89, 0x4c, 0x24, 0x20, 0x48, 0x83, 0xec, 0x28, 0xb9, 0x1e, 0x0d, 0x0f, 0xc0, 0xe8,
        0x00, 0x01, 0x00, 0x00, 0x49, 0x89, 0xc3, 0xb9, 0x1e, 0x0d, 0x0f, 0xc0, 0xe8, 0x00, 0x02,
        0x00, 0x00, 0x48, 0x83, 0xc4, 0x28, 0x48, 0x8b, 0x4c, 0x24, 0x08, 0x48, 0x8b, 0x54, 0x24,
        0x10, 0x4c, 0x8b, 0x44, 0x24, 0x18, 0x4c, 0x8b, 0x4c, 0x24, 0x20, 0x4c, 0x8b, 0xd1, 0x41,
        0xff, 0xe3,
    });
    ck_assert(syscalls_origin::looks_like_syscall_stub(read, jumper));
    ret = call_rel32(m, APP + 0x200, jumper);
    ck_assert_uint_eq(syscalls_origin::indirect_call(read, ret, STUB, syscalls_origin::STUB64_SIZE, false), jumper);

    // A wrapper that tail-calls the export: sub rsp; call log; add rsp; jmp NtAllocateVirtualMemory
    const address wrapper = APP + 0x3000;
    m.put(wrapper, cat({ { 0x48, 0x83, 0xec, 0x28, 0xe8 }, le(0x100, 4), { 0x48, 0x83, 0xc4, 0x28, 0xe9 }, le(0x200, 4) }));
    ck_assert(!syscalls_origin::looks_like_syscall_stub(read, wrapper));
    ret = call_rel32(m, APP + 0x300, wrapper);
    ck_assert_uint_eq(syscalls_origin::indirect_call(read, ret, STUB, syscalls_origin::STUB64_SIZE, false), 0);

    // ntdll's stub is no stub of the sample's
    ck_assert(!syscalls_origin::looks_like_syscall_stub(read, STUB));
}
END_TEST

START_TEST(test_origin_wow64)
{
    memory m;
    const auto read = m.reader();
    // 32-bit ntdll!NtClose: mov eax, 3000Fh; mov edx, Wow64SystemServiceCall; call edx; ret 4
    const address stub = 0x77d42b30;
    m.put(stub, { 0xb8, 0x0f, 0x00, 0x03, 0x00, 0xba, 0xb0, 0xa8, 0xd5, 0x77, 0xff, 0xd2, 0xc2, 0x04, 0x00 });
    ck_assert(syscalls_origin::is_stub32(read, stub + syscalls_origin::STUB32_CALLER));
    ck_assert(!syscalls_origin::is_stub32(read, stub + 5));

    // call [__imp__NtClose@4], an absolute address in 32-bit code
    m.put(0x00402000, le(stub, 4));
    m.put(0x00401000, { 0xff, 0x15, 0x00, 0x20, 0x40, 0x00 });
    ck_assert_uint_eq(syscalls_origin::call_target(read, 0x00401006, true, stub), stub);
    ck_assert_uint_eq(syscalls_origin::indirect_call(read, 0x00401006, stub, syscalls_origin::STUB32_CALLER, true), 0);

    // A call to the stub's mov edx, past its start
    const address ret = call_rel32(m, 0x00401100, stub + 5);
    ck_assert_uint_eq(syscalls_origin::indirect_call(read, ret, stub, syscalls_origin::STUB32_CALLER, true), stub + 5);
}
END_TEST

Suite* syscall_origin_suite(void)
{
    Suite* s = suite_create("Where a Windows syscall was made from");
    TCase* tc = tcase_create("Core");
    tcase_add_test(tc, test_origin_stub64);
    tcase_add_test(tc, test_origin_calls_that_reach_the_stub);
    tcase_add_test(tc, test_origin_indirect_syscalls);
    tcase_add_test(tc, test_origin_wow64);
    suite_add_tcase(s, tc);
    return s;
}

int main(void)
{
    int number_failed;
    Suite* s;
    SRunner* sr;

    s = syscall_parameters_suite();
    sr = srunner_create(s);
    srunner_add_suite(sr, syscall_parameters_suite());
    srunner_add_suite(sr, syscall_origin_suite());

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
