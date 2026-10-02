#include "utils.hpp"
#include "dl_rendezvous_abi.hpp"
#include "ld_so_cache.hpp"

// plugin_target_config_entry_t holds unique_ptr<ArgumentPrinter>, which
// utils.hpp only forward-declares; destroying one needs the complete type.
#include "libusermode/printers/printers.hpp"

#include <array>
#include <sstream>
#include <string>

#include <check.h>

START_TEST(test_match_so_name)
{
    // bare name: matches a prefix of the basename
    ck_assert(is_so_name_matched("/lib/x86_64-linux-gnu/libc.so.6", "libc.so.6"));
    ck_assert(is_so_name_matched("libc.so.6", "libc.so.6"));

    // versioned sonames: an unversioned pattern still matches
    ck_assert(is_so_name_matched("/usr/lib/x86_64-linux-gnu/libssl.so.3", "libssl.so"));
    ck_assert(is_so_name_matched("/lib/x86_64-linux-gnu/libc.so.6", "libc.so"));

    // must not match a different library that merely ends the same way
    ck_assert(!is_so_name_matched("/opt/evil/notlibc.so.6", "libc.so.6"));
    ck_assert(!is_so_name_matched("/lib/libmycrypto.so.3", "libcrypto.so"));

    // case-sensitive, unlike the Windows DLL equivalent
    ck_assert(!is_so_name_matched("/usr/lib/LIBC.so.6", "libc.so.6"));

    // pattern longer than the basename
    ck_assert(!is_so_name_matched("/lib/libc.so", "libc.so.6"));

    // path patterns: suffix match on a path boundary
    ck_assert(is_so_name_matched("/lib/x86_64-linux-gnu/libc.so.6", "x86_64-linux-gnu/libc.so.6"));
    ck_assert(!is_so_name_matched("/lib/x86_64-linux-gnu/libc.so.6", "linux-gnu/libc.so.6"));

    // degenerate input
    ck_assert(!is_so_name_matched("/lib/libc.so.6", ""));
    ck_assert(!is_so_name_matched("", "libc.so.6"));
}
END_TEST

START_TEST(test_so_hooks_lookup)
{
    wanted_so_hooks_t hooks;
    PrinterConfig config;

    for (auto entry_str :
        {
            "libc.so.6,open,log,Path:lpcstr,Flags:int",
            "libc.so.6,connect,log,Fd:int",
            "libssl.so,SSL_write,log,Ssl:lpvoid",
        })
    {
        std::stringstream ss(entry_str);
        hooks.add_hook(parse_entry(ss, config));
    }

    ck_assert(!hooks.empty());

    size_t libc_hits = 0;
    hooks.visit_hooks_for("/lib/x86_64-linux-gnu/libc.so.6",
        [&libc_hits](const plugin_target_config_entry_t&)
    {
        libc_hits++;
    });
    ck_assert_int_eq(libc_hits, 2);

    // versioned soname still reaches the unversioned "libssl.so" pattern
    size_t ssl_hits = 0;
    hooks.visit_hooks_for("/usr/lib/x86_64-linux-gnu/libssl.so.3",
        [&ssl_hits](const plugin_target_config_entry_t& e)
    {
        ssl_hits++;
        ck_assert(e.function_name == "SSL_write");
    });
    ck_assert_int_eq(ssl_hits, 1);

    size_t misses = 0;
    hooks.visit_hooks_for("/lib/x86_64-linux-gnu/libselinux.so.1",
        [&misses](const plugin_target_config_entry_t&)
    {
        misses++;
    });
    ck_assert_int_eq(misses, 0);
}
END_TEST

START_TEST(test_glibc_abi_offsets)
{
    // struct r_debug on x86-64: int r_version, then 8-byte aligned pointers.
    ck_assert_int_eq(R_DEBUG_VERSION, 0);
    ck_assert_int_eq(R_DEBUG_MAP, 8);
    ck_assert_int_eq(R_DEBUG_BRK, 16);
    ck_assert_int_eq(R_DEBUG_STATE, 24);
    ck_assert_int_eq(R_DEBUG_LDBASE, 32);

    ck_assert_int_eq(RT_CONSISTENT, 0);
    ck_assert_int_eq(RT_ADD, 1);
    ck_assert_int_eq(RT_DELETE, 2);

    // struct link_map on x86-64: five consecutive 8-byte fields.
    ck_assert_int_eq(LINK_MAP_ADDR, 0);
    ck_assert_int_eq(LINK_MAP_NAME, 8);
    ck_assert_int_eq(LINK_MAP_LD, 16);
    ck_assert_int_eq(LINK_MAP_NEXT, 24);
    ck_assert_int_eq(LINK_MAP_PREV, 32);

    ck_assert_int_eq(DT_DEBUG_TAG, 21);
}
END_TEST

// The ELF header of a Debian trixie /lib64/ld-linux-x86-64.so.2: ET_DYN,
// EM_X86_64, with the fields ld_so_key() leans on filled in.
static std::array<uint8_t, LD_SO_EHDR_SIZE> sample_ehdr()
{
    std::array<uint8_t, LD_SO_EHDR_SIZE> h{};

    h[0] = 0x7f;
    h[1] = 'E';
    h[2] = 'L';
    h[3] = 'F';
    h[4] = 2;       // ELFCLASS64
    h[5] = 1;       // ELFDATA2LSB
    h[6] = 1;       // EV_CURRENT
    h[16] = 3;      // e_type = ET_DYN
    h[18] = 62;     // e_machine = EM_X86_64
    h[24] = 0x40;   // e_entry = 0x1d940
    h[25] = 0xd9;
    h[26] = 0x01;
    h[32] = 0x40;   // e_phoff = 0x40
    h[40] = 0x18;   // e_shoff = 0x35918
    h[41] = 0x59;
    h[42] = 0x03;

    return h;
}

START_TEST(test_ld_so_key_identifies_a_build)
{
    auto h = sample_ehdr();

    const uint64_t key = ld_so_key(h.data());
    ck_assert(key != 0);

    // Stable: the same header is the same build however often it is read, and
    // from whichever process it was read.
    ck_assert(ld_so_key(h.data()) == key);

    // e_entry differing is a different build. This is the discrimination the
    // whole scheme rests on -- two linkers whose code differs cannot agree
    // here -- so a collision would be a breakpoint at a wrong offset in shared
    // text, not a missed hook.
    auto other = h;
    other[24] ^= 0x10;
    ck_assert(ld_so_key(other.data()) != key);

    // So is e_shoff, which moves with anything that changes the file's size.
    other = h;
    other[40] ^= 0x08;
    ck_assert(ld_so_key(other.data()) != key);
}
END_TEST

START_TEST(test_ld_so_key_rejects_unusable)
{
    auto h = sample_ehdr();

    ck_assert(ld_so_key(nullptr) == 0);

    // Not an ELF object at all: what a read of a page that is resident but is
    // not ld.so's first page looks like.
    auto bad = h;
    bad[1] = 'X';
    ck_assert(ld_so_key(bad.data()) == 0);

    // 32-bit, or big-endian: v1 handles neither, and caching offsets for one
    // would hand them to a process that cannot use them.
    bad = h;
    bad[4] = 1;     // ELFCLASS32
    ck_assert(ld_so_key(bad.data()) == 0);

    bad = h;
    bad[5] = 2;     // ELFDATA2MSB
    ck_assert(ld_so_key(bad.data()) == 0);

    // ET_EXEC rather than ET_DYN: a non-PIE executable, so not an interpreter.
    bad = h;
    bad[16] = 2;
    ck_assert(ld_so_key(bad.data()) == 0);

    // i386 interpreter, as a 32-bit process on an x86-64 guest maps.
    bad = h;
    bad[18] = 3;    // EM_386
    ck_assert(ld_so_key(bad.data()) == 0);

    // All zeroes, which is what a page reads as before anything writes it.
    std::array<uint8_t, LD_SO_EHDR_SIZE> empty{};
    ck_assert(ld_so_key(empty.data()) == 0);
}
END_TEST

START_TEST(test_layout_plausible)
{
    // Real offsets from a glibc 2.41 ld.so.
    ck_assert(ld_so_layout_plausible(ld_so_layout{ 0x3a1e0, 0x1a2c0 }));

    // Zero means the field was read before ld.so wrote it: ld.so defines both
    // symbols itself, so neither can sit on its load address.
    ck_assert(!ld_so_layout_plausible(ld_so_layout{ 0, 0x1a2c0 }));
    ck_assert(!ld_so_layout_plausible(ld_so_layout{ 0x3a1e0, 0 }));

    // Past the end of any linker: a pointer read out of the wrong place, or
    // r_brk still holding something that is not an ld.so address.
    ck_assert(!ld_so_layout_plausible(ld_so_layout{ 0x3a1e0, LD_SO_MAX_SPAN }));
    ck_assert(!ld_so_layout_plausible(ld_so_layout{ LD_SO_MAX_SPAN + 1, 0x1a2c0 }));
}
END_TEST

START_TEST(test_cache_learn_and_forget)
{
    ld_so_cache cache;
    const uint64_t key = ld_so_key(sample_ehdr().data());

    ck_assert(!cache.find(key));
    ck_assert_int_eq(cache.size(), 0);

    ck_assert(cache.learn(key, ld_so_layout{ 0x3a1e0, 0x1a2c0 }));
    ck_assert_int_eq(cache.size(), 1);

    const ld_so_layout* found = cache.find(key);
    ck_assert(found != nullptr);
    ck_assert(found->r_debug_off == 0x3a1e0);
    ck_assert(found->r_brk_off == 0x1a2c0);

    // Learning the same build twice reports no new build, so the counters
    // track builds rather than how many processes were read.
    ck_assert(!cache.learn(key, ld_so_layout{ 0x3a1e0, 0x1a2c0 }));
    ck_assert_int_eq(cache.size(), 1);

    // An unusable key and an implausible layout are both refused, so nothing
    // is ever armed from them.
    ck_assert(!cache.learn(0, ld_so_layout{ 0x3a1e0, 0x1a2c0 }));
    ck_assert(!cache.learn(key + 1, ld_so_layout{ 0x3a1e0, 0 }));
    ck_assert(!cache.find(0));
    ck_assert(!cache.find(key + 1));
    ck_assert_int_eq(cache.size(), 1);

    // What happens when a process disproves a layout: it goes, and the next
    // process of that build reads it again rather than inheriting it.
    cache.forget(key);
    ck_assert(!cache.find(key));
    ck_assert_int_eq(cache.size(), 0);
}
END_TEST

static Suite* so_matching_suite(void)
{
    Suite* s = suite_create("Match shared object names");
    TCase* tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_match_so_name);
    tcase_add_test(tc_core, test_so_hooks_lookup);
    suite_add_tcase(s, tc_core);

    return s;
}

static Suite* glibc_abi_suite(void)
{
    Suite* s = suite_create("glibc rendezvous ABI");
    TCase* tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_glibc_abi_offsets);
    suite_add_tcase(s, tc_core);

    return s;
}

static Suite* ld_so_cache_suite(void)
{
    Suite* s = suite_create("ld.so layout cache");
    TCase* tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_ld_so_key_identifies_a_build);
    tcase_add_test(tc_core, test_ld_so_key_rejects_unusable);
    tcase_add_test(tc_core, test_layout_plausible);
    tcase_add_test(tc_core, test_cache_learn_and_forget);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    SRunner* sr = srunner_create(so_matching_suite());
    srunner_add_suite(sr, glibc_abi_suite());
    srunner_add_suite(sr, ld_so_cache_suite());

    srunner_run_all(sr, CK_NORMAL);
    int number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
