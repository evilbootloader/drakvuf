#include "utils.hpp"
#include "dl_rendezvous_abi.hpp"

// plugin_target_config_entry_t holds unique_ptr<ArgumentPrinter>, which
// utils.hpp only forward-declares; destroying one needs the complete type.
#include "libusermode/printers/printers.hpp"

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

int main(void)
{
    SRunner* sr = srunner_create(so_matching_suite());
    srunner_add_suite(sr, glibc_abi_suite());

    srunner_run_all(sr, CK_NORMAL);
    int number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
