#include "module_map.hpp"

#include <cstdlib>

#include <check.h>

// ck_assert_str_eq() binds its argument to a const char*, so handing it
// .c_str() of a temporary string would dangle. Compare inside instead.
static bool resolves_to(const so_map_t& libs, addr_t addr, const char* expect)
{
    auto found = resolve_module_in(libs, addr);
    return found.has_value() && *found == expect;
}

// A plausible process layout: ld.so high, libc below it, and the main
// executable at the usual PIE base. Extents are the real ones for a
// Debian trixie glibc 2.41, from its PT_LOAD headers.
static so_map_t sample_layout()
{
    return
    {
        { 0x555555554000, { "/bin/cat",                              0x555555558000 } },
        { 0x7ffff7c00000, { "/lib/x86_64-linux-gnu/libc.so.6",       0x7ffff7e21000 } },
        { 0x7ffff7fc5000, { "/lib64/ld-linux-x86-64.so.2",           0x7ffff7ffc000 } },
    };
}

START_TEST(test_resolve_hit)
{
    auto libs = sample_layout();

    // at the load address, inside, and at the last byte
    ck_assert(resolves_to(libs, 0x7ffff7c00000, "/lib/x86_64-linux-gnu/libc.so.6"));
    ck_assert(resolves_to(libs, 0x7ffff7c89d42, "/lib/x86_64-linux-gnu/libc.so.6"));
    ck_assert(resolves_to(libs, 0x7ffff7e20fff, "/lib/x86_64-linux-gnu/libc.so.6"));

    ck_assert(resolves_to(libs, 0x555555554100, "/bin/cat"));
    ck_assert(resolves_to(libs, 0x7ffff7fc5000, "/lib64/ld-linux-x86-64.so.2"));
}
END_TEST

START_TEST(test_resolve_miss)
{
    auto libs = sample_layout();

    // Below everything mapped.
    ck_assert(!resolve_module_in(libs, 0x1000).has_value());

    // One past libc's last byte: the gap before ld.so, which on a real
    // process holds libc's own anonymous mappings and the heap. This is the
    // case a nearest-load-address lookup gets wrong, attributing the whole
    // gap to libc.
    ck_assert(!resolve_module_in(libs, 0x7ffff7e21000).has_value());
    ck_assert(!resolve_module_in(libs, 0x7ffff7f00000).has_value());

    // The gap between the executable and libc.
    ck_assert(!resolve_module_in(libs, 0x555555600000).has_value());

    // Above everything: the stack.
    ck_assert(!resolve_module_in(libs, 0x7ffffffde000).has_value());

    // Nothing mapped at all.
    so_map_t empty;
    ck_assert(!resolve_module_in(empty, 0x7ffff7c00000).has_value());
}
END_TEST

START_TEST(test_resolve_unknown_extent)
{
    // end == 0 means the program headers could not be read, so the lookup
    // falls back to a size cap rather than refusing to attribute anything.
    so_map_t libs
    {
        { 0x7ffff7c00000, { "/lib/x86_64-linux-gnu/libc.so.6", 0 } },
    };

    ck_assert(resolves_to(libs, 0x7ffff7c89d42, "/lib/x86_64-linux-gnu/libc.so.6"));

    // Still bounded: past the cap it is something else.
    ck_assert(!resolve_module_in(libs, 0x7ffff7c00000 + MODULE_SPAN_CAP).has_value());
    ck_assert(resolve_module_in(libs, 0x7ffff7c00000 + MODULE_SPAN_CAP - 1).has_value());
}
END_TEST

START_TEST(test_resolve_adjacent)
{
    // Two libraries mapped back to back, which the loader does often enough:
    // the boundary belongs to the second, not the first.
    so_map_t libs
    {
        { 0x7ffff7c00000, { "first.so",  0x7ffff7d00000 } },
        { 0x7ffff7d00000, { "second.so", 0x7ffff7e00000 } },
    };

    ck_assert(resolves_to(libs, 0x7ffff7cfffff, "first.so"));
    ck_assert(resolves_to(libs, 0x7ffff7d00000, "second.so"));
    ck_assert(!resolve_module_in(libs, 0x7ffff7e00000).has_value());
}
END_TEST

static Suite* module_map_suite(void)
{
    Suite* s = suite_create("libmon module map");
    TCase* tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_resolve_hit);
    tcase_add_test(tc_core, test_resolve_miss);
    tcase_add_test(tc_core, test_resolve_unknown_extent);
    tcase_add_test(tc_core, test_resolve_adjacent);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    SRunner* sr = srunner_create(module_map_suite());

    srunner_run_all(sr, CK_NORMAL);
    int number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
