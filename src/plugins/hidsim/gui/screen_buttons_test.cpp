/*
 * choose_button(), read_ppm() and frame_changed() on their own: no DRAKVUF,
 * no OCR. sandboxd/tests/test_hidsim_screen_buttons.py compiles and runs it:
 *
 *   g++ -std=c++17 -Wall -Wextra -Werror screen_buttons.cpp screen_buttons_test.cpp -o t && ./t
 */

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "screen_buttons.h"

static int failures = 0;

#define CHECK(what) do { if (!(what)) { failures++; fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #what); } } while (0)

static std::string pressed(const std::vector<screen_word>& words, int* x = nullptr, int* y = nullptr)
{
    int cx = 0, cy = 0;
    std::string label;
    if (!choose_button(words, 1920, 1080, &cx, &cy, &label))
        return "";
    if (x) *x = cx;
    if (y) *y = cy;
    return label;
}

static bool never_ok(const std::string& label, int, int, void*)
{
    return label == "ok";
}

int main()
{
    int x = 0, y = 0;

    /* A message box: a sentence, and a button under it */
    std::vector<screen_word> box =
    {
        {"The", 700, 500, 30, 14}, {"operation", 736, 500, 70, 14}, {"completed", 812, 500, 72, 14},
        {"OK", 940, 560, 22, 14},
    };
    CHECK(pressed(box, &x, &y) == "ok");
    CHECK(x == 951 && y == 567);

    /* The same word inside a sentence is not a button */
    CHECK(pressed({{"Click", 100, 100, 40, 14}, {"OK", 146, 100, 22, 14}, {"to", 174, 100, 14, 14},
                   {"continue", 194, 100, 60, 14}}) == "");

    /* An installer's row of buttons: the one that moves it on, with its accelerator mark */
    CHECK(pressed({{"<", 1000, 700, 8, 14}, {"Back", 1012, 700, 34, 14}, {"Next", 1120, 700, 30, 14},
                   {">", 1154, 700, 8, 14}, {"Cancel", 1230, 700, 46, 14}}) == "next");
    CHECK(pressed({{"&Install", 1120, 700, 50, 14}, {"Cancel", 1230, 700, 46, 14}}) == "install");

    /* Two words that are one label; a word of it alone is not */
    CHECK(pressed({{"Try", 900, 600, 24, 14}, {"again", 930, 600, 40, 14}}) == "try again");
    CHECK(pressed({{"Allow", 900, 600, 38, 14}, {"access", 944, 600, 46, 14}}) == "allow access");
    CHECK(pressed({{"again", 930, 600, 40, 14}}) == "");

    /* Not a prefix, and not a word that only looks like one */
    CHECK(pressed({{"Okay", 940, 560, 36, 14}}) == "");
    CHECK(pressed({{"Runtime", 940, 560, 60, 14}}) == "");

    /* A heading is not a button, nor is a speck */
    CHECK(pressed({{"Install", 100, 100, 600, 120}}) == "");
    CHECK(pressed({{"OK", 940, 560, 4, 3}}) == "");

    /* Of two of a kind the lower; one refused is passed over */
    const std::vector<screen_word> two = {{"OK", 300, 200, 22, 14}, {"OK", 940, 560, 22, 14}};
    CHECK(pressed(two, &x, &y) == "ok" && y == 567);
    std::string label;
    const std::vector<screen_word> either = {{"OK", 940, 560, 22, 14}, {"Yes", 800, 560, 26, 14}};
    const std::vector<screen_word> only = {{"OK", 940, 560, 22, 14}};
    CHECK(choose_button(either, 1920, 1080, &x, &y, &label, never_ok, nullptr) && label == "yes");
    CHECK(!choose_button(only, 1920, 1080, &x, &y, &label, never_ok, nullptr));

    /* A box outside the frame is no place to click */
    CHECK(pressed({{"OK", 1915, 560, 22, 14}}) == "");

    /* QEMU's screendump: P6, a comment allowed, 255, then the pixels */
    const char* path = "screen_buttons_test.ppm";
    FILE* f = fopen(path, "wb");
    fputs("P6\n# a comment\n4 2\n255\n", f);
    for (int i = 0; i < 24; i++)
        fputc(i, f);
    fclose(f);
    screen_frame frame;
    CHECK(read_ppm(path, &frame) && frame.width == 4 && frame.height == 2 &&
        frame.rgb.size() == 24 && frame.rgb[23] == 23);
    f = fopen(path, "wb");
    fputs("P6\n4 2\n255\n", f);           /* no pixels */
    fclose(f);
    CHECK(!read_ppm(path, &frame));
    f = fopen(path, "wb");
    fputs("P6\n99999 99999\n255\n", f);   /* no screen */
    fclose(f);
    CHECK(!read_ppm(path, &frame));
    remove(path);
    CHECK(!read_ppm("no-such-file.ppm", &frame));

    /* A pointer's worth of change is no change; a dialog's is */
    screen_frame a;
    a.width = 640;
    a.height = 480;
    a.rgb.assign(640 * 480 * 3, 10);
    screen_frame b = a;
    for (int py = 100; py < 120; py++)
        for (int px = 200; px < 212; px++)
            b.rgb[(py * 640 + px) * 3] = 250;
    CHECK(!frame_changed(frame_blocks(a), frame_blocks(b)));
    for (int py = 150; py < 330; py++)
        for (int px = 160; px < 480; px++)
            b.rgb[(py * 640 + px) * 3 + 1] = 200;
    CHECK(frame_changed(frame_blocks(a), frame_blocks(b)));
    screen_frame c = a;
    c.width = 480;
    c.height = 640;
    CHECK(frame_changed(frame_blocks(a), frame_blocks(c)));
    CHECK(frame_changed({}, frame_blocks(a)));

    /* The page for the recogniser: a letter stays, a border goes, dark themes too */
    for (int dark = 0; dark < 2; dark++)
    {
        screen_frame page;
        page.width = 200;
        page.height = 100;
        page.rgb.assign(200 * 100 * 3, dark ? 30 : 240);
        auto paint = [&](int px, int py)
        {
            for (int ch = 0; ch < 3; ch++)
                page.rgb[(py * 200 + px) * 3 + ch] = dark ? 230 : 20;
        };
        for (int py = 40; py < 50; py++)        /* a stem, the size of a letter's */
            for (int px = 100; px < 102; px++)
                paint(px, py);
        for (int px = 20; px < 180; px++)       /* a button's border */
            paint(px, 20);
        int w = 0, h = 0;
        std::vector<uint8_t> mask = screen_text_mask(page, &w, &h);
        CHECK(w == 200 * SCREEN_TEXT_SCALE && h == 100 * SCREEN_TEXT_SCALE);
        CHECK(mask[(45 * SCREEN_TEXT_SCALE) * w + 100 * SCREEN_TEXT_SCALE] == 0);
        CHECK(mask[(20 * SCREEN_TEXT_SCALE) * w + 100 * SCREEN_TEXT_SCALE] == 255);
        CHECK(mask[(70 * SCREEN_TEXT_SCALE) * w + 100 * SCREEN_TEXT_SCALE] == 255);
    }

    if (failures)
        return 1;
    puts("ok");
    return 0;
}
