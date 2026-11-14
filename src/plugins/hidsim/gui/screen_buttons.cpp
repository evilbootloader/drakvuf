/*
 * Buttons read off the screen. See screen_buttons.h.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>     /* HAVE_TESSERACT */
#endif

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <thread>
#include <utility>

#include "screen_buttons.h"

#pragma push_macro("HAVE_CONFIG_H")
#undef HAVE_CONFIG_H

#include <tesseract/baseapi.h>

#pragma pop_macro("HAVE_CONFIG_H")

/*
 * vmi_win_gui_filter_definitions.h's BTN_TEXTS, in the order they are wanted
 * when a screen shows several: what moves an installer on before what merely
 * agrees. Compared whole, never as a prefix: "ok" is not "okay then".
 */
const char* const SCREEN_BUTTON_TEXTS[] =
{
    "install", "next", "continue", "run", "execute", "launch", "extract",
    "allow access", "accept", "agree", "i agree", "yes", "ok", "enable",
    "try again", "download", "open", "finish", "go", "load", "click", "new",
};
const size_t SCREEN_BUTTON_TEXTS_COUNT =
    sizeof(SCREEN_BUTTON_TEXTS) / sizeof(SCREEN_BUTTON_TEXTS[0]);

/* A button's text is this tall at most, in pixels, and at least */
#define WORD_MAX_HEIGHT 64
#define WORD_MIN_HEIGHT 6
/* Its box is at most the screen's width over this (BTN_RATIO of the parser) */
#define BUTTON_RATIO 4
/* Seconds before a label pressed at a place is pressed there again */
#define PRESS_AGAIN_AFTER 30
/* Pixels within which two presses are the same place */
#define SAME_PLACE 24
/* What tesseract must make of a word (0 to 100) for it to count as read */
#define WORD_MIN_CONFIDENCE 60.0f

std::string screen_normalize(const std::string& text)
{
    std::string out;
    for (unsigned char c : text)
    {
        if (c >= 'A' && c <= 'Z')
            out += (char)(c - 'A' + 'a');
        else if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'))
            out += (char)c;
    }
    return out;
}

/* Whether b is on a's line: their vertical extents overlap by half of the shorter */
static bool same_line(const screen_word& a, const screen_word& b)
{
    int top = std::max(a.y, b.y);
    int bottom = std::min(a.y + a.h, b.y + b.h);
    return bottom - top > std::min(a.h, b.h) / 2;
}

/* The gap between a and the word right of it, negative if they overlap */
static int gap_after(const screen_word& a, const screen_word& b)
{
    return b.x - (a.x + a.w);
}

/*
 * Whether another word stands next to [left, right) on its line: a word
 * closer than its line is tall and a half is the same sentence's.
 */
static bool has_neighbour(const std::vector<screen_word>& words, size_t first,
    size_t last, const screen_word& box)
{
    int reach = box.h + box.h / 2;
    for (size_t i = 0; i < words.size(); i++)
    {
        if (i == first || i == last)
            continue;
        const screen_word& other = words[i];
        if (screen_normalize(other.text).empty() || !same_line(box, other))
            continue;
        int after = other.x - (box.x + box.w);
        int before = box.x - (other.x + other.w);
        if ((after >= 0 && after < reach) || (before >= 0 && before < reach) ||
            (after < 0 && before < 0))
            return true;
    }
    return false;
}

bool choose_button(const std::vector<screen_word>& words, int width, int height,
    int* cx, int* cy, std::string* label,
    bool (*skip)(const std::string&, int, int, void*), void* ctx)
{
    if (width <= 0 || height <= 0)
        return false;

    size_t best_rank = SCREEN_BUTTON_TEXTS_COUNT;
    screen_word best = {};
    bool found = false;

    for (size_t i = 0; i < words.size(); i++)
    {
        const std::string one = screen_normalize(words[i].text);
        if (one.empty())
            continue;

        /* The word alone, and with the word right of it on its line */
        for (size_t j = i; j < words.size() && j <= i + 1; j++)
        {
            screen_word box = words[i];
            std::string text = one;
            if (j != i)
            {
                const std::string two = screen_normalize(words[j].text);
                int gap = gap_after(words[i], words[j]);
                if (two.empty() || !same_line(words[i], words[j]) ||
                    gap < 0 || gap > words[i].h * 2)
                    continue;
                text = one + " " + two;
                box.w = words[j].x + words[j].w - box.x;
                box.y = std::min(words[i].y, words[j].y);
                box.h = std::max(words[i].y + words[i].h, words[j].y + words[j].h) - box.y;
            }

            if (box.h < WORD_MIN_HEIGHT || box.h > WORD_MAX_HEIGHT ||
                box.w <= 0 || box.w > width / BUTTON_RATIO ||
                box.x < 0 || box.y < 0 ||
                box.x + box.w > width || box.y + box.h > height)
                continue;

            size_t rank = 0;
            while (rank < SCREEN_BUTTON_TEXTS_COUNT && text != SCREEN_BUTTON_TEXTS[rank])
                rank++;
            if (rank == SCREEN_BUTTON_TEXTS_COUNT || has_neighbour(words, i, j, box))
                continue;

            int x = box.x + box.w / 2;
            int y = box.y + box.h / 2;
            if (skip && skip(SCREEN_BUTTON_TEXTS[rank], x, y, ctx))
                continue;

            /* The most wanted text; of two alike, the lower one, then the right one */
            if (!found || rank < best_rank ||
                (rank == best_rank && (box.y > best.y || (box.y == best.y && box.x > best.x))))
            {
                found = true;
                best_rank = rank;
                best = box;
            }
        }
    }

    if (!found)
        return false;
    *cx = best.x + best.w / 2;
    *cy = best.y + best.h / 2;
    if (label)
        *label = SCREEN_BUTTON_TEXTS[best_rank];
    return true;
}

/* One token of a PPM header: comments and white space skipped */
static bool ppm_number(FILE* f, long* value)
{
    int c;
    for (;;)
    {
        c = fgetc(f);
        if (c == '#')
            while ((c = fgetc(f)) != EOF && c != '\n') {}
        else if (c != ' ' && c != '\t' && c != '\n' && c != '\r')
            break;
    }
    if (c < '0' || c > '9')
        return false;
    long v = 0;
    int digits = 0;
    while (c >= '0' && c <= '9' && digits++ < 6)
    {
        v = v * 10 + (c - '0');
        c = fgetc(f);
    }
    *value = v;
    /* c is the single white space after the token (or the header is not one) */
    return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

bool read_ppm(const char* path, screen_frame* frame)
{
    /* As get_display_dimensions(): nothing above 8K is a screen */
    const long limit = 7680;
    FILE* f = fopen(path, "rb");
    if (!f)
        return false;

    long width = 0, height = 0, maxval = 0;
    bool ok = fgetc(f) == 'P' && fgetc(f) == '6' &&
        ppm_number(f, &width) && ppm_number(f, &height) && ppm_number(f, &maxval) &&
        width > 0 && height > 0 && width <= limit && height <= limit && maxval == 255;
    if (ok)
    {
        size_t size = (size_t)width * (size_t)height * 3;
        frame->rgb.resize(size);
        ok = fread(frame->rgb.data(), 1, size, f) == size;
    }
    fclose(f);
    if (!ok)
        return false;
    frame->width = (int)width;
    frame->height = (int)height;
    return true;
}

std::vector<uint32_t> frame_blocks(const screen_frame& frame)
{
    const int bw = (frame.width + SCREEN_BLOCK - 1) / SCREEN_BLOCK;
    const int bh = (frame.height + SCREEN_BLOCK - 1) / SCREEN_BLOCK;
    std::vector<uint32_t> blocks((size_t)bw * bh + 2, 0);
    blocks[0] = (uint32_t)frame.width;
    blocks[1] = (uint32_t)frame.height;
    for (int y = 0; y < frame.height; y++)
    {
        const uint8_t* row = frame.rgb.data() + (size_t)y * frame.width * 3;
        uint32_t* out = blocks.data() + 2 + (size_t)(y / SCREEN_BLOCK) * bw;
        for (int x = 0; x < frame.width; x++)
            out[x / SCREEN_BLOCK] += row[3 * x] + row[3 * x + 1] + row[3 * x + 2];
    }
    return blocks;
}

bool frame_changed(const std::vector<uint32_t>& before, const std::vector<uint32_t>& after)
{
    if (before.size() != after.size() || before.size() < 2 ||
        before[0] != after[0] || before[1] != after[1])
        return true;
    int differ = 0;
    for (size_t i = 2; i < before.size(); i++)
        if (before[i] != after[i] && ++differ > SCREEN_POINTER_BLOCKS)
            return true;
    return false;
}

/* Ink is this far from the mean brightness around it (0 to 255) */
#define INK_CONTRAST 40
/* Half the side of the square that mean is taken over, in pixels */
#define INK_RADIUS 12
/* A letter is at most this wide and tall, and at least this tall, in pixels */
#define GLYPH_MAX_WIDTH 48
#define GLYPH_MAX_HEIGHT 48
#define GLYPH_MIN_HEIGHT 4

std::vector<uint8_t> screen_text_mask(const screen_frame& frame, int* width, int* height)
{
    const int w = frame.width, h = frame.height;
    *width = w * SCREEN_TEXT_SCALE;
    *height = h * SCREEN_TEXT_SCALE;
    std::vector<uint8_t> page((size_t)*width * *height, 255);
    if (w <= 0 || h <= 0 || frame.rgb.size() < (size_t)w * h * 3)
        return page;

    /* Brightness, and its sums over every rectangle from the corner */
    std::vector<uint8_t> gray((size_t)w * h);
    std::vector<uint32_t> sums((size_t)(w + 1) * (h + 1), 0);
    for (int y = 0; y < h; y++)
    {
        uint32_t row = 0;
        for (int x = 0; x < w; x++)
        {
            const uint8_t* px = frame.rgb.data() + ((size_t)y * w + x) * 3;
            uint8_t g = (uint8_t)((px[0] * 30 + px[1] * 59 + px[2] * 11) / 100);
            gray[(size_t)y * w + x] = g;
            row += g;
            sums[(size_t)(y + 1) * (w + 1) + x + 1] = sums[(size_t)y * (w + 1) + x + 1] + row;
        }
    }

    /* Ink: 0 none, 1 ink not yet looked at */
    std::vector<uint8_t> ink((size_t)w * h, 0);
    for (int y = 0; y < h; y++)
    {
        int y0 = std::max(0, y - INK_RADIUS), y1 = std::min(h, y + INK_RADIUS + 1);
        for (int x = 0; x < w; x++)
        {
            int x0 = std::max(0, x - INK_RADIUS), x1 = std::min(w, x + INK_RADIUS + 1);
            uint32_t total = sums[(size_t)y1 * (w + 1) + x1] - sums[(size_t)y0 * (w + 1) + x1]
                - sums[(size_t)y1 * (w + 1) + x0] + sums[(size_t)y0 * (w + 1) + x0];
            int mean = (int)(total / (uint32_t)((y1 - y0) * (x1 - x0)));
            if (std::abs((int)gray[(size_t)y * w + x] - mean) > INK_CONTRAST)
                ink[(size_t)y * w + x] = 1;
        }
    }

    /* Each connected piece of ink: kept if it is the size of a letter */
    std::vector<uint32_t> stack, piece;
    for (int sy = 0; sy < h; sy++)
    {
        for (int sx = 0; sx < w; sx++)
        {
            if (ink[(size_t)sy * w + sx] != 1)
                continue;
            int left = sx, right = sx, top = sy, bottom = sy;
            piece.clear();
            stack.assign(1, (uint32_t)(sy * w + sx));
            ink[(size_t)sy * w + sx] = 2;
            while (!stack.empty())
            {
                uint32_t at = stack.back();
                stack.pop_back();
                piece.push_back(at);
                int x = (int)(at % (uint32_t)w), y = (int)(at / (uint32_t)w);
                left = std::min(left, x);
                right = std::max(right, x);
                top = std::min(top, y);
                bottom = std::max(bottom, y);
                for (int ny = std::max(0, y - 1); ny <= std::min(h - 1, y + 1); ny++)
                {
                    for (int nx = std::max(0, x - 1); nx <= std::min(w - 1, x + 1); nx++)
                    {
                        size_t n = (size_t)ny * w + nx;
                        if (ink[n] == 1)
                        {
                            ink[n] = 2;
                            stack.push_back((uint32_t)n);
                        }
                    }
                }
            }
            int pw = right - left + 1, ph = bottom - top + 1;
            if (pw > GLYPH_MAX_WIDTH || ph > GLYPH_MAX_HEIGHT || ph < GLYPH_MIN_HEIGHT)
                continue;
            for (uint32_t at : piece)
            {
                int x = (int)(at % (uint32_t)w), y = (int)(at / (uint32_t)w);
                for (int dy = 0; dy < SCREEN_TEXT_SCALE; dy++)
                    for (int dx = 0; dx < SCREEN_TEXT_SCALE; dx++)
                        page[(size_t)(y * SCREEN_TEXT_SCALE + dy) * *width + x * SCREEN_TEXT_SCALE + dx] = 0;
            }
        }
    }
    return page;
}

#ifdef HAVE_TESSERACT

bool screen_monitor_available()
{
    return true;
}

/* The words tesseract finds on the frame */
static void recognise(tesseract::TessBaseAPI* ocr, const screen_frame& frame,
    std::vector<screen_word>* words)
{
    const tesseract::PageIteratorLevel level = tesseract::RIL_WORD;

    int width, height;
    const std::vector<uint8_t> page = screen_text_mask(frame, &width, &height);
    const int k = SCREEN_TEXT_SCALE;

    words->clear();
    ocr->SetImage(page.data(), width, height, 1, width);
    if (ocr->Recognize(nullptr) != 0)
        return;

    tesseract::ResultIterator* ri = ocr->GetIterator();
    if (ri)
    {
        do
        {
            int left, top, right, bottom;
            char* text = ri->GetUTF8Text(level);
            if (!text)
                continue;
            if (ri->BoundingBox(level, &left, &top, &right, &bottom) &&
                ri->Confidence(level) >= WORD_MIN_CONFIDENCE)
                words->push_back({text, left / k, top / k, (right - left) / k, (bottom - top) / k});
            delete[] text;
        } while (ri->Next(level));
        delete ri;
    }
    ocr->Clear();
}

/* What was pressed, where and when: a dialog that stays is not hammered */
struct pressed
{
    std::string label;
    int x, y;
    std::chrono::steady_clock::time_point at;
};

static bool pressed_lately(const std::string& label, int x, int y, void* ctx)
{
    const auto* list = static_cast<std::vector<pressed>*>(ctx);
    const auto now = std::chrono::steady_clock::now();
    for (const pressed& p : *list)
        if (p.label == label && std::abs(p.x - x) < SAME_PLACE && std::abs(p.y - y) < SAME_PLACE &&
            now - p.at < std::chrono::seconds(PRESS_AGAIN_AFTER))
            return true;
    return false;
}

int screen_monitor(const char* path, std::atomic<uint32_t>* frames,
    std::atomic<uint32_t>* coords, std::atomic<bool>* has_to_stop)
{
    /* Before the recogniser loads its data: a frame dumped meanwhile is read */
    uint32_t seen = frames->load();

    tesseract::TessBaseAPI tess;
    tesseract::TessBaseAPI* ocr = &tess;
    if (ocr->Init(nullptr, "eng") != 0)
    {
        fprintf(stderr, "[HIDSIM] [MONITOR] No English data for tesseract "
            "(tesseract-ocr-eng): the screen is not read\n");
        return -1;
    }
    /* Words wherever they are, in no order: a screen is not a page */
    ocr->SetPageSegMode(tesseract::PSM_SPARSE_TEXT);
    /* Its own remarks ("Estimating resolution as ...") are not DRAKVUF's */
    ocr->SetVariable("debug_file", "/dev/null");

    std::vector<uint32_t> last;
    auto read_at = std::chrono::steady_clock::now();
    screen_frame frame;
    std::vector<screen_word> words;
    std::vector<pressed> history;

    while (!has_to_stop->load())
    {
        if (frames->load() == seen)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }
        seen = frames->load();

        /* A frame that cannot be read is the next one's problem */
        if (!read_ppm(path, &frame))
            continue;
        /*
         * Recognition costs a second of a core: only a frame that changed by
         * more than the pointer is read, and one that stays is read again
         * when a button pressed on it and still there may be pressed again.
         */
        std::vector<uint32_t> blocks = frame_blocks(frame);
        const auto started = std::chrono::steady_clock::now();
        if (!frame_changed(last, blocks) &&
            started - read_at < std::chrono::seconds(PRESS_AGAIN_AFTER))
            continue;
        last = std::move(blocks);
        read_at = started;

        recognise(ocr, frame, &words);

        int x, y;
        std::string label;
        if (choose_button(words, frame.width, frame.height, &x, &y, &label, pressed_lately, &history))
        {
            const auto now = std::chrono::steady_clock::now();
            history.erase(std::remove_if(history.begin(), history.end(), [&](const pressed& p)
            {
                return now - p.at >= std::chrono::seconds(PRESS_AGAIN_AFTER);
            }), history.end());
            history.push_back({label, x, y, now});
            fprintf(stderr, "[HIDSIM] [MONITOR] \"%s\" at %d x %d\n", label.c_str(), x, y);
            coords->store((uint32_t)x << 16 | (uint32_t)y);
        }
    }

    ocr->End();
    return 0;
}

#else /* !HAVE_TESSERACT */

bool screen_monitor_available()
{
    return false;
}

int screen_monitor(const char*, std::atomic<uint32_t>*, std::atomic<uint32_t>*, std::atomic<bool>*)
{
    return -1;
}

#endif
