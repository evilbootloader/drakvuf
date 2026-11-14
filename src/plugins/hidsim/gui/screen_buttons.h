/*
 * Buttons read off the screen: what --hid-monitor-gui does on a guest whose
 * window manager cannot be walked (every one but Windows 7).
 *
 * The injector dumps the guest's frame through QMP every few seconds; the
 * monitor reads the frame, has the words on it recognised (tesseract, when
 * DRAKVUF was built with it) and picks one that reads as a button: a text
 * from a short list, standing alone, the size of a button. Its centre goes
 * to the injector, which moves the pointer there and clicks.
 *
 * It sees what a person at the screen sees and nothing else: no window
 * tree, no control classes. A word of the list standing alone anywhere on
 * screen is pressed, button or not.
 *
 * choose_button() and its helpers have no dependency on DRAKVUF or on the
 * OCR library: sandboxd's suite compiles screen_buttons_test.cpp and runs it.
 */

#ifndef HIDSIM_SCREEN_BUTTONS_H
#define HIDSIM_SCREEN_BUTTONS_H

#include <atomic>
#include <cstdint>
#include <string>
#include <vector>

/* A word as recognised on screen, with its box in pixels */
struct screen_word
{
    std::string text;
    int x, y, w, h;
};

/* A frame of the guest's screen: 3 bytes a pixel, rows top down */
struct screen_frame
{
    int width = 0;
    int height = 0;
    std::vector<uint8_t> rgb;
};

/* The texts pressed, lower case, most wanted first */
extern const char* const SCREEN_BUTTON_TEXTS[];
extern const size_t SCREEN_BUTTON_TEXTS_COUNT;

/* A recognised word as it is compared: lower case, letters and digits only */
std::string screen_normalize(const std::string& text);

/*
 * The button to press among the words of a frame, or false. label is the
 * list's text it matched, (cx, cy) its centre in pixels. skip, if given, is
 * asked about each candidate and may refuse it (one pressed moments ago).
 */
bool choose_button(const std::vector<screen_word>& words, int width, int height,
    int* cx, int* cy, std::string* label,
    bool (*skip)(const std::string& label, int cx, int cy, void* ctx) = nullptr,
    void* ctx = nullptr);

/* A P6 portable pixmap, as QEMU's screendump writes it. False if it is not one */
bool read_ppm(const char* path, screen_frame* frame);

/*
 * A frame as the sum of each SCREEN_BLOCK x SCREEN_BLOCK square of it (after
 * its width and height), and whether two differ by more than a pointer does:
 * the guest draws its pointer into the frame, so every frame differs from the
 * last in the few squares it left and entered.
 */
#define SCREEN_BLOCK 32
#define SCREEN_POINTER_BLOCKS 8
std::vector<uint32_t> frame_blocks(const screen_frame& frame);
bool frame_changed(const std::vector<uint32_t>& before, const std::vector<uint32_t>& after);

/*
 * The frame as a page for the recogniser: its text black on white, everything
 * else gone, SCREEN_TEXT_SCALE times the size (width and height are the
 * mask's, one byte a pixel).
 *
 * A recogniser trained on print does not read a screen: a label inside a
 * button's border is taken for a figure and skipped, light text on a dark
 * theme is missed, 11 pixel letters are too small. So: a pixel is ink where
 * it differs from the mean of the square around it, light or dark; connected
 * ink larger than a letter (borders, frames, pictures) is erased; and what is
 * left is enlarged.
 */
#define SCREEN_TEXT_SCALE 2
std::vector<uint8_t> screen_text_mask(const screen_frame& frame, int* width, int* height);

/* Whether this build can recognise text at all */
bool screen_monitor_available();

/*
 * The monitor thread: waits for the injector to announce a frame at path
 * (frames counts them), and posts the button it finds to coords as
 * x << 16 | y, in pixels. Returns when has_to_stop is set.
 */
int screen_monitor(const char* path, std::atomic<uint32_t>* frames,
    std::atomic<uint32_t>* coords, std::atomic<bool>* has_to_stop);

#endif
