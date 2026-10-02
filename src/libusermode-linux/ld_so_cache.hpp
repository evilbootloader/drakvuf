#ifndef _INCLUDE_LD_SO_CACHE
#define _INCLUDE_LD_SO_CACHE

#include <cstddef>
#include <cstdint>
#include <map>

// Where the two addresses the rendezvous protocol needs sit inside ld.so, as
// offsets from the load address the aux vector reports in AT_BASE.
//
// Both are properties of the ld.so *build*, not of the process: ASLR moves the
// base, not the layout. So once they have been read out of one process, every
// later process running the same ld.so can be armed from them without waiting
// to read anything out of it -- which matters because what a freshly exec'd
// process makes us wait for is exactly these two reads.
struct ld_so_layout
{
    uint64_t r_debug_off = 0;   // &_r_debug - ld_base
    uint64_t r_brk_off = 0;     // r_debug.r_brk - ld_base, i.e. &_dl_debug_state
};

// The bytes of ld.so that identify a build: its ELF64 header, all of it.
static constexpr size_t LD_SO_EHDR_SIZE = 64;

// Not a description of ld.so, which is a few hundred KB: a bound loose enough
// to never reject a real linker and tight enough to reject a field read out of
// an r_debug that was not initialised yet, or out of the wrong address.
static constexpr uint64_t LD_SO_MAX_SPAN = 16ull << 20;

/*
 * Identify an ld.so build from the ELF header at its load address.
 *
 * The offsets in ld_so_layout are only meaningful for the exact file they were
 * learned from, and ld.so text is shared through the page cache, so applying
 * them to a different build would put a breakpoint at a wrong offset in a page
 * every process on the guest executes. An INT3 landing mid-instruction there
 * corrupts the guest rather than merely missing a hook, so which build this is
 * has to be settled before the offsets are used, not after.
 *
 * The ELF header settles it in one 64-byte read. It carries e_entry, e_phoff,
 * e_shoff and e_shnum, so two builds whose code differs at all differ here,
 * and two files that agree on all of it are the same build whatever their
 * paths say -- a stronger check than the path comparison the cold-page donor
 * search makes, and cheaper. It is also in a page ld.so touches early: it
 * reads its own e_phoff/e_phnum through __ehdr_start while setting up its link
 * map, well before any library is loaded.
 *
 * Returns 0 for anything that is not an x86-64 ELF64 shared object, which
 * callers treat as "do not cache this and do not arm from it".
 */
inline uint64_t ld_so_key(const uint8_t* ehdr)
{
    if (!ehdr)
        return 0;

    if (ehdr[0] != 0x7f || ehdr[1] != 'E' || ehdr[2] != 'L' || ehdr[3] != 'F')
        return 0;

    // EI_CLASS == ELFCLASS64, EI_DATA == ELFDATA2LSB.
    if (ehdr[4] != 2 || ehdr[5] != 1)
        return 0;

    // e_type == ET_DYN: ld.so is a shared object. e_machine == EM_X86_64,
    // since v1 is x86-64 only -- a 32-bit interpreter mapped by a compat
    // process would otherwise be cached with offsets nothing can use.
    const uint16_t e_type = (uint16_t)ehdr[16] | ((uint16_t)ehdr[17] << 8);
    const uint16_t e_machine = (uint16_t)ehdr[18] | ((uint16_t)ehdr[19] << 8);
    if (e_type != 3 || e_machine != 62)
        return 0;

    // FNV-1a over the whole header.
    uint64_t hash = 0xcbf29ce484222325ull;
    for (size_t i = 0; i < LD_SO_EHDR_SIZE; i++)
    {
        hash ^= ehdr[i];
        hash *= 0x100000001b3ull;
    }

    // 0 is reserved for "unusable", so a header that happens to hash to it
    // gets the next value rather than being thrown away.
    return hash ? hash : 1;
}

// Neither offset can be zero -- ld.so defines both symbols itself, so neither
// lands on its load address -- and neither can be past the end of any
// plausible linker. Both failures mean the fields were read before ld.so wrote
// them, or from the wrong place.
inline bool ld_so_layout_plausible(const ld_so_layout& layout)
{
    return layout.r_debug_off && layout.r_debug_off < LD_SO_MAX_SPAN
        && layout.r_brk_off && layout.r_brk_off < LD_SO_MAX_SPAN;
}

// What has been learned about each ld.so build on the guest, keyed by
// ld_so_key(). Small and long-lived: one entry per distinct linker, which on
// an ordinary guest means one, and on a guest running containers means one per
// base image.
class ld_so_cache
{
public:
    // Null until some process has given up a layout for this build.
    const ld_so_layout* find(uint64_t key) const
    {
        if (!key)
            return nullptr;

        auto it = this->entries.find(key);
        return it == this->entries.end() ? nullptr : &it->second;
    }

    // Keeps the first plausible layout seen for a build, and reports whether
    // this call was the one that added it, so the caller can count builds
    // rather than attempts.
    bool learn(uint64_t key, const ld_so_layout& layout)
    {
        if (!key || !ld_so_layout_plausible(layout))
            return false;

        return this->entries.emplace(key, layout).second;
    }

    // Drops a build's layout after a process it was applied to disagreed with
    // it, so nothing else is armed from it until it has been learned again.
    void forget(uint64_t key)
    {
        this->entries.erase(key);
    }

    size_t size() const
    {
        return this->entries.size();
    }

private:
    std::map<uint64_t, ld_so_layout> entries;
};

#endif