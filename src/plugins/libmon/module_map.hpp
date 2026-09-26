#ifndef _INCLUDE_LIBMON_MODULE_MAP
#define _INCLUDE_LIBMON_MODULE_MAP

#include <map>
#include <optional>
#include <string>

#include <libdrakvuf/libdrakvuf.h>

// Attributing an address to the library it lies in. Kept apart from libmon
// itself because it is pure lookup over a snapshot, with no guest access, and
// so is the one part of the plugin that can be tested directly.

// A library mapped in a process: where it starts (the map key) and where it
// ends. The dynamic linker reports only the start, so the end comes from the
// PT_LOAD headers and is 0 when those could not be read.
struct loaded_so
{
    std::string path;
    addr_t end;
};

// Load address -> library, for one process.
using so_map_t = std::map<addr_t, loaded_so>;

// Fallback extent for a library whose program headers could not be read: no
// library is this large, so an address further than this past a load address
// belongs to something else entirely.
constexpr addr_t MODULE_SPAN_CAP = 0x10000000;

// Which library `addr` lies in, or nothing if it lies in none -- a heap
// block, a stack, or an anonymous mapping between two libraries.
inline std::optional<std::string> resolve_module_in(const so_map_t& loaded, addr_t addr)
{
    // First library loaded above addr; the one before it is the candidate.
    auto above = loaded.upper_bound(addr);
    if (above == loaded.begin())
        return std::nullopt;

    auto candidate = std::prev(above);
    addr_t end = candidate->second.end ? candidate->second.end
        : candidate->first + MODULE_SPAN_CAP;

    if (addr >= end)
        return std::nullopt;

    return candidate->second.path;
}

#endif
