
#ifndef _INCLUDE_DL_RENDEZVOUS_ABI
#define _INCLUDE_DL_RENDEZVOUS_ABI

// Hardcoded glibc/ld.so userspace ABI constants for x86-64 (v1: glibc only,
// not musl). These are NOT kernel-DWARF-profile-derived offsets -- the
// r_debug/link_map layout has been stable across glibc versions for decades
// (the same rendezvous protocol gdb/lldb depend on), so it's hardcoded here
// rather than read from a per-guest debug-info profile.
//
// Offsets taken from struct r_debug / struct link_map in glibc's elf/link.h,
// e.g. https://github.com/openlgtv/glibc/blob/master/elf/link.h

// struct r_debug (link.h), x86-64 layout:
//   int r_version;                          // offset 0 (padded to 8 for the pointer below)
//   struct link_map *r_map;                 // offset 8
//   ElfW(Addr) r_brk;                       // offset 16
//   enum { RT_CONSISTENT, RT_ADD, RT_DELETE } r_state; // offset 24 (padded to 8 below)
//   ElfW(Addr) r_ldbase;                    // offset 32
enum r_debug_offset
{
    R_DEBUG_VERSION = 0,
    R_DEBUG_MAP     = 8,
    R_DEBUG_BRK     = 16,
    R_DEBUG_STATE   = 24,
    R_DEBUG_LDBASE  = 32,
};

// Values of r_debug.r_state, read at R_DEBUG_STATE.
enum r_debug_state
{
    RT_CONSISTENT = 0, // mapping change is complete
    RT_ADD        = 1, // beginning to add a new object
    RT_DELETE     = 2, // beginning to remove an object mapping
};

// struct link_map (link.h), x86-64 layout:
//   ElfW(Addr) l_addr;                      // offset 0
//   char *l_name;                           // offset 8
//   ElfW(Dyn) *l_ld;                        // offset 16
//   struct link_map *l_next, *l_prev;       // offset 24, 32
enum link_map_offset
{
    LINK_MAP_ADDR = 0,
    LINK_MAP_NAME = 8,
    LINK_MAP_LD   = 16,
    LINK_MAP_NEXT = 24,
    LINK_MAP_PREV = 32,
};

// Elf64_Dyn tags relevant to locating r_debug from a PT_DYNAMIC segment.
// Not yet used by dl_rendezvous.cpp -- v1 resolves r_debug via ld.so's own
// _r_debug export as a shortcut (see dl_rendezvous::try_arm).
// Kept here for the planned v2 switch to reading DT_DEBUG out of the main
// executable's own dynamic section, which is more portable across libc/
// linker vendors than depending on a named export.
// Aux vector entry types (elf.h). AT_BASE holds the load address of the
// program interpreter, i.e. ld.so.
enum auxv_type
{
    AT_BASE_TYPE  = 7,  // load address of the interpreter (ld.so)
    AT_ENTRY_TYPE = 9,  // entry point of the main executable
};

enum dt_tag
{
    DT_DEBUG_TAG  = 0x15,
    DT_STRTAB_TAG = 5,
    DT_SYMTAB_TAG = 6,
    DT_STRSZ_TAG  = 0xa,
    DT_SYMENT_TAG = 0xb,
};

#endif
