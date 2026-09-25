#ifndef _INCLUDE_LIBUSERMODE_LINUX_UTILS
#define _INCLUDE_LIBUSERMODE_LINUX_UTILS

#include <functional>
#include <map>
#include <string>
#include <vector>

// plugin_target_config_entry_t and parse_entry are shared with libusermode:
// the --so-hooks-list line grammar is the same as --dll-hooks-list, only the
// first field names a shared object rather than a DLL.
#include "libusermode/utils.hpp"

// Matches a mapped shared object's path against a config pattern, so that
// "libc.so.6" matches "/lib/x86_64-linux-gnu/libc.so.6" and "libssl.so" also
// matches a versioned "libssl.so.3". libusermode's is_dll_name_matched()
// can't be reused: it only treats '\' as a path separator, matches
// case-insensitively, and requires an exact suffix, which fails on every
// versioned soname.
bool is_so_name_matched(const std::string& so_path, const std::string& pattern);

class wanted_so_hooks_t
{
public:
    void add_hook(plugin_target_config_entry_t entry);

    bool empty() const noexcept
    {
        return hooks.empty();
    }

    void visit_hooks_for(const std::string& so_path,
        const std::function<void(const plugin_target_config_entry_t&)>& visitor) const;

private:
    std::map<std::string, std::vector<plugin_target_config_entry_t>> hooks;
};

// Reads a --so-hooks-list file. Blank lines and '#' comments are skipped; a
// line that fails to parse is reported and skipped rather than aborting the
// whole config.
void load_so_hook_config(const char* path, bool print_no_addr, wanted_so_hooks_t& wanted_hooks);

#endif
