#include <fstream>
#include <sstream>
#include <stdexcept>

#include <libdrakvuf/libdrakvuf.h>

#include "utils.hpp"
#include "libusermode/printers/printers.hpp"

bool is_so_name_matched(const std::string& so_path, const std::string& pattern)
{
    if (pattern.empty())
        return false;

    // A pattern containing a '/' is treated as a path suffix, and has to land
    // on a path boundary so "lib/libc.so.6" doesn't match "notlib/libc.so.6".
    if (pattern.find('/') != std::string::npos)
    {
        if (pattern.size() > so_path.size())
            return false;

        const size_t start = so_path.size() - pattern.size();
        if (so_path.compare(start, pattern.size(), pattern) != 0)
            return false;

        return start == 0 || so_path[start - 1] == '/';
    }

    // A bare name matches a prefix of the basename, so that "libssl.so" also
    // matches a versioned "libssl.so.3" while "libc.so.6" still matches
    // exactly. A plain suffix match would fail on every versioned soname.
    const size_t slash = so_path.find_last_of('/');
    const std::string basename = (slash == std::string::npos) ? so_path : so_path.substr(slash + 1);

    return basename.compare(0, pattern.size(), pattern) == 0;
}

void wanted_so_hooks_t::add_hook(plugin_target_config_entry_t entry)
{
    auto& entries = this->hooks[entry.dll_name];
    entries.push_back(std::move(entry));
}

void wanted_so_hooks_t::visit_hooks_for(const std::string& so_path,
    const std::function<void(const plugin_target_config_entry_t&)>& visitor) const
{
    for (const auto& [pattern, entries] : this->hooks)
    {
        if (!is_so_name_matched(so_path, pattern))
            continue;

        for (const auto& entry : entries)
            visitor(entry);
    }
}

void load_so_hook_config(const char* path, bool print_no_addr, wanted_so_hooks_t& wanted_hooks)
{
    if (!path)
        return;

    std::ifstream file(path);
    if (!file)
    {
        PRINT_DEBUG("[LIBMON] Failed to open so-hooks-list '%s'\n", path);
        return;
    }

    PrinterConfig printer_config{print_no_addr, PrinterConfig::NumericFormat::HEX};

    std::string line;
    while (std::getline(file, line))
    {
        if (line.empty() || line[0] == '#')
            continue;

        std::stringstream ss(line);
        try
        {
            wanted_hooks.add_hook(parse_entry(ss, printer_config));
        }
        catch (const std::exception& e)
        {
            PRINT_DEBUG("[LIBMON] %s: skipping malformed entry '%s' (%s)\n", path, line.c_str(), e.what());
        }
    }
}
