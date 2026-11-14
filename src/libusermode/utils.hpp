/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF (C) 2014-2024 Tamas K Lengyel.                                  *
 * Tamas K Lengyel is hereinafter referred to as the author.               *
 * This program is free software; you may redistribute and/or modify it    *
 * under the terms of the GNU General Public License as published by the   *
 * Free Software Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE   *
 * CLARIFICATIONS AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your   *
 * right to use, modify, and redistribute this software under certain      *
 * conditions.  If you wish to embed DRAKVUF technology into proprietary   *
 * software, alternative licenses can be acquired from the author.         *
 *                                                                         *
 * Note that the GPL places important restrictions on "derivative works",  *
 * yet it does not provide a detailed definition of that term.  To avoid   *
 * misunderstandings, we interpret that term as broadly as copyright law   *
 * allows.  For example, we consider an application to constitute a        *
 * derivative work for the purpose of this license if it does any of the   *
 * following with any software or content covered by this license          *
 * ("Covered Software"):                                                   *
 *                                                                         *
 * o Integrates source code from Covered Software.                         *
 *                                                                         *
 * o Reads or includes copyrighted data files.                             *
 *                                                                         *
 * o Is designed specifically to execute Covered Software and parse the    *
 * results (as opposed to typical shell or execution-menu apps, which will *
 * execute anything you tell them to).                                     *
 *                                                                         *
 * o Includes Covered Software in a proprietary executable installer.  The *
 * installers produced by InstallShield are an example of this.  Including *
 * DRAKVUF with other software in compressed or archival form does not     *
 * trigger this provision, provided appropriate open source decompression  *
 * or de-archiving software is widely available for no charge.  For the    *
 * purposes of this license, an installer is considered to include Covered *
 * Software even if it actually retrieves a copy of Covered Software from  *
 * another source during runtime (such as by downloading it from the       *
 * Internet).                                                              *
 *                                                                         *
 * o Links (statically or dynamically) to a library which does any of the  *
 * above.                                                                  *
 *                                                                         *
 * o Executes a helper program, module, or script to do any of the above.  *
 *                                                                         *
 * This list is not exclusive, but is meant to clarify our interpretation  *
 * of derived works with some common examples.  Other people may interpret *
 * the plain GPL differently, so we consider this a special exception to   *
 * the GPL that we apply to Covered Software.  Works which meet any of     *
 * these conditions must conform to all of the terms of this license,      *
 * particularly including the GPL Section 3 requirements of providing      *
 * source code and allowing free redistribution of the work as a whole.    *
 *                                                                         *
 * Any redistribution of Covered Software, including any derived works,    *
 * must obey and carry forward all of the terms of this license, including *
 * obeying all GPL rules and restrictions.  For example, source code of    *
 * the whole work must be provided and free redistribution must be         *
 * allowed.  All GPL references to "this License", are to be treated as    *
 * including the terms and conditions of this license text as well.        *
 *                                                                         *
 * Because this license imposes special exceptions to the GPL, Covered     *
 * Work may not be combined (even as part of a larger work) with plain GPL *
 * software.  The terms, conditions, and exceptions of this license must   *
 * be included as well.  This license is incompatible with some other open *
 * source licenses as well.  In some cases we can relicense portions of    *
 * DRAKVUF or grant special permissions to use it in other open source     *
 * software.  Please contact tamas.k.lengyel@gmail.com with any such       *
 * requests.  Similarly, we don't incorporate incompatible open source     *
 * software into Covered Software without special permission from the      *
 * copyright holders.                                                      *
 *                                                                         *
 * If you have any questions about the licensing restrictions on using     *
 * DRAKVUF in other works, are happy to help.  As mentioned above,         *
 * alternative license can be requested from the author to integrate       *
 * DRAKVUF into proprietary applications and appliances.  Please email     *
 * tamas.k.lengyel@gmail.com for further information.                      *
 *                                                                         *
 * If you have received a written license agreement or contract for        *
 * Covered Software stating terms other than these, you may choose to use  *
 * and redistribute Covered Software under those terms instead of these.   *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes.          *
 *                                                                         *
 * Source code also allows you to port DRAKVUF to new platforms, fix bugs, *
 * and add new features.  You are highly encouraged to submit your changes *
 * on https://github.com/tklengyel/drakvuf, or by other methods.           *
 * By sending these changes, it is understood (unless you specify          *
 * otherwise) that you are offering unlimited, non-exclusive right to      *
 * reuse, modify, and relicense the code.  DRAKVUF will always be          *
 * available Open Source, but this is important because the inability to   *
 * relicense code has caused devastating problems for other Free Software  *
 * projects (such as KDE and NASM).                                        *
 * To specify special license conditions of your contributions, just say   *
 * so when you send them.                                                  *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the DRAKVUF   *
 * license file for more details (it's in a COPYING file included with     *
 * DRAKVUF, and also available from                                        *
 * https://github.com/tklengyel/drakvuf/COPYING)                           *
 *                                                                         *
 ***************************************************************************/

#pragma once

#include <cstdint>
#include <libdrakvuf/libdrakvuf.h>
#include <string>
#include <sstream>
#include <vector>
#include <memory>

bool is_dll_name_matched(const std::string& dll_name, const std::string& pattern);

enum target_hook_type
{
    HOOK_BY_NAME,
    HOOK_BY_OFFSET
};

// Where a hooked function's arguments are. A hook list says so for the
// functions that do not follow the platform's C convention.
enum class argument_abi
{
    PLATFORM,
    // Go's register convention ("goabi"): amd64 since Go 1.17. Integer words
    // in RAX, RBX, RCX, RDI, RSI, R8, R9, R10, R11, then the stack. A string
    // is two words (pointer, length), a slice three, an interface two.
    GO_REGISTERS,
    // Go's stack convention ("goabi0"): every argument on the stack above the
    // return address, a word each. All of Go before 1.17, all of 32-bit Go,
    // and the functions written in assembly to this day.
    GO_STACK,
};

struct HookActions
{
    bool log;
    bool stack;

    HookActions() : log{false}, stack{false} {}

    static HookActions empty()
    {
        return HookActions{};
    }
    HookActions& set_log()
    {
        this->log = true;
        return *this;
    }
    HookActions& set_stack()
    {
        this->stack = true;
        return *this;
    }
};

class ArgumentPrinter;
struct PrinterConfig;

struct plugin_target_config_entry_t
{
    std::string dll_name;
    target_hook_type type;
    std::string function_name;
    std::string clsid;
    uint64_t offset;
    bool no_retval{false};
    argument_abi abi{argument_abi::PLATFORM};
    HookActions actions;
    std::vector<std::unique_ptr<ArgumentPrinter>> argument_printers;

    plugin_target_config_entry_t()
        : dll_name(), type(), function_name(), offset(), actions(), argument_printers()
    {}

    plugin_target_config_entry_t(std::string dll_name, std::string function_name, uint64_t offset, HookActions hook_actions, std::vector<std::unique_ptr<ArgumentPrinter>> argument_printers)
        : dll_name(std::move(dll_name)), type(HOOK_BY_OFFSET), function_name(std::move(function_name)), offset(offset), actions(hook_actions), argument_printers(std::move(argument_printers))
    {}

    plugin_target_config_entry_t(std::string dll_name, std::string function_name, HookActions hook_actions, std::vector<std::unique_ptr<ArgumentPrinter>> argument_printers)
        : dll_name(std::move(dll_name)), type(HOOK_BY_NAME), function_name(std::move(function_name)), offset(), actions(hook_actions), argument_printers(std::move(argument_printers))
    {}
};

plugin_target_config_entry_t parse_entry(std::stringstream& ss, PrinterConfig& config);

/*
 * The lines a hook list has gained since it was loaded. A list written for
 * one job grows while the trace runs: what the sample drops and then runs is
 * read on the host as it is written, and its functions are added at the end
 * (sandboxd/stagehooks.py). Lines are only ever added after what was there,
 * so what was read stays read, whether the file was appended to or replaced.
 */
class hook_list_tail
{
public:
    // The list as it is now counts as read. No path: nothing ever comes.
    void start(const char* list_path);

    // The complete lines added since the last call, comments and empty ones
    // left out. Looks at the file at most every few hundred milliseconds,
    // being called from callbacks that stall the guest.
    std::vector<std::string> new_lines();

private:
    std::string path;
    uint64_t consumed = 0;
    int64_t last_look_ms = 0;
};

// Argument `number` (from 1) of the function a breakpoint at its entry was
// hit in, read the way `abi` has it
uint64_t read_hook_argument(drakvuf_t drakvuf, drakvuf_trap_info_t* info, argument_abi abi, int number);
