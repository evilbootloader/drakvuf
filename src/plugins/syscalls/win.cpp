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

#include <glib.h>
#include <inttypes.h>
#include <libvmi/libvmi.h>
#include <assert.h>
#include <string>
#include <vector>

#include <libdrakvuf/ntstatus.h>
#include <libinjector/libinjector.h>

#include "win.h"
#include "origin.h"
#include "plugins/helpers/object_attributes.h"

using namespace syscalls_ns;
using namespace syscalls_origin;

// _MMVAD_FLAGS.VadType of an executable image mapped by the loader or NtMapViewOfSection
#define VAD_TYPE_IMAGE_MAP 2

static bool enum_modules_cb(drakvuf_t dravkuf, const module_info_t* module_info, bool* need_free, bool* need_stop, void* ctx)
{
    // Skip modules without a full_name (can be NULL for some kernel modules)
    if (!module_info->full_name || !module_info->full_name->contents)
        return true;

    auto plugin   = static_cast<win_syscalls*>(ctx);
    std::lock_guard<std::mutex> lock(plugin->procs_mtx);
    auto& modules = plugin->procs[module_info->pid];
    modules.push_back(
    {
        .name = (const char*)module_info->full_name->contents,
        .base = module_info->base_addr,
        .size = module_info->size
    });
    return true;
}

static event_response_t ret_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    //Loads a pointer to the plugin, which is responsible for the trap
    auto s = get_trap_plugin<win_syscalls>(info);

    //get_trap_params reinterprets the pointer of info->trap->data as a pointer to duplicate_result_t
    auto wr = get_trap_params<wrapper_t>(info);

    //Verifies that the params we got above (preset by the previous trap) match the trap_information this cb got called with.
    //The return trap is shared by all threads returning to the same address and may hit on any vCPU, so this is what
    //selects the trap of the current thread.
    if (!wr->verify_result_call_params(drakvuf, info))
        return VMI_EVENT_RESPONSE_NONE;

    char exit_status_buf[NTSTATUS_MAX_FORMAT_STR_SIZE] = {0};
    const char* exit_status_str = ntstatus_to_string(ntstatus_t(info->regs->rax));
    if (!exit_status_str)
        exit_status_str = ntstatus_format_string(ntstatus_t(info->regs->rax), exit_status_buf, sizeof(exit_status_buf));

    s->print_sysret(drakvuf, info, wr->num, info->regs->rax, exit_status_str);

    //Destroys this return trap, because it is specific for the RIP and not usable anymore. This was the trap being called when the physical address got computed.
    //Deletes this trap from the list of existing traps traps
    //Additionally removes the trap and frees the memory
    //With parallel events it is skipped from now on, so it can't match the next return of this thread
    s->destroy_trap(info->trap);

    return 0;
}

void win_syscalls::print_kernel_sysret(drakvuf_t drakvuf, drakvuf_trap_info_t* info, const pending_syscall& call)
{
    char exit_status_buf[NTSTATUS_MAX_FORMAT_STR_SIZE] = {0};
    const char* exit_status_str = ntstatus_to_string(ntstatus_t(info->regs->rax));
    if (!exit_status_str)
        exit_status_str = ntstatus_format_string(ntstatus_t(info->regs->rax), exit_status_buf, sizeof(exit_status_buf));

    this->print_sysret(drakvuf, info, call.num, info->regs->rax, exit_status_str);
}

// stack_args: where the fifth argument of a 64-bit call is from rsp. 0x28 at the entry of the called
// function, past its return address and the home space of the first four; 0x20 before the call.
static std::vector<uint64_t> extract_args(drakvuf_t drakvuf, drakvuf_trap_info_t const* info, size_t reg_size, size_t nargs,
    addr_t stack_args = 0x28)
{
    std::vector<uint64_t> args(nargs);

    ACCESS_CONTEXT(ctx);
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.dtb = info->regs->cr3;

    if (nargs)
    {
        auto vmi = vmi_reader_guard(drakvuf);

        // get arguments only if we know how many to get

        if ( 4 == reg_size )
        {
            // 32 bit os
            ctx.addr = info->regs->rsp + reg_size;  // jump over base pointer

            // multiply num args by 4 for 32 bit systems to get the number of bytes we need
            // to read from the stack.  assumes standard calling convention (cdecl) for the
            // visual studio compile.
            std::vector<uint32_t> tmp_args(nargs);
            size_t sp_size = reg_size * nargs;
            if ( VMI_FAILURE == vmi_read(vmi, &ctx, sp_size, &tmp_args[0], NULL) )
                nargs = 0;

            for (size_t i = 0; i < nargs; ++i)
                args[i] = tmp_args[i];
        }
        else
        {
            // 64 bit os
            if ( nargs > 0 )
                args[0] = info->regs->rcx;
            if ( nargs > 1 )
                args[1] = info->regs->rdx;
            if ( nargs > 2 )
                args[2] = info->regs->r8;
            if ( nargs > 3 )
                args[3] = info->regs->r9;
            if ( nargs > 4 )
            {
                // first 4 agrs passed via rcx, rdx, r8, and r9
                ctx.addr = info->regs->rsp + stack_args;
                size_t sp_size = reg_size * (nargs - 4);
                if ( VMI_FAILURE == vmi_read(vmi, &ctx, sp_size, &args[4], NULL) )
                    nargs = 0;
            }
        }
    }
    args.resize(nargs);

    return args;
}

// A file directly in System32 or SysWOW64, its path lowercased. Windows maps such an image at one
// base in every process, chosen once a boot.
static bool is_system_dll(const std::string& path)
{
    for (const char* dir : { "\\windows\\system32\\", "\\windows\\syswow64\\" })
    {
        const size_t length = strlen(dir);
        if (path.compare(0, length, dir) == 0 && path.find('\\', length) == std::string::npos)
            return true;
    }
    return false;
}

/*
 * The module an address lies in: for pid 4 a driver's name, otherwise the path of the file mapped
 * there, volume relative (\Windows\System32\ntdll.dll), or "" for memory no file backs -- private
 * memory, a section backed by the pagefile. Nothing when it could not be looked up: the address is
 * in no VAD, or an image's file name could not be read. An image without a name is never "", so
 * that a read failure cannot pass for shellcode.
 *
 * `copy` is set for a system DLL mapped at another base than the first mapping of it seen, in any
 * process: a copy of ntdll a sample mapped to make its syscalls from, or a file at a system DLL's
 * path on another volume, a mounted image -- another file, mapped at another base.
 * KNOWN GAP: a system DLL Windows itself had to relocate in a process, where something else held
 * its base, is reported a copy there.
 */
static std::optional<syscalls_module> resolve_module(drakvuf_t drakvuf, addr_t addr, addr_t process, vmi_pid_t pid, win_syscalls* s)
{
    // The cache is shared by all vCPU threads. It isn't locked while resolving,
    // the drakvuf functions take the VMI lock and enum_modules_cb takes procs_mtx.
    auto lookup = [&]() -> std::optional<syscalls_module>
    {
        std::lock_guard<std::mutex> lock(s->procs_mtx);
        const auto& mods = s->procs.find(pid);
        if (mods != s->procs.end())
        {
            for (const auto& module : mods->second)
            {
                if (addr >= module.base && addr < module.base + module.size)
                {
                    return module;
                }
            }
        }
        return {};
    };
    if (auto cached = lookup())
    {
        return cached;
    }
    // Didn't find in cache, try to resolve.
    //
    if (pid == 4)
    {
        if (drakvuf_enumerate_drivers(drakvuf, enum_modules_cb, s))
        {
            return lookup();
        }
        return {};
    }
    else if (mmvad_info_t mmvad{}; drakvuf_find_mmvad(drakvuf, process, addr, &mmvad))
    {
        // Not cached: memory no file backs is freed and allocated again, and a DLL may be mapped
        // where it was
        if (!mmvad.file_name_ptr)
        {
            if (drakvuf_mmvad_type(drakvuf, &mmvad) == VAD_TYPE_IMAGE_MAP)
                return {};
            return syscalls_module{ .name = "", .base = 0, .size = 0 };
        }
        if (auto u_name = drakvuf_read_unicode_va(drakvuf, mmvad.file_name_ptr, 0))
        {
            // ending_vpn is the VAD's last page, not the one past it
            syscalls_module module
            {
                .name = (const char*)u_name->contents,
                .base = mmvad.starting_vpn << 12,
                .size = (mmvad.ending_vpn - mmvad.starting_vpn + 1) << 12
            };
            vmi_free_unicode_str(u_name);

            gchar* lowered = g_ascii_strdown(module.name.c_str(), -1);
            const std::string path = lowered ? lowered : "";
            g_free(lowered);

            std::lock_guard<std::mutex> lock(s->procs_mtx);
            if (is_system_dll(path))
            {
                auto [known, first] = s->system_dll_bases.emplace(path, module.base);
                if (!first && known->second != module.base)
                    module.copy = module.base;
            }
            s->procs[pid].push_back(module);
            return module;
        }
    }
    return {};
}

// `addr` and the module it lies in, in the process
static win_syscalls::frame resolve_frame(drakvuf_t drakvuf, addr_t addr, addr_t process, vmi_pid_t pid, win_syscalls* s)
{
    win_syscalls::frame out;
    out.address = addr;
    if (addr)
    {
        if (auto module = resolve_module(drakvuf, addr, process, pid, s))
        {
            out.module = std::move(module->name);
            out.copy = module->copy;
        }
    }
    return out;
}

// Up to `size` bytes at `addr` in the address space the thread runs in; how many were read, up to
// the first page that is not present when the read fails there (vmi_read)
static size_t read_user(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t addr, void* buffer, size_t size)
{
    vmi_reader_guard vmi(drakvuf);
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = addr
    );
    size_t got = 0;
    vmi_read(vmi, &ctx, size, buffer, &got);
    return got;
}

// syscalls_origin's reader, over the address space the thread runs in
static syscalls_origin::reader user_reader(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    return [drakvuf, info](addr_t at, void* buffer, size_t size)
    {
        return read_user(drakvuf, info, at, buffer, size);
    };
}

// KTHREAD.SystemCallNumber: the eax of the thread's last entry from user mode, which
// KiSystemServiceUser stores. Not always the service being dispatched: converting a thread to a
// GUI thread, on its first win32k syscall, makes callbacks whose syscalls overwrite it first.
static std::optional<uint32_t> thread_service(drakvuf_t drakvuf, drakvuf_trap_info_t* info, win_syscalls* s)
{
    const addr_t thread = s->thread_syscall_number ? drakvuf_get_current_thread(drakvuf, info) : 0;
    if (!thread)
        return {};
    uint32_t number = 0;
    vmi_reader_guard vmi(drakvuf);
    if (VMI_SUCCESS != vmi_read_32_va(vmi, thread + s->thread_syscall_number, 0, &number))
        return {};
    return number;
}

// Every entry of the service routine at `routine`, as a stub's eax names them
// (syscalls_origin::service_of): more than one for routines the linker folded into one
static std::vector<uint32_t> routine_services(win_syscalls* s, addr_t routine)
{
    std::shared_lock<std::shared_mutex> lock(s->targets_mtx);
    if (auto it = s->services.find(routine); it != s->services.end())
        return it->second;
    return {};
}

// The frame of what the call before `ret` called, when that makes the syscall indirect
// (syscalls_origin::indirect_call); nothing otherwise
static win_syscalls::frame indirect_target(drakvuf_t drakvuf, drakvuf_trap_info_t* info, win_syscalls* s,
    addr_t ret, addr_t stub, addr_t stub_size, bool is32)
{
    const addr_t target = syscalls_origin::indirect_call(user_reader(drakvuf, info), ret, stub, stub_size, is32);
    if (!target)
        return {};
    return resolve_frame(drakvuf, target, info->attached_proc_data.base_addr, info->attached_proc_data.pid, s);
}

/*
 * The 32-bit call a WoW64 process's syscall serves. wow64cpu saves the 32-bit registers when the
 * thread enters 64-bit mode through Wow64Transition: Eip, the address the call to it returns to,
 * popped off the 32-bit stack, and Esp, the stack after that pop. The dword below Esp is then Eip
 * again, and the dword at Esp what the 32-bit stub returns to: frames 0 and 1 of the 32-bit call.
 *
 * Saved by anything else -- an exception in 32-bit code, NtSetContextThread -- Eip is not a return
 * address and the dword below Esp almost never equals it: false then. The registers stay until
 * the next transition, so this is the thread's last 32-bit call: get_origin takes it only for a
 * syscall made through WoW64's own 64-bit code.
 */
static bool wow64_call(drakvuf_t drakvuf, drakvuf_trap_info_t* info, win_syscalls* s, win_syscalls::syscall_origin& origin)
{
    // No --json-wow profile
    if (!s->wow64_context_eip || !s->wow64_context_esp)
        return false;

    addr_t thread = drakvuf_get_current_thread(drakvuf, info);
    addr_t context = 0;
    if (!thread || !drakvuf_get_wow_context(drakvuf, thread, &context))
        return false;

    uint32_t eip = 0, esp = 0;
    uint32_t stack[2] = {};
    if (read_user(drakvuf, info, context + s->wow64_context_eip, &eip, sizeof(eip)) != sizeof(eip) || !eip ||
        read_user(drakvuf, info, context + s->wow64_context_esp, &esp, sizeof(esp)) != sizeof(esp) ||
        esp < sizeof(uint32_t) ||
        read_user(drakvuf, info, esp - sizeof(uint32_t), stack, sizeof(stack)) != sizeof(stack) ||
        stack[0] != eip)
        return false;

    const addr_t process = info->attached_proc_data.base_addr;
    const vmi_pid_t pid = info->attached_proc_data.pid;
    origin.caller = resolve_frame(drakvuf, eip, process, pid, s);
    origin.parent = resolve_frame(drakvuf, stack[1], process, pid, s);
    // Not compared: WoW64 makes syscalls of its own for a 32-bit call, for other services
    origin.stub_syscall.reset();
    // Only a call into the stub past its start: 32-bit stubs have no `mov r10, rcx` to match
    // code that looks like a stub of its own by
    origin.call_target = {};
    if (stack[1] && is_stub32(user_reader(drakvuf, info), eip))
        origin.call_target = indirect_target(drakvuf, info, s, stack[1], eip - STUB32_CALLER, STUB32_CALLER, true);
    return true;
}

// The file name of a frame's module directly in System32, lowercased, when it is Windows' own
// mapping of it; "" otherwise
static std::string system32_name(const win_syscalls::frame& f)
{
    static const std::string system32 = "\\windows\\system32\\";
    if (!f.address || !f.module || f.copy)
        return {};
    gchar* lowered = g_ascii_strdown(f.module->c_str(), -1);
    const std::string path = lowered ? lowered : "";
    g_free(lowered);
    if (path.compare(0, system32.size(), system32) != 0 || path.find('\\', system32.size()) != std::string::npos)
        return {};
    return path.substr(system32.size());
}

/*
 * A WoW64 process's syscall made through WoW64's own 64-bit code, for 32-bit code: `syscall` in
 * ntdll's or win32u's stub, the stub of the service called, called by ntdll or a wow64*.dll --
 * or in a wow64cpu.dll turbo thunk, which is jumped to and has no caller to check. Anything else
 * is 64-bit code the process runs itself (Heaven's Gate). syscall_origin.py's WOW64_LAYER is
 * this list.
 */
static bool through_wow64(const win_syscalls::syscall_origin& origin)
{
    const std::string site = system32_name(origin.caller);
    if (site == "wow64cpu.dll")
        return true;
    if ((site != "ntdll.dll" && site != "win32u.dll") || origin.stub_syscall || origin.call_target.address)
        return false;
    const std::string from = system32_name(origin.parent);
    for (const char* layer : { "ntdll.dll", "wow64.dll", "wow64win.dll", "wow64cpu.dll", "wow64base.dll", "wow64con.dll" })
        if (from == layer)
            return true;
    return false;
}

/*
 * Who made the syscall. From the kernel: the driver that called the Zw function (`caller`, from
 * the dispatcher_caller or the hooked routine's return address). From user mode: the first two
 * frames of the thread's user stack as it entered the kernel -- frame 0 the instruction after
 * `syscall` (KTRAP_FRAME.Rip, `caller`), frame 1 the qword at KTRAP_FRAME.Rsp, which the stub
 * that ran `syscall` returns to (`parent`). That is ntdll's or win32u's stub and its caller, unless
 * the syscall was made elsewhere: Hell's Gate and SysWhispers run `syscall` from their own code
 * (frame 0); an indirect syscall jumps to the instruction in ntdll's stub, so that frame 1 never
 * called the stub (`call_target`) or called another service's (`stub_syscall`). Which ones are,
 * is for the analysis to say (cape_plugin/syscall_origin.py).
 *
 * `dispatched` is the service the kernel is running, every entry of its routine: what the stub's
 * is compared with (syscalls_origin::other_service).
 *
 * A WoW64 process's syscall made through WoW64's own 64-bit code has those frames of the 32-bit
 * call instead (`bitness` 32): the 64-bit ones are ntdll's stub and wow64.dll every time. Made by
 * 64-bit code of the process's own, or with no 32-bit call to show, they are the 64-bit ones
 * (`bitness` 64).
 */
static win_syscalls::syscall_origin get_origin(drakvuf_t drakvuf, drakvuf_trap_info_t* info, win_syscalls* s,
    privilege_mode_t mode, addr_t caller, const std::vector<uint32_t>& dispatched)
{
    win_syscalls::syscall_origin origin;
    if (mode == KERNEL_MODE)
    {
        origin.mode = mode;
        origin.caller = resolve_frame(drakvuf, caller, info->proc_data.base_addr, 4, s);
        return origin;
    }
    if (mode != USER_MODE)
        return origin;

    const addr_t process = info->attached_proc_data.base_addr;
    const vmi_pid_t pid = info->attached_proc_data.pid;
    origin.mode = mode;
    origin.caller = resolve_frame(drakvuf, caller, process, pid, s);

    // KTRAP_FRAME.Rsp is the second qword below the top of the kernel stack (win_get_syscall_retaddr)
    if (addr_t rspbase = drakvuf_get_rspbase(drakvuf, info))
    {
        addr_t rsp = 0, parent = 0;
        {
            vmi_reader_guard vmi(drakvuf);
            if (VMI_SUCCESS != vmi_read_addr_va(vmi, rspbase - 0x10, 0, &rsp) ||
                VMI_SUCCESS != vmi_read_addr_va(vmi, rsp, pid, &parent))
            {
                PRINT_DEBUG("[SYSCALLS] Failed to resolve top of the stack\n");
                parent = 0;
            }
        }
        origin.parent = resolve_frame(drakvuf, parent, process, pid, s);
    }

    if (auto service = stub64_service(user_reader(drakvuf, info), caller))
    {
        if (other_service(*service, dispatched))
        {
            // A routine with a breakpoint of its own is also reached when the kernel calls it
            // itself, serving the service the thread asked for through this stub: the dispatcher
            // hook never sees those calls
            auto asked = s->dispatcher ? std::nullopt : thread_service(drakvuf, info, s);
            if (!asked || (*asked & SERVICE_MASK) != (*service & SERVICE_MASK))
                origin.stub_syscall = *service;
        }
        if (origin.parent.address)
            origin.call_target = indirect_target(drakvuf, info, s, origin.parent.address,
                    caller - STUB64_CALLER, STUB64_SIZE, false);
    }

    // A 32-bit process on a 64-bit kernel
    if (!s->is32bit && info->attached_proc_data.bitness == PROC_TYPE_32)
    {
        win_syscalls::syscall_origin call32 = origin;
        if (through_wow64(origin) && wow64_call(drakvuf, info, s, call32))
        {
            origin = std::move(call32);
            origin.bitness = 32;
        }
        else
            origin.bitness = 64;
    }
    return origin;
}

/// Who made the syscall, in the thread's previous mode. Nothing on a 32-bit kernel.
/// `num` in the nt (`ntos`) or win32k table is the entry the breakpoint hit was placed for.
///
static win_syscalls::syscall_origin get_syscall_origin(drakvuf_t drakvuf, drakvuf_trap_info_t* info, win_syscalls* s,
    uint16_t num, bool ntos)
{
    if (s->is32bit)
    {
        return {};
    }

    privilege_mode_t mode = MAXIMUM_MODE;
    if (!drakvuf_get_current_thread_previous_mode(drakvuf, info, &mode))
    {
        PRINT_DEBUG("[SYSCALLS] Failed to get previous mode\n");
    }

    // The routine the breakpoint is on: folded ones have one for each of their entries, and
    // all are hit
    auto dispatched = routine_services(s, info->regs->rip);
    if (dispatched.empty())
        dispatched.push_back(service_of(num, ntos));
    return get_origin(drakvuf, info, s, mode, drakvuf_get_syscall_retaddr(drakvuf, info, mode), dispatched);
}

// Where the syscall returns to: ntdll for calls from user mode, the caller of the Nt function otherwise.
// 0 if unknown, the return address of the hooked function is used then.
static addr_t syscall_return_address(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    privilege_mode_t mode;
    if (!drakvuf_get_current_thread_previous_mode(drakvuf, info, &mode))
        return 0;

    return drakvuf_get_syscall_retaddr(drakvuf, info, mode);
}

drakvuf_trap_t* init_syscall_return_bp(drakvuf_t drakvuf, drakvuf_trap_info_t* info, drakvuf_trap_t* trap)
{
    if (!trap)
    {
        return nullptr;
    }

    addr_t ret_addr = syscall_return_address(drakvuf, info);
    PRINT_DEBUG("Setting syscall return breakpoint at %lx\n", ret_addr);

    return breakpoint_by_dtb_searcher()
        .for_virt_addr(ret_addr)
        (drakvuf, info, trap);
}

static event_response_t syscall_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto s = get_trap_plugin<win_syscalls>(info);
    auto w = get_trap_params<wrapper_t>(info);
    const syscall_t* sc = w->sc;
    auto num_args = sc ? sc->num_args : 0;

    auto args = extract_args(drakvuf, info, s->register_size, num_args);
    auto origin = get_syscall_origin(drakvuf, info, s, w->num, !strcmp(w->type, "nt"));
    s->print_syscall(drakvuf, info, w->num, w->type, sc, std::move(args), origin);

    if (s->disable_sysret || s->is_stopping())
        return VMI_EVENT_RESPONSE_NONE;

    addr_t ret_addr = drakvuf_get_function_return_address(drakvuf, info);
    if (!ret_addr)
        return VMI_EVENT_RESPONSE_NONE;

    if (s->sysret_mode == sysret_mode_t::KERNEL)
    {
        //Every syscall returns to the caller of the Nt function, the system service dispatcher for most
        s->track_syscall_return(drakvuf, info, ret_addr, w->num, w->type, info->trap->name);
        return VMI_EVENT_RESPONSE_NONE;
    }

    //Save the address of the target thread, address of the rsp (this was the rip-address, which we used for construction) and the value of the CR3 register to the params.
    addr_t user_rsp = 0;
    bool has_user_rsp = origin.mode == USER_MODE && drakvuf_get_user_rsp(drakvuf, info, &user_rsp);

    //wrapper extends from call_result_t which extends from plugin_params
    //The params are filled in before the trap is added: other threads returning to the same address may hit it
    //right away, on any vCPU, and the thread itself may return on another vCPU than it entered the syscall on.
    auto trap = s->register_prepared_trap<wrapper_t>(info, ret_cb, init_syscall_return_bp, nullptr,
            [&](drakvuf_trap_t* ret_trap, wrapper_t* wr)
    {
        if (has_user_rsp)
            wr->set_result_call_params(info, user_rsp);
        else
            wr->set_result_call_params(info);

        //enrich the params of the new/next trap. This information is used later.
        wr->num = w->num;
        wr->type = w->type;
        wr->sc = w->sc;

        ret_trap->breakpoint.module = w->type;
        ret_trap->mt_safe = true;
    });
    if (!trap)
    {
        PRINT_DEBUG("Failed to trap syscall return %hu\n", w->num);
        return VMI_EVENT_RESPONSE_NONE;
    }

    if (has_user_rsp)
        PRINT_DEBUG("[SYSCALLS] set trap with user rsp: %lx, module: %s\n", user_rsp, w->type);
    else
        PRINT_DEBUG("[SYSCALLS] set trap with kernel rsp: %lx, module %s\n", info->regs->rsp, w->type);

    return VMI_EVENT_RESPONSE_NONE;
}

// Dispatcher mode needs where syscalls enter and leave, and where the thread keeps their number and trap frame
bool win_syscalls::setup_dispatcher(drakvuf_t drakvuf, vmi_instance_t vmi)
{
    addr_t entry = 0;
    if (VMI_SUCCESS != vmi_translate_ksym2v(vmi, "KiSystemServiceCopyEnd", &entry) ||
        VMI_SUCCESS != vmi_translate_ksym2v(vmi, "KiSystemServiceExit", &this->dispatcher_exit) ||
        !drakvuf_get_kernel_struct_member_rva(drakvuf, "_KTHREAD", "SystemCallNumber", &this->thread_syscall_number) ||
        !drakvuf_get_kernel_struct_member_rva(drakvuf, "_KTHREAD", "TrapFrame", &this->thread_trap_frame) ||
        !drakvuf_get_kernel_struct_member_rva(drakvuf, "_KTRAP_FRAME", "Rsp", &this->trap_frame_rsp))
    {
        fprintf(stderr, "[SYSCALLS] The syscall dispatcher is not in the kernel profile, hooking each service routine instead\n");
        return false;
    }
    return true;
}

// Stubs the linker folded into one routine share its address, their numbers tell them apart.
// From user mode the stub `syscall` ran in says which: its eax is what the kernel looked the
// routine up by. Otherwise -- code that is no stub of Windows', a kernel caller -- the number
// KiSystemServiceUser stored, for calls from user mode only and stale on a thread's first win32k
// syscall (thread_service): the first stub is taken when it is none of them.
static win_syscalls::dispatch_target pick_folded(drakvuf_t drakvuf, drakvuf_trap_info_t* info, win_syscalls* s,
    const std::vector<win_syscalls::dispatch_target>& folded, privilege_mode_t mode, addr_t caller)
{
    if (mode == USER_MODE)
    {
        if (auto service = stub64_service(user_reader(drakvuf, info), caller))
        {
            for (const auto& target : folded)
                if (service_of(target.num, target.ntos) == (*service & SERVICE_MASK))
                    return target;
        }
    }

    addr_t thread = drakvuf_get_current_thread(drakvuf, info);
    uint32_t number = 0;
    if (thread)
    {
        auto vmi = vmi_reader_guard(drakvuf);
        if (VMI_SUCCESS != vmi_read_32_va(vmi, thread + s->thread_syscall_number, 0, &number))
            return folded.front();
    }
    for (const auto& target : folded)
        if (target.num == (number & 0xfff) && target.ntos == !(number & 0x1000))
            return target;
    return folded.front();
}

// Where the syscall returns to: ntdll for calls from user mode. A kernel caller went through a Zw
// stub, which saved its stack pointer, at the return address into the caller, in the trap frame
// KiServiceInternal built and KiSystemServiceStart made the thread's TrapFrame.
static addr_t dispatcher_caller(drakvuf_t drakvuf, drakvuf_trap_info_t* info, win_syscalls* s, privilege_mode_t mode)
{
    if (mode != KERNEL_MODE)
        return drakvuf_get_syscall_retaddr(drakvuf, info, mode);

    addr_t thread = drakvuf_get_current_thread(drakvuf, info);
    if (!thread)
        return 0;

    auto vmi = vmi_reader_guard(drakvuf);
    addr_t frame = 0, rsp = 0, ret = 0;
    if (VMI_SUCCESS != vmi_read_addr_va(vmi, thread + s->thread_trap_frame, 0, &frame) ||
        VMI_SUCCESS != vmi_read_addr_va(vmi, frame + s->trap_frame_rsp, 0, &rsp) ||
        VMI_SUCCESS != vmi_read_addr_va(vmi, rsp, 0, &ret))
        return 0;
    return ret;
}

/*
 * Every syscall, about to call the service routine KiSystemServiceRepeat looked up into r10, with
 * the first four arguments in rcx, rdx, r8 and r9 and the rest from rsp+0x20: what the kernel's
 * own syscall tracing in KiSystemServiceCopyEnd hands on too. Runs on several vCPU threads at
 * once; the targets are read under their lock, the rest is what syscall_cb shares as well.
 */
event_response_t win_syscalls::dispatcher_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    dispatch_target target;
    std::vector<dispatch_target> folded;
    {
        std::shared_lock<std::shared_mutex> lock(this->targets_mtx);
        auto it = this->targets.find(info->regs->r10);
        // Filtered out, or in a table not read yet: win32k's until explorer.exe runs
        if (it == this->targets.end())
            return VMI_EVENT_RESPONSE_NONE;
        target = it->second.front();
        if (it->second.size() > 1)
            folded = it->second;
    }
    // The routine in r10 is the service dispatched
    const auto dispatched = routine_services(this, info->regs->r10);

    privilege_mode_t mode = MAXIMUM_MODE;
    if (!drakvuf_get_current_thread_previous_mode(drakvuf, info, &mode))
        PRINT_DEBUG("[SYSCALLS] Failed to get previous mode\n");
    const addr_t caller = dispatcher_caller(drakvuf, info, this, mode);

    if (!folded.empty())
        target = pick_folded(drakvuf, info, this, folded, mode, caller);

    const char* type = target.ntos ? "nt" : "win32k";
    auto args = extract_args(drakvuf, info, this->register_size, target.sc ? target.sc->num_args : 0, 0x20);

    auto origin = get_origin(drakvuf, info, this, mode, caller, dispatched);

    // Named after the syscall so Method shows it, as its own breakpoint was. The dispatcher's is
    // shared by all syscalls and vCPU threads, so a copy is named.
    drakvuf_trap_t trap = *info->trap;
    trap.name = target.name;
    drakvuf_trap_info_t named_info = *info;
    named_info.trap = &trap;
    this->print_syscall(drakvuf, &named_info, target.num, type, target.sc, std::move(args), origin);

    if (this->disable_sysret || this->is_stopping())
        return VMI_EVENT_RESPONSE_NONE;

    // The call KiSystemServiceCopyEnd makes, or one of the two the kernel's syscall tracing makes
    // instead, returns into KiSystemServiceExit with rsp back where it is now and the status in rax
    this->track_syscall_return(drakvuf, info, this->dispatcher_exit, target.num, type, target.name);
    return VMI_EVENT_RESPONSE_NONE;
}

bool win_syscalls::trap_syscall_table_entries(drakvuf_t drakvuf, vmi_instance_t vmi, addr_t cr3, bool ntos, addr_t base, std::array<addr_t, 2> _sst, json_object* json)
{
    unsigned int syscall_count = ntos ? NUM_SYSCALLS_NT : NUM_SYSCALLS_WIN32K;
    const syscall_t** definitions = ntos ? nt : win32k;

    symbols_t* symbols = json ? json_get_symbols(json) : NULL;

    int32_t* table = (int32_t*)g_try_malloc0(_sst[1] * sizeof(int32_t));
    if ( !table )
    {
        drakvuf_free_symbols(symbols);
        return false;
    }

    ACCESS_CONTEXT(ctx);
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.dtb = cr3;
    ctx.addr = _sst[0];
    if ( VMI_FAILURE == vmi_read(vmi, &ctx, _sst[1] * sizeof(uint32_t), table, NULL) )
    {
        drakvuf_free_symbols(symbols);
        g_free(table);
        return false;
    }

    for ( addr_t syscall_num = 0; syscall_num < _sst[1]; syscall_num++ )
    {
        long offset = 0;
        addr_t syscall_va;

        if ( !this->is32bit )
        {
            /*
             * The offsets in the SSDT are 32-bit RVAs calculated from the table base.
             * bits 0-3 are argument count information that needs to be shifted out.
             * Must be signed long because the offset may be negative.
             */
            offset = table[syscall_num] >> 4;
            syscall_va = _sst[0] + offset;
        }
        else
            syscall_va = table[syscall_num];

        addr_t rva = syscall_va - base;
        if ( this->is32bit )
            rva = static_cast<uint32_t>(rva);

        const struct symbol* symbol = nullptr;
        const syscall_t* definition = nullptr;
        if ( symbols )
        {
            for (unsigned int z=0; z < symbols->count; z++)
            {
                if ( symbols->symbols[z].rva == rva )
                {
                    symbol = &symbols->symbols[z];

                    for (unsigned int d=0; d < syscall_count; d++)
                    {
                        if ( !strcmp(definitions[d]->name, symbol->name) )
                        {
                            definition = definitions[d];
                            break;
                        }
                    }
                    break;
                }
            }
        }

        // Before the filter: an entry filtered out is still one its routine serves
        {
            std::unique_lock<std::shared_mutex> lock(this->targets_mtx);
            this->services[syscall_va].push_back(service_of(syscall_num, ntos));
        }

        const char* symbol_name = nullptr;

        if ( !symbol )
            PRINT_DEBUG("\t Syscall %lu @ 0x%lx has no debug information matching it with RVA 0x%lx. Table: 0x%lx Offset: 0x%lx\n", syscall_num, syscall_va, rva, _sst[0], offset);
        else if ( !definition )
        {
            gchar* tmp = g_strdup(symbol->name);
            this->strings_to_free = g_slist_prepend(this->strings_to_free, tmp);
            symbol_name = (const char*)tmp;
            PRINT_DEBUG("\t Syscall %s:%s has no internal definition. New syscall?\n",
                ntos ? "nt" : "wink32k", symbol_name);
        }
        else
            symbol_name = definition->name;

        if ( !this->filter.empty() && ( !symbol_name || (this->filter.find(symbol_name) == this->filter.end())))
        {
            PRINT_DEBUG("Syscall %s filtered out by syscalls filter file\n", symbol_name ? symbol_name : "<unknown>");
            continue;
        }

        // r10 holds syscall_va when KiSystemServiceCopyEnd is reached for this entry
        if ( this->dispatcher )
        {
            std::unique_lock<std::shared_mutex> lock(this->targets_mtx);
            this->targets[syscall_va].push_back({ static_cast<uint16_t>(syscall_num), ntos, definition, symbol_name });
            continue;
        }

        //wrapper extends from call_result_t which extends from plugin_params
        //The params are filled in before the trap is added, the win32k table may be trapped while other vCPUs run.
        breakpoint_by_dtb_searcher bp;
        auto trap = this->register_prepared_trap<wrapper_t>(
                nullptr,
                syscall_cb,
                bp.for_virt_addr(syscall_va).for_dtb(cr3),
                symbol_name,
                [&](drakvuf_trap_t* entry_trap, wrapper_t* w)
        {
            //enrich the params of the new/next trap. This information is used later.
            w->num = syscall_num;
            w->type = ntos ? "nt" : "win32k";
            w->sc = definition;

            //syscall_cb only shares the plugin's module cache and output, which are locked
            entry_trap->mt_safe = true;
        });

        if (!trap)
        {
            PRINT_DEBUG("Failed to trap syscall %lu @ 0x%lx\n", syscall_num, syscall_va);
            continue;
        }
    }

    drakvuf_free_symbols(symbols);
    g_free(table);

    return true;
}

win_syscalls::win_syscalls(drakvuf_t drakvuf, const syscalls_config* config, output_format_t output)
    : syscalls_base(drakvuf, config, output)
    , win32k_profile{ config->win32k_profile ?: "" }
{
    auto vmi = vmi_lock_guard(drakvuf);

    if ( !this->is32bit )
    {
        system_service_table_x64 _sst[2] = {};
        if ( VMI_FAILURE == vmi_read_ksym(vmi, "KeServiceDescriptorTableShadow", 2*sizeof(system_service_table_x64), (void*)&_sst, NULL) )
        {
            PRINT_DEBUG("[SYSCALLS] Failed to read ksym KeServiceDescriptorTableShadow\n");
            throw -1;
        }

        this->sst[0][0] = _sst[0].ServiceTable;
        this->sst[0][1] = _sst[0].ServiceLimit;
        this->sst[1][0] = _sst[1].ServiceTable;
        this->sst[1][1] = _sst[1].ServiceLimit;
    }
    else
    {
        system_service_table_x86 _sst[2] = {};
        if ( VMI_FAILURE == vmi_read_ksym(vmi, "KeServiceDescriptorTableShadow", 2*sizeof(system_service_table_x86), (void*)&_sst, NULL) )
        {
            PRINT_DEBUG("[SYSCALLS] Failed to read ksym KeServiceDescriptorTableShadow\n");
            throw -1;
        }

        this->sst[0][0] = _sst[0].ServiceTable;
        this->sst[0][1] = _sst[0].ServiceLimit;
        this->sst[1][0] = _sst[1].ServiceTable;
        this->sst[1][1] = _sst[1].ServiceLimit;
    }

    addr_t dtb;
    if ( VMI_FAILURE == vmi_pid_to_dtb(vmi, 0, &dtb) )
    {
        PRINT_DEBUG("[SYSCALLS] Failed to get dtb.\n");
        throw -1;
    }

#ifdef DRAKVUF_DEBUG
    uint16_t ntbuild;
    if ( VMI_FAILURE == vmi_read_16_ksym(vmi, "NtBuildNumber", &ntbuild) )
        throw -1;

    PRINT_DEBUG("Kernel base: 0x%lx\n", this->kernel_base);
    PRINT_DEBUG("Kernel pagetable: 0x%lx\n", dtb);
    PRINT_DEBUG("NtBuildNumber: %u\n", ntbuild);
    PRINT_DEBUG("NT syscall table: 0x%lx. Limit: %lu\n", this->sst[0][0], this->sst[0][1]);
    PRINT_DEBUG("Win32k syscall table: 0x%lx. Limit: %lu\n", this->sst[1][0], this->sst[1][1]);
#endif

    if (!drakvuf_get_kernel_struct_member_rva(drakvuf, "_RTL_USER_PROCESS_PARAMETERS", "ImagePathName", &this->image_path_name))
    {
        PRINT_DEBUG("[SYSCALLS] Failed to get ImagePathName from _RTL_USER_PROCESS_PARAMETERS\n");
        throw -1;
    }

    // The 32-bit registers WoW64 saves, from the 32-bit ntdll's profile (--json-wow). Without it a
    // WoW64 process's syscalls are reported with their 64-bit frames only.
    if (json_object* json_wow = this->is32bit ? nullptr : drakvuf_get_json_wow(drakvuf))
    {
        if (!json_get_struct_member_rva(drakvuf, json_wow, "_CONTEXT", "Eip", &this->wow64_context_eip) ||
            !json_get_struct_member_rva(drakvuf, json_wow, "_CONTEXT", "Esp", &this->wow64_context_esp))
        {
            this->wow64_context_eip = this->wow64_context_esp = 0;
        }
    }
    if (!this->is32bit && !this->wow64_context_eip)
        PRINT_DEBUG("[SYSCALLS] No WoW64 profile (--json-wow): the 32-bit side of WoW64 syscalls is not reported\n");

    // The service a thread last asked for: tells folded routines apart (pick_folded), and a
    // routine the kernel called itself from one dispatched (get_origin, without the dispatcher).
    // Dispatcher mode needs it as well (setup_dispatcher).
    if (!this->is32bit &&
        !drakvuf_get_kernel_struct_member_rva(drakvuf, "_KTHREAD", "SystemCallNumber", &this->thread_syscall_number))
    {
        this->thread_syscall_number = 0;
    }

    // Per-call sysret mode places each return breakpoint from the return address of the service
    // routine, which only a breakpoint on the routine itself has. A 32-bit kernel dispatches
    // through KiFastCallEntry, which is not hooked. Both keep a breakpoint per table entry.
    if (!this->is32bit && (this->disable_sysret || this->sysret_mode == sysret_mode_t::KERNEL))
        this->dispatcher = this->setup_dispatcher(drakvuf, vmi);

    if (!trap_syscall_table_entries(drakvuf, vmi, dtb, true, this->kernel_base, this->sst[0], vmi_get_kernel_json(vmi)))
    {
        PRINT_DEBUG("[SYSCALLS] Failed to trap NT syscall table entries\n");
        throw -1;
    }

    if (!this->setup_win32k_syscalls(drakvuf))
    {
        PRINT_DEBUG("[SYSCALLS] Delay hooks initialization\n");
        this->load_driver_hook = this->createSyscallHook("NtLoadDriver", &win_syscalls::load_driver_cb);
        this->create_process_hook = this->createSyscallHook("NtCreateUserProcess", &win_syscalls::create_process_cb);
    }

    // After the nt table is in targets, so that the first syscalls find their routines
    if (this->dispatcher)
    {
        this->dispatcher_hook = this->createSyscallHook("KiSystemServiceCopyEnd", &win_syscalls::dispatcher_cb,
                "KiSystemServiceCopyEnd", UNLIMITED_TTL, true);
        if (!this->dispatcher_hook)
        {
            fprintf(stderr, "[SYSCALLS] Failed to hook KiSystemServiceCopyEnd\n");
            throw -1;
        }
    }
    this->delete_process_hook = this->createSyscallHook("PspProcessDelete", &win_syscalls::delete_process_cb);
}

bool win_syscalls::setup_win32k_syscalls(drakvuf_t drakvuf)
{
    auto vmi = vmi_lock_guard(drakvuf);

    if (this->win32k_profile == "")
    {
        PRINT_DEBUG("Skipping second syscall table since no json profile for win32k is provided\n");
        return true;
    }

    addr_t modlist;
    if (VMI_SUCCESS != vmi_read_addr_ksym(vmi, "PsLoadedModuleList", &modlist))
    {
        PRINT_DEBUG("Couldn't read PsLoadedModuleList\n");
        return false;
    }

    addr_t win32k_base;
    if (!drakvuf_get_module_base_addr(drakvuf, modlist, "win32k.sys", &win32k_base))
    {
        PRINT_DEBUG("Couldn't find win32k.sys\n");
        return false;
    }

    addr_t explorer;
    if (!drakvuf_find_process(drakvuf, ~0, "explorer.exe", &explorer))
    {
        PRINT_DEBUG("Couldn't find explorer.exe\n");
        return false;
    }

    addr_t dtb;
    if (!drakvuf_get_process_dtb(drakvuf, explorer, &dtb))
    {
        PRINT_DEBUG("Couldn't find explorer.exe's dtb\n");
        return false;
    }

    PRINT_DEBUG("Found explorer.exe @ 0x%lx. DTB: 0x%lx\n", explorer, dtb);

    json_object* win32k_json = json_object_from_file(this->win32k_profile.data());
    if (!win32k_json)
    {
        PRINT_DEBUG("Failed to load win32k profile\n");
        return false;
    }

    if (!this->trap_syscall_table_entries(drakvuf, vmi, dtb, false, win32k_base, this->sst[1], win32k_json))
    {
        json_object_put(win32k_json);
        PRINT_DEBUG("Failed to trap win32k syscall entries\n");
        return false;
    }

    json_object_put(win32k_json);
    PRINT_DEBUG("Successfully trap win32k syscall entries\n");
    return true;
}

char* win_syscalls::win_extract_string(drakvuf_t drakvuf, drakvuf_trap_info_t* info, const arg_t& arg, addr_t val)
{
    if (arg.type == PUNICODE_STRING)
    {
        unicode_string_t* us = drakvuf_read_unicode(drakvuf, info, val);
        if (us)
        {
            char* str = (char*)us->contents;
            us->contents = nullptr; // move ownership
            vmi_free_unicode_str(us);
            return str;
        }
    }
    else if ( arg.type == POBJECT_ATTRIBUTES )
    {
        char* filename = drakvuf_get_filename_from_object_attributes(drakvuf, info, val);
        if ( filename ) return filename;
    }

    if ( !strcmp(arg.name, "FileHandle") )
    {
        char* filename = drakvuf_get_filename_from_handle(drakvuf, info, val);
        if ( filename ) return filename;
    }

    return nullptr;
}

event_response_t win_syscalls::load_driver_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    addr_t service_name_addr = drakvuf_get_function_argument(drakvuf, info, 1);
    unicode_string_t* service_name = drakvuf_read_unicode(drakvuf, info, service_name_addr);
    if (!service_name)
        return VMI_EVENT_RESPONSE_NONE;

    PRINT_DEBUG("[SYSCALLS] Load driver: %s\n", service_name->contents);

    gchar* service_name_casefold = g_utf8_casefold(reinterpret_cast<const gchar*>(service_name->contents), -1);
    vmi_free_unicode_str(service_name);

    if (service_name_casefold)
    {
        if (strstr(service_name_casefold, "win32k.sys"))
        {
            this->load_driver_hook = {};

            if (setup_win32k_syscalls(drakvuf))
                this->create_process_hook = {};
        }
        g_free(service_name_casefold);
    }

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t win_syscalls::create_process_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    addr_t user_process_parameters_addr = drakvuf_get_function_argument(drakvuf, info, 9);
    addr_t imagepath_addr = user_process_parameters_addr + this->image_path_name;
    unicode_string_t* image_path = drakvuf_read_unicode(drakvuf, info, imagepath_addr);
    if (!image_path)
        return VMI_EVENT_RESPONSE_NONE;

    PRINT_DEBUG("[SYSCALLS] Create process: %s\n", image_path->contents);

    gchar* image_path_casefold = g_utf8_casefold(reinterpret_cast<const gchar*>(image_path->contents), -1);
    vmi_free_unicode_str(image_path);

    if (image_path_casefold)
    {
        if (strstr(image_path_casefold, "explorer.exe"))
        {
            this->create_process_hook = {};

            auto hook = createReturnHook<PluginResult>(info, &win_syscalls::create_process_ret_cb);
            this->wait_process_creation_hook = std::move(hook);
        }
        g_free(image_path_casefold);
    }

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t win_syscalls::create_process_ret_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    this->wait_process_creation_hook = {};

    if (setup_win32k_syscalls(drakvuf))
        this->load_driver_hook = {};

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t win_syscalls::delete_process_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    addr_t process = drakvuf_get_function_argument(drakvuf, info, 1);

    if (vmi_pid_t pid; drakvuf_get_process_pid(drakvuf, process, &pid))
    {
        {
            std::lock_guard<std::mutex> lock(this->procs_mtx);
            this->procs.erase(pid);
        }

        this->forget_process_syscalls(pid);
    }
    return VMI_EVENT_RESPONSE_NONE;
}

void win_syscalls::print_syscall(
    drakvuf_t drakvuf, drakvuf_trap_info_t* info,
    int nr, const char* module, const syscall_t* sc,
    std::vector<uint64_t> args, const syscall_origin& origin
)
{
    // The trap is already named after the syscall when it is known
    std::vector<std::pair<char const*, fmt::Aarg>> fmt_args;

    if (sc)
    {
        for (size_t i = 0; i < args.size(); ++i)
        {
            uint64_t val = transform_value(drakvuf, info, sc->args[i], args[i]);
            if ( sc->args[i].type == POBJECT_ATTRIBUTES )
            {
                // The pointer, and the object it names -- a file, a key, a
                // mutex... -- under capemon's name for it. At the kernel's
                // entry the structure has the kernel's layout, also for WoW64.
                fmt_args.push_back(keyval(sc->args[i].name, fmt::Xval(val)));
                if ( sc->args[i].dir == DIR_IN || sc->args[i].dir == DIR_INOUT )
                {
                    if (auto object = read_object_attributes(drakvuf, info, sc->name, sc->args[i].name,
                                args[i], drakvuf_get_address_width(drakvuf) == 4))
                        fmt_args.push_back(keyval(object->label, fmt::Estr(std::move(object->name))));
                }
                continue;
            }
            auto str = this->parse_argument(drakvuf, info, sc->args[i], args[i]);
            if ( !str.empty() && !strcmp((sc->args[i]).name, "FileHandle") ){
                fmt_args.push_back(keyval(sc->args[i].name, fmt::Xval(val)));
                fmt_args.push_back(keyval("FileName", fmt::Estr(str)));
            }
            else if ( !str.empty() )
                fmt_args.push_back(keyval(sc->args[i].name, fmt::Estr(str)));
            else
            {
                fmt_args.push_back(keyval(sc->args[i].name, fmt::Xval(val)));
            }
        }
    }

    std::optional<fmt::Rstr<const char*>> priv_mode_opt;
    if (origin.mode != MAXIMUM_MODE)
        priv_mode_opt = fmt::Rstr(origin.mode == USER_MODE ? "User" : "Kernel");

    // Each frame (get_origin) as an address, its module and, for a second mapping of a system DLL,
    // that mapping's base (`...Copy`). An address is left out when unknown (0); a module when it
    // could not be looked up, and "" for memory no file backs (exact_str): the analysis tells
    // the two apart.
    // StubSyscall, the call target and the copies are printed only when there is one.
    auto address = [](addr_t value)
    {
        std::optional<fmt::Xval<addr_t>> out;
        if (value)
            out = fmt::Xval(value);
        return out;
    };
    auto module_of = [](const frame& f)
    {
        std::optional<fmt::Estr<std::string>> out;
        if (f.address && f.module)
            out = exact_str(*f.module);
        return out;
    };
    std::optional<fmt::Xval<uint32_t>> stub_syscall;
    if (origin.stub_syscall)
        stub_syscall = fmt::Xval(*origin.stub_syscall);
    // A WoW64 process's: 32 when the frames are the 32-bit call's, 64 when they are 64-bit code's.
    // Left out for a 64-bit process.
    std::optional<fmt::Nval<int>> bitness;
    if (origin.bitness)
        bitness = fmt::Nval(origin.bitness);

    fmt::print(this->m_output_format, "syscall", drakvuf, info,
        keyval("Module", fmt::Qstr(std::move(module))),
        keyval("vCPU", fmt::Nval(info->vcpu)),
        keyval("CR3", fmt::Xval(info->regs->cr3)),
        keyval("Syscall", fmt::Nval(nr)),
        keyval("NArgs", fmt::Nval(args.size())),
        keyval("PreviousMode", priv_mode_opt),
        keyval("Bitness", bitness),
        keyval("Caller", address(origin.caller.address)),
        keyval("FromModule", module_of(origin.caller)),
        keyval("FromModuleCopy", address(origin.caller.copy)),
        keyval("ParentCaller", address(origin.parent.address)),
        keyval("FromParentModule", module_of(origin.parent)),
        keyval("FromParentModuleCopy", address(origin.parent.copy)),
        keyval("StubSyscall", stub_syscall),
        keyval("ParentCallTarget", address(origin.call_target.address)),
        keyval("ParentCallTargetModule", module_of(origin.call_target)),
        std::move(fmt_args)
    );
}

win_syscalls::~win_syscalls()
{
    // The targets name syscalls with the strings freed below
    this->dispatcher_hook.reset();

    GSList* loop = this->strings_to_free;
    while (loop)
    {
        g_free(loop->data);
        loop = loop->next;
    }
    g_slist_free(this->strings_to_free);
}
