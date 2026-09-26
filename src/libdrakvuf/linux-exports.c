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

#include <stdlib.h>
#include <sys/prctl.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>
#include <unistd.h>
#include <limits.h>
#include <glib.h>
#include <libvmi/libvmi.h>
#include <libvmi/peparse.h>

#include "private.h"
#include "linux-exports.h"
#include "linux-offsets.h"

#define ELF_HEADER	        0x464c457f
#define PAGE_SHIFT          	12
#define AT_NULL_TYPE            0
// DT_VERSYM: .gnu.version, one 16-bit version index per .dynsym entry. Bit 15
// marks a symbol as hidden, i.e. a compat version that a fresh link would not
// bind to; the default version of a name has it clear.
#define DT_VERSYM_TAG           0x6ffffff0
#define VERSYM_HIDDEN           0x8000
// PT_LOAD: a segment the loader maps. The union of these is the module's
// footprint in memory; PT_DYNAMIC (2) is already matched by literal below.
#define PT_LOAD_TAG             1
// struct mm_struct's saved_auxv is AT_VECTOR_SIZE longs, i.e. half that many
// (type, value) pairs; cap the scan well above that rather than trusting the
// AT_NULL terminator to be present in memory we may be reading mid-exec.
#define AUXV_MAX_ENTRIES        32
#define VM_READ		        0x00000001
#define VM_WRITE	        0x00000002
#define VM_EXEC		        0x00000004
#define VM_SHARED	        0x00000008
#define R_X86_64_GLOB_DAT	0x00000006

addr_t linux_eprocess_sym2va(drakvuf_t drakvuf, addr_t eprocess_base, const char* lib, const char* sym)
{
    vmi_instance_t vmi = drakvuf->vmi;

    vmi_pid_t pid;
    if (!drakvuf_get_process_pid(drakvuf, eprocess_base, &pid))
        return -1;

    addr_t mm_struct_address;
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_PID,
        .addr = eprocess_base + drakvuf->offsets[TASK_STRUCT_MMSTRUCT],
        .pid = pid
    );
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &mm_struct_address) || !mm_struct_address)
    {
        ctx.addr = eprocess_base + drakvuf->offsets[TASK_STRUCT_ACTIVE_MMSTRUCT];
        if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &mm_struct_address))
            return -1;
    }

    addr_t mmap;
    ctx.addr = mm_struct_address + drakvuf->offsets[MM_STRUCT_MMAP];
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &mmap))
        return -1;

    addr_t vm_next, nullp = 0;

    addr_t text_segment_address = 0;
    do
    {
        addr_t vm_start;
        ctx.addr = mmap + drakvuf->offsets[VM_AREA_STRUCT_START];
        if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &vm_start))
            return -1;

        addr_t vm_end;
        ctx.addr = mmap + drakvuf->offsets[VM_AREA_STRUCT_END];
        if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &vm_end))
            return -1;

        ctx.addr = mmap + drakvuf->offsets[VM_AREA_STRUCT_NEXT];
        if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &vm_next))
            return -1;

        addr_t file_address;
        ctx.addr = mmap + drakvuf->offsets[VM_AREA_STRUCT_FILE];
        if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &file_address))
            goto next;

        addr_t path_dentry;
        ctx.addr = file_address + drakvuf->offsets[FILE_F_PATH] + drakvuf->offsets[PATH_DENTRY];
        if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &path_dentry))
            goto next;

        addr_t pgoffset;
        ctx.addr = mmap + drakvuf->offsets[VM_AREA_STRUCT_PGOFF];
        if (VMI_FAILURE == vmi_read_64(vmi, &ctx, &pgoffset))
            goto next;
        pgoffset = pgoffset << PAGE_SHIFT;

        addr_t vm_flags;
        ctx.addr = mmap + drakvuf->offsets[VM_AREA_STRUCT_FLAGS];
        if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &vm_flags))
            goto next;

        addr_t libname_addr;
        ctx.addr = path_dentry + drakvuf->offsets[DENTRY_D_NAME] + drakvuf->offsets[QSTR_NAME];
        if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &libname_addr))
            goto next;

        ctx.addr = libname_addr;
        char* libname = vmi_read_str(vmi, &ctx);
        PRINT_DEBUG("LIB NAME is: %s \n", libname);

        if (libname && strncmp(libname, lib, strlen(lib)) == 0 )
        {
            ctx.addr = vm_start;
            uint32_t elf_header;

            if (VMI_SUCCESS == vmi_read_32(vmi, &ctx, &elf_header))
                if (elf_header == ELF_HEADER)
                    text_segment_address = vm_start;
        }

        g_free(libname);

next:
        mmap = vm_next;

    } while (vm_next != nullp);

    if (text_segment_address == 0)
        return -1;

    return linux_module_sym2va(drakvuf, eprocess_base, text_segment_address, sym);
}

/*
 * How far a module reaches past its load address: the highest end of any
 * PT_LOAD segment, which is what the loader actually maps. The dynamic
 * linker's link_map reports each library's base but no extent, so without
 * this the only way to tell whether an address belongs to a library is to
 * assume it does whenever no later library starts below it -- which silently
 * claims every anonymous mapping and heap block sitting above the last one.
 *
 * Returns 0 if the base does not look like an ELF image or the headers cannot
 * be read.
 */
addr_t linux_module_span(drakvuf_t drakvuf, addr_t eprocess_base, addr_t module_base)
{
    vmi_instance_t vmi = drakvuf->vmi;

    if (!drakvuf->offsets[ELF64PHDR_MEMSZ])
        return 0;

    vmi_pid_t pid;
    if (!drakvuf_get_process_pid(drakvuf, eprocess_base, &pid))
        return 0;

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_PID,
        .addr = module_base,
        .pid = pid
    );

    uint32_t elf_header;
    if (VMI_FAILURE == vmi_read_32(vmi, &ctx, &elf_header) || elf_header != ELF_HEADER)
        return 0;

    addr_t program_header_offset;
    ctx.addr = module_base + drakvuf->offsets[ELF64HDR_PHOFF];
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &program_header_offset))
        return 0;

    uint16_t num_of_program_headers;
    ctx.addr = module_base + drakvuf->offsets[ELF64HDR_PHNUM];
    if (VMI_FAILURE == vmi_read_16(vmi, &ctx, &num_of_program_headers))
        return 0;

    uint16_t size_of_program_headers;
    ctx.addr = module_base + drakvuf->offsets[ELF64HDR_PHENTSIZE];
    if (VMI_FAILURE == vmi_read_16(vmi, &ctx, &size_of_program_headers))
        return 0;

    addr_t offset = 0, span = 0;
    for (uint16_t i = 0; i < num_of_program_headers; i++, offset += size_of_program_headers)
    {
        uint32_t ph_type;
        ctx.addr = module_base + program_header_offset + offset + drakvuf->offsets[ELF64PHDR_TYPE];
        if (VMI_FAILURE == vmi_read_32(vmi, &ctx, &ph_type))
            return 0;

        if (ph_type != PT_LOAD_TAG)
            continue;

        addr_t ph_vaddr, ph_memsz;
        ctx.addr = module_base + program_header_offset + offset + drakvuf->offsets[ELF64PHDR_VADDR];
        if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &ph_vaddr))
            return 0;

        ctx.addr = module_base + program_header_offset + offset + drakvuf->offsets[ELF64PHDR_MEMSZ];
        if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &ph_memsz))
            return 0;

        /* p_vaddr is a link-time address, relative to the image, so the span
         * is measured from the image rather than from the load address. */
        if (ph_vaddr + ph_memsz > span)
            span = ph_vaddr + ph_memsz;
    }

    /* The loader maps whole pages, so the last segment reaches to the end of
     * the page its last byte falls in. */
    if (span)
        span = (span + VMI_PS_4KB - 1) & ~(addr_t)(VMI_PS_4KB - 1);

    return span;
}

/*
 * Resolve a symbol in a shared object whose load address is already known,
 * skipping the VMA search that linux_eprocess_sym2va() has to do. Callers that
 * learned the base another way (the dynamic linker's link_map, or AT_BASE from
 * the aux vector) must use this: the VMA walk relies on mm_struct.mmap and
 * vm_area_struct.vm_next, which Linux 6.1 removed in favour of a maple tree.
 */
addr_t linux_module_sym2va(drakvuf_t drakvuf, addr_t eprocess_base, addr_t module_base, const char* sym)
{
    vmi_instance_t vmi = drakvuf->vmi;

    vmi_pid_t pid;
    if (!drakvuf_get_process_pid(drakvuf, eprocess_base, &pid))
        return -1;

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_PID,
        .addr = module_base,
        .pid = pid
    );

    // Sanity check the caller's base before trusting anything we read past it.
    uint32_t elf_header;
    if (VMI_FAILURE == vmi_read_32(vmi, &ctx, &elf_header) || elf_header != ELF_HEADER)
        return -1;

    addr_t text_segment_address = module_base;

    // Parsing ELF header

    addr_t program_header_offset;
    ctx.addr = text_segment_address + drakvuf->offsets[ELF64HDR_PHOFF];
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &program_header_offset))
        return -1;

    uint16_t num_of_program_headers;
    ctx.addr = text_segment_address + drakvuf->offsets[ELF64HDR_PHNUM];
    if (VMI_FAILURE == vmi_read_16(vmi, &ctx, &num_of_program_headers))
        return -1;

    uint16_t size_of_program_headers;
    ctx.addr = text_segment_address + drakvuf->offsets[ELF64HDR_PHENTSIZE];
    if (VMI_FAILURE == vmi_read_16(vmi, &ctx, &size_of_program_headers))
        return -1;

    // Extracting DYNAMIC SEGMENT offset program headers

    int counter = 0;
    uint32_t ph_type;
    addr_t dynamic_section_offset = 0, offset = 0, ph_vaddr;
    while (counter < num_of_program_headers)
    {
        ctx.addr = text_segment_address + offset + program_header_offset + drakvuf->offsets[ELF64PHDR_TYPE];
        if (VMI_FAILURE == vmi_read_32(vmi, &ctx, &ph_type))
            return -1;

        ctx.addr = text_segment_address + offset + program_header_offset + drakvuf->offsets[ELF64PHDR_VADDR];
        if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &ph_vaddr))
            return -1;

        if (ph_type == 2)
        {
            dynamic_section_offset = ph_vaddr;
            break;
        }
        offset += size_of_program_headers;
        counter++;
    }

    // Exracting address of dynsym and dynstr sections from Dynamic section table entries

    addr_t dynsym_offset = 0, dynstr_offset = 0, versym_offset = 0;
    addr_t dynsym_entry_size = 0x18, dynstr_size = 0;
    // addr_t rela_section_offset =0, rela_section_size=0, rela_section_entry=0x18; // set defaults incase not defined

    ctx.addr = text_segment_address + dynamic_section_offset;

    addr_t word, ptr;
    do
    {
        if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &word))
            return -1;
        ctx.addr += 0x8;

        if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &ptr))
            return -1;
        ctx.addr += 0x8;

        if (word == 0x5) // .strtab section offset
            dynstr_offset = ptr;
        if (word == 0x6) // .symtab section offset
            dynsym_offset = ptr;

        // Offsets for Relocation table section for (TODO Section)
        // Symbols offset of relocated symbols are not yet found.
        // if (word == 0x7) // address of .rela.dyn section
        //     rela_section_offset = ptr;
        // if (word == 0x8) // total size of .rela.dyn section
        //     rela_section_size = ptr;
        // if (word == 0x9) // size of an entry in .rela.dyn section
        //     rela_section_entry = ptr;

        if (word == 0xa) // size of .strtab section
            dynstr_size = ptr;
        if (word == 0xb) // size of an entry in .symtab section
            dynsym_entry_size = ptr;
        if (word == DT_VERSYM_TAG)
            versym_offset = ptr;
    } while (word != 0x0 && ptr != 0x0);

    // TODO
    // Reading Relocatable files
    // Symbol mapping of relocated symbols is not yet done.
    // Offsets are found but mapping is to symbol name is not completed

    /* addr_t rela_addend, rela_info, rela_offset;
    offset = 0x0;
    while (offset < rela_section_size)
    {
        ctx.addr = rela_section_offset + offset + drakvuf->offsets[ELF64RELA_ADDEND];
        if (VMI_SUCCESS == vmi_read_addr(vmi, &ctx, &rela_addend))
            printf("rela_addend is: %lx\n", rela_addend);

        ctx.addr = rela_section_offset + offset + drakvuf->offsets[ELF64RELA_INFO];
        if (VMI_SUCCESS == vmi_read_addr(vmi, &ctx, &rela_info))
            printf("rela_info is: %lx\n", rela_info);
        rela_info = rela_info & 0xf;

        ctx.addr = rela_section_offset + offset + drakvuf->offsets[ELF64RELA_OFFSET];
        if (VMI_SUCCESS == vmi_read_addr(vmi, &ctx, &rela_offset))
            printf("rela_offset is: %lx\n\n", rela_offset);

        addr_t num;
        if (rela_info == R_X86_64_GLOB_DAT)
        {
            ctx.addr = rela_section_offset + offset + drakvuf->offsets[ELF64RELA_INFO] + 0x4;
            if (VMI_SUCCESS == vmi_read_addr(vmi, &ctx, &num))
                printf("symbol offset is -> %ld\n", num);
            break;
        }
        offset+=rela_section_entry;
    }
    */

    /*
     * Walk .dynsym comparing each entry's name, rather than locating the
     * string in .dynstr first and then matching st_name offsets against it.
     *
     * A string table merges strings that are suffixes of longer ones, so
     * "open" is typically stored inside "fopen" and its st_name points into
     * the middle of that string. Scanning .dynstr from one NUL to the next
     * only ever yields offsets that begin a string, so every suffix-merged
     * symbol -- open, fork, execve, connect, mprotect and plenty more in
     * glibc -- was unresolvable.
     */
    addr_t fallback = 0;
    size_t max_symbols = 65536;
    if (dynstr_offset > dynsym_offset && dynsym_entry_size)
    {
        // .dynsym is conventionally laid out immediately before .dynstr, so
        // the gap between them bounds the symbol count. Falls back to the cap
        // above for anything unusual, since nothing records the count.
        max_symbols = (dynstr_offset - dynsym_offset) / dynsym_entry_size;
    }

    for (size_t i = 0; i < max_symbols; i++)
    {
        addr_t entry = dynsym_offset + i * dynsym_entry_size;

        uint32_t st_name;
        ctx.addr = entry + drakvuf->offsets[ELF64SYM_NAME];
        if (VMI_FAILURE == vmi_read_32(vmi, &ctx, &st_name))
            return -1;

        if (!st_name || (dynstr_size && st_name >= dynstr_size))
            continue;

        ctx.addr = dynstr_offset + st_name;
        char* symbol_name = vmi_read_str(vmi, &ctx);
        if (!symbol_name)
            continue;

        int cmp = strcmp(symbol_name, sym);
        g_free(symbol_name);

        if (cmp)
            continue;

        addr_t value = 0;
        ctx.addr = entry + drakvuf->offsets[ELF64SYM_VALUE];
        if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &value))
            return -1;

        // st_value is 0 for an undefined symbol, i.e. one this object imports
        // rather than defines. Keep looking instead of returning the base.
        if (!value)
            continue;

        /*
         * glibc carries several versions of plenty of names -- memcpy,
         * pthread_cond_wait and so on -- as separate .dynsym entries sharing
         * one string. Returning whichever comes first can land on a compat
         * version that nothing links against any more. .gnu.version marks the
         * older ones hidden, so prefer an entry without that bit, which is
         * what a fresh link would bind to, and fall back to a hidden one only
         * if that is all there is.
         */
        if (versym_offset)
        {
            uint16_t versym;
            ctx.addr = versym_offset + i * sizeof(uint16_t);

            if (VMI_SUCCESS == vmi_read_16(vmi, &ctx, &versym) && (versym & VERSYM_HIDDEN))
            {
                if (!fallback)
                    fallback = text_segment_address + value;
                continue;
            }
        }

        return text_segment_address + value;
    }

    return fallback ? fallback : -1;
}

addr_t get_lib_address(drakvuf_t drakvuf, addr_t eprocess_base, const char* lib)
{
    vmi_instance_t vmi = drakvuf->vmi;

    vmi_pid_t pid;
    if (!drakvuf_get_process_pid(drakvuf, eprocess_base, &pid))
        return -1;

    addr_t mm_struct_address;
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_PID,
        .addr = eprocess_base + drakvuf->offsets[TASK_STRUCT_MMSTRUCT],
        .pid = pid
    );

    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &mm_struct_address))
        return -1;

    addr_t mmap;
    ctx.addr = mm_struct_address + drakvuf->offsets[MM_STRUCT_MMAP];
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &mmap))
        return -1;

    addr_t vm_next, nullp = 0;
    do
    {
        addr_t vm_start;
        ctx.addr = mmap + drakvuf->offsets[VM_AREA_STRUCT_START];
        if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &vm_start))
            return -1;

        addr_t vm_end;
        ctx.addr = mmap + drakvuf->offsets[VM_AREA_STRUCT_END];
        if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &vm_end))
            return -1;

        ctx.addr = mmap + drakvuf->offsets[VM_AREA_STRUCT_NEXT];
        if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &vm_next))
            return -1;

        addr_t file_address;
        ctx.addr = mmap + drakvuf->offsets[VM_AREA_STRUCT_FILE];
        if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &file_address))
            goto next;

        addr_t path_dentry;
        ctx.addr = file_address + drakvuf->offsets[FILE_F_PATH] + drakvuf->offsets[PATH_DENTRY];
        if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &path_dentry))
            goto next;

        addr_t libname_addr;
        ctx.addr = path_dentry + drakvuf->offsets[DENTRY_D_NAME] + drakvuf->offsets[QSTR_NAME];
        if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &libname_addr))
            goto next;

        ctx.addr = libname_addr;
        char* libname = vmi_read_str(vmi, &ctx);
        PRINT_DEBUG("LIB NAME is: %s\n", libname);
        if (libname)
        {
            int strncmp_ret = strncmp(libname, lib, strlen(lib));
            g_free(libname);
            if (strncmp_ret == 0)
                return vm_start;
        }

next:
        mmap = vm_next;

    } while (vm_next != nullp);

    return -1;
}

/*
 * Read one entry out of the process's aux vector, which the kernel keeps in
 * mm_struct.saved_auxv (the same data /proc/<pid>/auxv exposes). This is how
 * the dynamic linker's load address (AT_BASE) can be found without touching
 * the VMA list, whose layout changed incompatibly in Linux 6.1.
 *
 * Returns 0 if the entry is absent or unreadable.
 */
addr_t linux_get_auxv_value(drakvuf_t drakvuf, addr_t eprocess_base, uint64_t type)
{
    vmi_instance_t vmi = drakvuf->vmi;

    // A profile without saved_auxv leaves the offset zeroed, which would make
    // us read from the head of mm_struct instead.
    if (!drakvuf->offsets[MM_STRUCT_SAVED_AUXV])
        return 0;

    vmi_pid_t pid;
    if (!drakvuf_get_process_pid(drakvuf, eprocess_base, &pid))
        return 0;

    addr_t mm_struct_address;
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_PID,
        .addr = eprocess_base + drakvuf->offsets[TASK_STRUCT_MMSTRUCT],
        .pid = pid
    );

    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &mm_struct_address) || !mm_struct_address)
    {
        ctx.addr = eprocess_base + drakvuf->offsets[TASK_STRUCT_ACTIVE_MMSTRUCT];
        if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &mm_struct_address) || !mm_struct_address)
            return 0;
    }

    // saved_auxv is a flat array of (type, value) pairs terminated by AT_NULL.
    addr_t entry = mm_struct_address + drakvuf->offsets[MM_STRUCT_SAVED_AUXV];

    for (size_t i = 0; i < AUXV_MAX_ENTRIES; i++, entry += 2 * sizeof(addr_t))
    {
        addr_t at_type;
        ctx.addr = entry;
        if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &at_type))
            return 0;

        if (at_type == AT_NULL_TYPE)
            return 0;

        if (at_type != type)
            continue;

        addr_t at_value;
        ctx.addr = entry + sizeof(addr_t);
        if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &at_value))
            return 0;

        return at_value;
    }

    return 0;
}
