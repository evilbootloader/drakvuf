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

#ifndef PRINTERS_H
#define PRINTERS_H

#include <cstddef>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include <libvmi/libvmi.h>
#include <libdrakvuf/libdrakvuf.h>

struct PrinterConfig
{
    bool print_no_addr;
    enum class NumericFormat
    {
        DECIMAL,
        HEX,
    } numeric_format;

    PrinterConfig() : print_no_addr{false}, numeric_format{NumericFormat::HEX} {}
    PrinterConfig(bool print_no_addr, NumericFormat numeric_format)
        : print_no_addr{print_no_addr}
        , numeric_format{numeric_format} {}
};

class ArgumentPrinter
{
protected:
    PrinterConfig config;
    std::string name;
    std::string type;
public:
    ArgumentPrinter(std::string arg_name, PrinterConfig config = PrinterConfig{});

    std::string get_name() const;
    const std::string& get_type() const { return type; }
    void set_type(const std::string& t) { type = t; }
    virtual std::string print(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t argument) const;
    // Whether print() reads a value the call may write through the argument
    // (an out parameter). Such an argument means something only once the
    // call has returned: printed at entry, NtAllocateVirtualMemory's
    // BaseAddress is the 0 the caller passed, not the region it got.
    virtual bool reads_output() const
    {
        return false;
    }
    // The number the argument stands for, which is what a buffer's length
    // argument is read as: the register itself, cut to its width, or what
    // it points to for a printer that dereferences one (pulong...).
    virtual uint64_t value(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t argument) const
    {
        return argument;
    }
    // A buffer's: the index of the argument holding its length, or that
    // the call's return value is (BufferPrinter). See print_argument.
    virtual std::optional<size_t> length_argument() const
    {
        return {};
    }
    virtual bool length_from_return() const
    {
        return false;
    }
    // Printed with the length a buffer has; for anything else as print()
    virtual std::string print_sized(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t argument, uint64_t length) const
    {
        return print(drakvuf, info, argument);
    }
    virtual ~ArgumentPrinter();
};

// An integer narrower than the register it is passed in. On x64 only the
// low bits of the register are the argument and the rest is whatever the
// caller left there: a DWORD 0x10 printed as the register reads 0x4f00000010.
class NarrowIntegerPrinter : public ArgumentPrinter
{
    unsigned bits;
public:
    NarrowIntegerPrinter(std::string arg_name, unsigned bits, PrinterConfig config = PrinterConfig{});

    std::string print(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t argument) const;
    uint64_t value(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t argument) const;
};

class StringPrinterInterface : public ArgumentPrinter
{
protected:
    virtual std::string getBuffer(drakvuf_t drakvuf, const access_context_t* ctx) const = 0;
public:
    using ArgumentPrinter::ArgumentPrinter;

    std::string print(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t argument) const;
};

class AsciiPrinter : public StringPrinterInterface
{
private:
    std::string getBuffer(drakvuf_t drakvuf, const access_context_t* ctx) const;

public:
    using StringPrinterInterface::StringPrinterInterface;
};

class WideStringPrinter : public StringPrinterInterface
{
private:
    std::string getBuffer(drakvuf_t drakvuf, const access_context_t* ctx) const;

public:
    using StringPrinterInterface::StringPrinterInterface;
};

class Binary16StringPrinter : public ArgumentPrinter
{
public:
    using ArgumentPrinter::ArgumentPrinter;

    std::string print(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t argument) const;
};

class UnicodePrinter : public ArgumentPrinter
{
public:
    using ArgumentPrinter::ArgumentPrinter;

    std::string print(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t argument) const;
};

// A PANSI_STRING, as UnicodePrinter prints a PUNICODE_STRING:
// name=0xADDR:"text". LdrGetProcedureAddress's ProcedureName is one, and
// NULL when the function is looked up by its ordinal.
class AnsiStringPrinter : public ArgumentPrinter
{
public:
    // Export names are far shorter; Length is the guest's number
    static constexpr size_t MAX_BYTES = 1024;

    using ArgumentPrinter::ArgumentPrinter;

    std::string print(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t argument) const;
};

class UlongPrinter : public ArgumentPrinter
{
public:
    using ArgumentPrinter::ArgumentPrinter;

    std::string print(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t argument) const;
    uint64_t value(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t argument) const;
    bool reads_output() const
    {
        return true;
    }
};

class UlongLongPrinter : public ArgumentPrinter
{
public:
    using ArgumentPrinter::ArgumentPrinter;

    std::string print(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t argument) const;
    uint64_t value(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t argument) const;
    bool reads_output() const
    {
        return true;
    }
};

class GuidPrinter : public ArgumentPrinter
{
public:
    using ArgumentPrinter::ArgumentPrinter;

    std::string print(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t argument) const;
};

class PointerToPointerPrinter : public ArgumentPrinter
{
public:
    using ArgumentPrinter::ArgumentPrinter;

    std::string print(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t argument) const;
    uint64_t value(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t argument) const;
    bool reads_output() const
    {
        return true;
    }
};

/*
 * Bytes at the argument, as many as another argument says -- `buffer[Len]`
 * in a hook list, Len an argument's name -- or as the call returns
 * (`[return]`: recv, SSL_read). Printed like a string, every byte that is
 * not printable ASCII as \xHH, up to MAX_BYTES. `buffer` is read at the
 * hook (what the call is given: send's, CryptEncrypt's plaintext),
 * `obuffer` at the return (what it filled: InternetReadFile's, recv's,
 * CryptDecrypt's plaintext). Without its length, a plain pointer.
 */
class BufferPrinter : public ArgumentPrinter
{
    std::string length_name;
    std::optional<size_t> length_index;
    bool output;
public:
    // capemon logs a buffer up to a cap as well (buffer_log_max)
    static constexpr size_t MAX_BYTES = 4096;

    BufferPrinter(std::string arg_name, std::string length_name, bool output, PrinterConfig config = PrinterConfig{});

    const std::string& get_length_name() const
    {
        return length_name;
    }
    void set_length_index(size_t index)
    {
        length_index = index;
    }
    std::optional<size_t> length_argument() const
    {
        return length_index;
    }
    bool length_from_return() const
    {
        return length_name == "return";
    }
    bool reads_output() const
    {
        return output;
    }
    std::string print_sized(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t argument, uint64_t length) const;

    static std::string print_bytes(const std::string& name, const PrinterConfig& config, uint64_t argument,
        const uint8_t* data, size_t size);
};

// A WSABUF array (WSASend's, WSARecv's lpBuffers): the first buffer's bytes,
// as BufferPrinter prints them. Read at the return, where WSARecv's is filled.
class WsaBufPrinter : public ArgumentPrinter
{
public:
    using ArgumentPrinter::ArgumentPrinter;

    std::string print(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t argument) const;
    bool reads_output() const
    {
        return true;
    }
};

// A SecBufferDesc (EncryptMessage's, DecryptMessage's pMessage): the bytes
// of its first SECBUFFER_DATA buffer, as BufferPrinter prints them -- the
// message itself, beside the header, trailer and padding tokens. Both
// calls work in place: `psecbufferdesc` is read at the hook (the plaintext
// EncryptMessage is given), `opsecbufferdesc` at the return (the
// plaintext DecryptMessage made).
class SecBufferDescPrinter : public ArgumentPrinter
{
    bool output;
public:
    static constexpr uint32_t SECBUFFER_DATA = 1;
    // BufferType's high bits are attributes (SECBUFFER_READONLY...)
    static constexpr uint32_t SECBUFFER_ATTRMASK = 0xF0000000;
    // More than a message ever has (SChannel's: four); bounds the walk
    static constexpr uint32_t MAX_BUFFERS = 16;

    SecBufferDescPrinter(std::string arg_name, bool output, PrinterConfig config = PrinterConfig{})
        : ArgumentPrinter(std::move(arg_name), config), output(output) {}

    std::string print(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t argument) const;
    bool reads_output() const
    {
        return output;
    }
};

// A CLIENT_ID (NtOpenProcess's, NtOpenThread's, RtlCreateUserThread's) as
// "pid:tid", in decimal: name=0xADDR:"1234:0".
class ClientIdPrinter : public ArgumentPrinter
{
public:
    using ArgumentPrinter::ArgumentPrinter;

    std::string print(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t argument) const;
    bool reads_output() const
    {
        return true;
    }
};

// A LARGE_INTEGER, signed, in decimal: NtDelayExecution's interval is
// negative 100 ns units for a relative delay (-50000000 is 5 s).
class LargeIntegerPrinter : public ArgumentPrinter
{
public:
    using ArgumentPrinter::ArgumentPrinter;

    std::string print(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t argument) const;
};

/*
 * A resolver's answer, from the pointer the call writes it through
 * (getaddrinfo's, GetAddrInfoW's res; GetAddrInfoExW's ppResult): the
 * addresses of the list's nodes, comma-separated -- "203.0.113.7,2001:db8::1".
 * `ex`: ADDRINFOEX, with its blob and provider before ai_next. Read at the
 * return, where the list exists.
 */
class AddrinfoPrinter : public ArgumentPrinter
{
    bool ex;
public:
    AddrinfoPrinter(std::string arg_name, bool ex, PrinterConfig config = PrinterConfig{});

    std::string print(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t argument) const;
    bool reads_output() const
    {
        return true;
    }
};

// DnsQuery_*'s answer (ppQueryResults): the A and AAAA records' addresses,
// as AddrinfoPrinter prints them
class DnsRecordPrinter : public ArgumentPrinter
{
public:
    using ArgumentPrinter::ArgumentPrinter;

    std::string print(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t argument) const;
    bool reads_output() const
    {
        return true;
    }
};

// A NULL-terminated array of strings (execve's argv), joined by spaces
class ArgvPrinter : public ArgumentPrinter
{
public:
    using ArgumentPrinter::ArgumentPrinter;

    std::string print(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t argument) const;
};

// A thread CONTEXT (NtSetContextThread's, SetThreadContext's): the debug
// registers and the instruction pointer, "Dr0=0x0;...;Dr7=0x0;Rip=0x..."
class ContextPrinter : public ArgumentPrinter
{
public:
    using ArgumentPrinter::ArgumentPrinter;

    std::string print(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t argument) const;
};

/*
 * Argument `i` of a call printed by its printer, a buffer with the length
 * its length argument stands for (that printer's value()) or the call's
 * return value. `arguments` are the call's raw arguments, read at the hook;
 * `return_value` is none when printing at the hook.
 */
std::string print_argument(drakvuf_t drakvuf, drakvuf_trap_info* info,
    const std::vector<std::unique_ptr<ArgumentPrinter>>& printers, const std::vector<uint64_t>& arguments,
    size_t i, std::optional<uint64_t> return_value);

// A sockaddr -- connect's, sendto's, accept's... -- printed as the address it
// holds (format_sockaddr), like a string: name=0xADDR:"203.0.113.7:443". As
// a plain pointer when it holds none this decodes.
class SockaddrPrinter : public ArgumentPrinter
{
public:
    using ArgumentPrinter::ArgumentPrinter;

    std::string print(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t argument) const;
    // accept's, recvfrom's and getpeername's are the call's to fill; the
    // ones a call reads are the caller's, unchanged by the return
    bool reads_output() const
    {
        return true;
    }
};

// A pointer to a sockaddr pointer the call fills (GetAcceptExSockaddrs's
// LocalSockaddr and RemoteSockaddr: where in AcceptEx's buffer each address
// is): the address that one holds, as SockaddrPrinter prints it. Read at
// the return.
class PointerToSockaddrPrinter : public SockaddrPrinter
{
public:
    using SockaddrPrinter::SockaddrPrinter;

    std::string print(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t argument) const;
};

class BitMaskPrinter : public ArgumentPrinter
{
    std::map < uint64_t, std::string > dict;
public:
    BitMaskPrinter(std::string arg_name, std::map < uint64_t, std::string > dict, PrinterConfig config = PrinterConfig{});
    std::string print(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t argument) const;
};

#endif
