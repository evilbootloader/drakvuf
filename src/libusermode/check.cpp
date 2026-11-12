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

#include "utils.hpp"
#include "printers/printers.hpp"
#include "userhook.hpp"

#include <sstream>
#include <string>

#include <check.h>

START_TEST(test_match_dll_name)
{
    ck_assert(is_dll_name_matched("\\Windows\\System32\\msi.dll", "msi.dll"));
    ck_assert(is_dll_name_matched("\\Windows\\System32\\msi.DLL", "msi.dll"));
    ck_assert(is_dll_name_matched("\\Windows\\System32\\MSI.DLL", "msi.dll"));
    ck_assert(!is_dll_name_matched("\\Windows\\System32\\amsi.dll", "msi.dll"));
    ck_assert(is_dll_name_matched("\\Windows\\SysWOW64\\msi.dll", "syswow64\\msi.dll"));
    ck_assert(!is_dll_name_matched("\\Windows\\SysWOW64\\msi.dll", "wow64\\msi.dll"));
    ck_assert(is_dll_name_matched("\\Windows\\System32\\msi.dll", "\\Windows\\System32\\msi.dll"));
}
END_TEST

static Suite* dll_matching_suite(void)
{
    Suite* s;
    TCase* tc_core;

    s = suite_create("Match DLL names");

    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_match_dll_name);
    suite_add_tcase(s, tc_core);

    return s;
}

static plugin_target_config_entry_t test_parse_dll_entry(const std::string& entry)
{
    PrinterConfig config;
    std::stringstream ss(entry);
    return parse_entry(ss, config);
}

START_TEST(test_parse_dll_hook)
{
    auto entry_str = "combase.dll,CoCreateInstance,log,rclsid:refclsid,punkOuter:lpvoid,dwClsContext:dword,riid:refiid,ppv:void**";
    auto entry = test_parse_dll_entry(entry_str);

    ck_assert(entry.dll_name == "combase.dll");
    ck_assert(entry.function_name == "CoCreateInstance");
    ck_assert(entry.type == HOOK_BY_NAME);
    ck_assert(entry.clsid.empty());
    ck_assert(entry.offset == 0);
    ck_assert(!entry.no_retval);
    ck_assert(entry.actions.log && !entry.actions.stack);
    ck_assert(entry.argument_printers.size() == 5);
}
END_TEST

START_TEST(test_parse_dll_hook_with_offset)
{
    auto entry_str = "taskschd.dll,ITaskFolder::RegisterTaskDefinition,clsid,0F87369F-A4E5-4CFC-BD3E-73E6154572DD,13cd3,log,lpvoid,bstr";
    auto entry = test_parse_dll_entry(entry_str);

    ck_assert(entry.dll_name == "taskschd.dll");
    ck_assert(entry.function_name == "ITaskFolder::RegisterTaskDefinition");
    ck_assert(entry.type == HOOK_BY_OFFSET);
    ck_assert(entry.clsid == "0F87369F-A4E5-4CFC-BD3E-73E6154572DD");
    ck_assert(entry.offset == 0x13cd3);
    ck_assert(!entry.no_retval);
    ck_assert(entry.actions.log && !entry.actions.stack);
    ck_assert(entry.argument_printers.size() == 2);
}
END_TEST

START_TEST(test_parse_dll_hook_with_empty_args)
{
    auto entry_str = "combase.dll,CoCreateInstance,log";
    auto entry = test_parse_dll_entry(entry_str);

    ck_assert(entry.dll_name == "combase.dll");
    ck_assert(entry.function_name == "CoCreateInstance");
    ck_assert(entry.type == HOOK_BY_NAME);
    ck_assert(entry.clsid.empty());
    ck_assert(entry.offset == 0);
    ck_assert(!entry.no_retval);
    ck_assert(entry.actions.log && !entry.actions.stack);
    ck_assert(entry.argument_printers.empty());
}
END_TEST

START_TEST(test_narrow_integer_argument)
{
    // On x64 a DWORD comes in the low half of a register whose high half is
    // whatever the caller left there
    auto entry = test_parse_dll_entry("advapi32.dll,RegSetValueExW,log,hKey:lpvoid,lpValueName:lpcwstr,"
            "Reserved:dword,dwType:dword,lpData:lpcstr,cbData:dword,Flag:bool,Lang:word");
    const auto& printers = entry.argument_printers;

    ck_assert(printers.size() == 8);
    ck_assert(printers[5]->print(nullptr, nullptr, 0x4f00000010) == "cbData=0x10");
    ck_assert(printers[6]->print(nullptr, nullptr, 0xffffffff00000001) == "Flag=0x1");
    ck_assert(printers[7]->print(nullptr, nullptr, 0x12340409) == "Lang=0x409");
    // A pointer keeps all of it
    ck_assert(printers[0]->print(nullptr, nullptr, 0x4f00000010) == "hKey=0x4f00000010");
}
END_TEST

START_TEST(test_output_arguments)
{
    // What the call writes through is read at its return
    auto entry = test_parse_dll_entry("ntdll.dll,NtAllocateVirtualMemory,log,ProcessHandle:lpvoid,"
            "BaseAddress:lpvoid*,ZeroBits:lpvoid,RegionSize:lpvoid*,AllocationType:dword,PageProtection:pulong,"
            "Name:lpcwstr");
    const auto& printers = entry.argument_printers;

    ck_assert(!printers[0]->reads_output());
    ck_assert(printers[1]->reads_output());
    ck_assert(printers[3]->reads_output());
    ck_assert(!printers[4]->reads_output());
    ck_assert(printers[5]->reads_output());
    ck_assert(!printers[6]->reads_output());

    // A sockaddr is decoded, after the call: accept's is the call's to fill
    auto connect = test_parse_dll_entry("ws2_32.dll,accept,log,s:lpvoid,addr:lpsockaddr,addrlen:pulong");
    ck_assert(dynamic_cast<const SockaddrPrinter*>(connect.argument_printers[1].get()) != nullptr);
    ck_assert(connect.argument_printers[1]->reads_output());
}
END_TEST

START_TEST(test_buffer_arguments)
{
    // The length named before or after the buffer, or the return value
    auto entry = test_parse_dll_entry("ws2_32.dll,send,log,s:lpvoid,buf:buffer[len],len:dword,flags:dword");
    auto* buf = dynamic_cast<const BufferPrinter*>(entry.argument_printers[1].get());
    ck_assert(buf && buf->length_argument() && *buf->length_argument() == 2 && !buf->reads_output());
    // The length as its printer reads it: a DWORD cut to its 32 bits
    ck_assert(entry.argument_printers[2]->value(nullptr, nullptr, 0x4f00000010) == 0x10);

    auto read = test_parse_dll_entry("wininet.dll,InternetReadFile,log,hFile:lpvoid,lpBuffer:obuffer[lpdwNumberOfBytesRead],"
            "dwNumberOfBytesToRead:dword,lpdwNumberOfBytesRead:pulong");
    auto* out = dynamic_cast<const BufferPrinter*>(read.argument_printers[1].get());
    ck_assert(out && *out->length_argument() == 3 && out->reads_output());

    auto recv = test_parse_dll_entry("ws2_32.dll,recv,log,s:lpvoid,buf:obuffer[return],len:dword,flags:dword");
    auto* ret = dynamic_cast<const BufferPrinter*>(recv.argument_printers[1].get());
    ck_assert(ret && ret->length_from_return() && !ret->length_argument());

    // A name no argument has: a plain pointer
    auto typo = test_parse_dll_entry("ws2_32.dll,send,log,s:lpvoid,buf:buffer[length],len:dword");
    ck_assert(!typo.argument_printers[1]->length_argument());
    ck_assert(typo.argument_printers[1]->print(nullptr, nullptr, 0x1000) == "buf=0x1000");
}
END_TEST

START_TEST(test_structure_arguments)
{
    auto entry = test_parse_dll_entry("ntdll.dll,NtOpenProcess,log,ProcessHandle:lpvoid*,DesiredAccess:dword,"
            "ObjectAttributes:lpvoid,ClientId:pclient_id");
    ck_assert(dynamic_cast<const ClientIdPrinter*>(entry.argument_printers[3].get()) != nullptr);
    auto delay = test_parse_dll_entry("ntdll.dll,NtDelayExecution,log,Alertable:dword,DelayInterval:plarge_integer");
    ck_assert(dynamic_cast<const LargeIntegerPrinter*>(delay.argument_printers[1].get()) != nullptr);
    auto wsa = test_parse_dll_entry("ws2_32.dll,WSASend,log,s:lpvoid,lpBuffers:lpwsabuf,dwBufferCount:dword");
    ck_assert(dynamic_cast<const WsaBufPrinter*>(wsa.argument_printers[1].get()) != nullptr);
    // A NULL one is the pointer, nothing read
    ck_assert(entry.argument_printers[3]->print(nullptr, nullptr, 0) == "ClientId=0x0");

    // A resolver's answer and a thread context: the first read at the return
    auto resolve = test_parse_dll_entry("ws2_32.dll,getaddrinfo,log,pNodeName:lpcstr,pServiceName:lpcstr,"
            "pHints:lpvoid,ppResult:ppaddrinfo");
    ck_assert(dynamic_cast<const AddrinfoPrinter*>(resolve.argument_printers[3].get()) != nullptr);
    ck_assert(resolve.argument_printers[3]->reads_output());
    auto query = test_parse_dll_entry("dnsapi.dll,DnsQuery_W,log,pszName:lpcwstr,wType:dword,Options:dword,"
            "pExtra:lpvoid,ppQueryResults:ppdns_record,pReserved:lpvoid");
    ck_assert(dynamic_cast<const DnsRecordPrinter*>(query.argument_printers[4].get()) != nullptr);
    auto context = test_parse_dll_entry("ntdll.dll,NtSetContextThread,log,ThreadHandle:lpvoid,Context:pcontext");
    ck_assert(dynamic_cast<const ContextPrinter*>(context.argument_printers[1].get()) != nullptr);
    auto exec = test_parse_dll_entry("libc.so.6,execve,log,Path:lpcstr,argv:argv,envp:lpvoid");
    ck_assert(dynamic_cast<const ArgvPrinter*>(exec.argument_printers[1].get()) != nullptr);

    // A DATA_BLOB is read as a WSABUF; a SecBufferDesc at the hook for the
    // message EncryptMessage is given, at the return for the one
    // DecryptMessage made
    auto protect = test_parse_dll_entry("crypt32.dll,CryptProtectData,log,pDataIn:pdata_blob,"
            "szDataDescr:lpcwstr");
    ck_assert(dynamic_cast<const WsaBufPrinter*>(protect.argument_printers[0].get()) != nullptr);
    auto encrypt = test_parse_dll_entry("sspicli.dll,EncryptMessage,log,phContext:lpvoid,fQOP:dword,"
            "pMessage:psecbufferdesc,MessageSeqNo:dword");
    ck_assert(dynamic_cast<const SecBufferDescPrinter*>(encrypt.argument_printers[2].get()) != nullptr);
    ck_assert(!encrypt.argument_printers[2]->reads_output());
    auto decrypt = test_parse_dll_entry("sspicli.dll,DecryptMessage,log,phContext:lpvoid,"
            "pMessage:opsecbufferdesc,MessageSeqNo:dword,pfQOP:lpvoid");
    ck_assert(decrypt.argument_printers[1]->reads_output());
    ck_assert(decrypt.argument_printers[1]->print(nullptr, nullptr, 0) == "pMessage=0x0");

    // AcceptEx's addresses: where the call says each one is, read at the
    // return; the data received with the connection, at the call
    auto addresses = test_parse_dll_entry("mswsock.dll,GetAcceptExSockaddrs,log,"
            "lpOutputBuffer:buffer[dwReceiveDataLength],dwReceiveDataLength:dword,"
            "dwLocalAddressLength:dword,dwRemoteAddressLength:dword,LocalSockaddr:ppsockaddr,"
            "LocalSockaddrLength:pulong,RemoteSockaddr:ppsockaddr,RemoteSockaddrLength:pulong");
    ck_assert(dynamic_cast<const PointerToSockaddrPrinter*>(addresses.argument_printers[6].get()) != nullptr);
    ck_assert(addresses.argument_printers[6]->reads_output());
    ck_assert(!addresses.argument_printers[0]->reads_output());
    ck_assert(addresses.argument_printers[6]->print(nullptr, nullptr, 0) == "RemoteSockaddr=0x0");
}
END_TEST

static Suite* dll_hooks_parsing_suite(void)
{
    Suite* s;
    TCase* tc_core;

    s = suite_create("Parse DLL hooks");

    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_parse_dll_hook);
    tcase_add_test(tc_core, test_parse_dll_hook_with_offset);
    tcase_add_test(tc_core, test_parse_dll_hook_with_empty_args);
    tcase_add_test(tc_core, test_narrow_integer_argument);
    tcase_add_test(tc_core, test_output_arguments);
    tcase_add_test(tc_core, test_buffer_arguments);
    tcase_add_test(tc_core, test_structure_arguments);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite* s;
    SRunner* sr;

    s = dll_matching_suite();
    sr = srunner_create(s);
    srunner_add_suite(sr, dll_hooks_parsing_suite());

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
