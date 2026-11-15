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
* Any redistribution ofQMP_EXEC_CAPABILITIEScluding aQMP_EXEC_CAPABILITIES*
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
* It is distributed as part of DRAKVUF under the same license             *
***************************************************************************/

/*
 * The QMP client against a server that does what QEMU's may: events between
 * replies, a reply in pieces, two in one read, a reply to a command given up
 * on. Standalone, like gui/screen_buttons_test.cpp:
 *
 *   g++ -std=c++17 -DQMP_REPLY_TIMEOUT_MS=300 -I. qmp/qmp_connection_test.cpp \
 *       qmp/qmp_connection.cpp $(pkg-config --cflags --libs json-c glib-2.0) -o qmp_test && ./qmp_test
 */
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string>
#include <thread>

#include "qmp_connection.h"

static int failures = 0;

#define CHECK(what) do { if (!(what)) { failures++; fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #what); } } while (0)

static void say(int fd, const std::string& text)
{
    if (write(fd, text.data(), text.size()) != (ssize_t)text.size())
        failures++;
}

/* The id of the command the client sent, read off its line */
static long command_id(int fd)
{
    std::string line;
    char c;
    while (read(fd, &c, 1) == 1 && c != '\n')
        line += c;
    const char* at = strstr(line.c_str(), "\"id\":");
    return at ? atol(at + 5) : -1;
}

static long screendump(qmp_connection* qc, int* ok)
{
    json_object* cmd = json_tokener_parse("{\"execute\":\"screendump\",\"arguments\":{\"filename\":\"/x\"}}");
    json_object* out = nullptr;
    *ok = qmp_communicate_json(qc, cmd, &out);
    long got = -1;
    json_object* ret = nullptr;
    json_object* frame = nullptr;
    if (out && json_object_object_get_ex(out, QMP_RETURN, &ret) && json_object_object_get_ex(ret, "frame", &frame))
        got = json_object_get_int64(frame);
    if (out)
        json_object_put(out);
    json_object_put(cmd);
    return got;
}

int main()
{
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
        return 2;
    qmp_connection qc = {};
    qc.fd = sv[0];
    snprintf(qc.sa.sun_path, sizeof(qc.sa.sun_path), "test");

    std::thread server([&]
    {
        // 1: an event first, a stale reply, then the reply split in two writes
        long id = command_id(sv[1]);
        say(sv[1], "{\"event\": \"RTC_CHANGE\", \"data\": {\"offset\": 0}}\r\n");
        say(sv[1], "{\"return\": {\"frame\": 999}, \"id\": " + std::to_string(id - 1) + "}\r\n");
        say(sv[1], "{\"return\": {\"fra");
        usleep(20000);
        say(sv[1], "me\": 1}, \"id\": " + std::to_string(id) + "}\r\n");
        // 2 and 3: both replies in one write, the second read from what is left
        long second = command_id(sv[1]);
        long third = second + 1;
        say(sv[1], "{\"return\": {\"frame\": 2}, \"id\": " + std::to_string(second) + "}\r\n"
            "{\"return\": {\"frame\": 3}, \"id\": " + std::to_string(third) + "}\r\n");
        command_id(sv[1]);
        // 4: an error is a reply too
        long fourth = command_id(sv[1]);
        say(sv[1], "{\"error\": {\"class\": \"GenericError\", \"desc\": \"no\"}, \"id\": " + std::to_string(fourth) + "}\r\n");
        // 5: nothing comes
        command_id(sv[1]);
    });

    int ok = 0;
    CHECK(screendump(&qc, &ok) == 1 && ok == 0);
    CHECK(screendump(&qc, &ok) == 2 && ok == 0);
    CHECK(screendump(&qc, &ok) == 3 && ok == 0);
    // an error reply: no `return`, which callers check for
    CHECK(screendump(&qc, &ok) == -1 && ok == 0);
    // no reply within the timeout: a failure, not a wait for ever
    CHECK(screendump(&qc, &ok) == -1 && ok == -1);

    server.join();
    close(sv[0]);
    close(sv[1]);
    if (failures)
        fprintf(stderr, "%d failed\n", failures);
    else
        printf("qmp_connection: all passed\n");
    return failures ? 1 : 0;
}
