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
* This file was created by Jan Gruber.                                    *
* It is distributed as part of DRAKVUF under the same license             *
***************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <string.h>
#include <glib/gprintf.h>
#include <string>

#include "qmp_connection.h"

static int qmp_read_reply(qmp_connection* qc, unsigned long id, char** out);

/* Checks, if the given string matches a success response */
int qmp_check_result_str(const char* s, size_t n)
{
    if (strncmp(s, QMP_SUCCESS, n) != 0)
        return -1;

    return 0;
}

/* Checks, resulting JSON-object, if it matches a success response */
int qmp_check_result_json(struct json_object* jo)
{
    if (json_object_object_get_ex(jo, QMP_RETURN, NULL))
    {
        return 0;
    }

    return -1;
}

/* Takes a caller allocated QMPConnection strcut and initializes connection */
int qmp_init_conn(qmp_connection* qc,  const char* path)
{
    int ret = -1;

    /* Creates a socket */
    qc->fd = socket(AF_UNIX, SOCK_STREAM, 0);

    if (qc->fd == -1)
    {
        fprintf(stderr, "Opening socket failed - %s\n", strerror(errno));
        return qc->fd;
    }
    qc->sa.sun_family = AF_UNIX;

    /* Check, if path to domain is too long */
    if ((strlen(path) + 1) > sizeof(qc->sa.sun_path))
    {
        fprintf(stderr, "Path to domain socket exceeds %ld characters\n",
            sizeof(qc->sa.sun_path));
        return -1;
    }

    /* Sets socket path */
    g_snprintf(qc->sa.sun_path, sizeof(qc->sa.sun_path), "%s", path);
    qc->pending_len = 0;
    qc->last_id = 0;
    qc->is_connected = false;

    /* Initializes connection */
    ret = connect(qc->fd, (struct sockaddr*) &qc->sa, sizeof(qc->sa));

    if (ret == -1)
    {
        fprintf(stderr, "Connecting to %s failed - %s\n", qc->sa.sun_path,
            strerror(errno));
        return -1;
    }

    /* Reads the capabilities, which are sent by the qmp-server */
    ret = read(qc->fd, qc->buf, sizeof(qc->buf));

    if (ret == -1)
    {
        qc->buf[BUF_SIZE - 1] = '\0'; /* Ensures termination */
        fprintf(stderr, "Fetching QMP greeting banner failed - %s\n", qc->buf);
        return -1;
    }

    memset(qc->buf, 0, sizeof(qc->buf));

    /* Exits capabilities negotiation mode */
    ret = write(qc->fd, QMP_EXEC_CAPABILITIES, strlen(QMP_EXEC_CAPABILITIES));

    if (ret == -1)
    {
        fprintf(stderr, "Write to %s failed - %s\n", qc->sa.sun_path,
            strerror(errno));
        return -1;
    }
    /* Check return value */
    ret = read(qc->fd, qc->buf, sizeof(qc->buf));

    if (ret == -1)
    {
        fprintf(stderr, "Read from %s failed - %s\n", qc->sa.sun_path,
            strerror(errno));
        return -1;
    }

    if (qmp_check_result_str(qc->buf, BUF_SIZE) != 0)
    {
        qc->buf[BUF_SIZE - 1] = '\0'; /* Ensures termination */
        fprintf(stderr, "Entering command mode failed, msg: %s\n", qc->buf);
        return -1;
    }

    qc->is_connected = true;

    return 0;
}

/* Sends the given data to the QMPConnection and reads the response */
int qmp_communicate_json(qmp_connection* qc, struct json_object* in,
    struct json_object** out)
{
    if (out)
        *out = NULL;

    unsigned long id = ++qc->last_id;
    json_object_object_add(in, "id", json_object_new_int64((int64_t)id));

    /* One line per command */
    std::string line = std::string(json_object_to_json_string_ext(in, JSON_C_TO_STRING_PLAIN)) + "\n";
    if (write(qc->fd, line.data(), line.size()) != (ssize_t)line.size())
    {
        fprintf(stderr, "Write to %s failed - %s\n", qc->sa.sun_path,
            strerror(errno));
        return -1;
    }

    char* out_str = NULL;
    if (qmp_read_reply(qc, id, &out_str) != 0)
        return -1;

    if (out)
        *out = json_tokener_parse(out_str);
    free(out_str);

    return 0;
}

/*
 * The next whole line the server sent, without its line end, in a buffer
 * the caller frees. -1 when none came in QMP_REPLY_TIMEOUT_MS or the socket
 * failed. A line longer than the buffer is no reply of ours and is dropped.
 */
static int qmp_next_line(qmp_connection* qc, char** line)
{
    for (;;)
    {
        char* end = (char*)memchr(qc->pending, '\n', qc->pending_len);
        if (end)
        {
            size_t n = end - qc->pending;
            *line = strndup(qc->pending, n);
            memmove(qc->pending, end + 1, qc->pending_len - n - 1);
            qc->pending_len -= n + 1;
            return 0;
        }
        if (qc->pending_len == sizeof(qc->pending))
            qc->pending_len = 0;

        struct pollfd p = { qc->fd, POLLIN, 0 };
        int ready = poll(&p, 1, QMP_REPLY_TIMEOUT_MS);
        if (ready <= 0)
        {
            fprintf(stderr, "No reply from %s%s%s\n", qc->sa.sun_path,
                ready < 0 ? " - " : "", ready < 0 ? strerror(errno) : "");
            return -1;
        }
        ssize_t got = read(qc->fd, qc->pending + qc->pending_len, sizeof(qc->pending) - qc->pending_len);
        if (got <= 0)
        {
            fprintf(stderr, "Read from %s failed - %s\n", qc->sa.sun_path,
                got < 0 ? strerror(errno) : "closed");
            return -1;
        }
        qc->pending_len += got;
    }
}

/*
 * The reply to the command with `id`: the next line with that id and a
 * `return` or an `error`. Events, and replies to commands given up on, are
 * read past. Reading whatever one read() returned, as this did until
 * 2026-11-15, handed a command an event or another's reply -- the
 * screendump's "done" arrived before the file did, and hidsim renamed a
 * frame QEMU had not written (sandbox jobs a900801c, 27bd6c98, e5049989).
 */
static int qmp_read_reply(qmp_connection* qc, unsigned long id, char** out)
{
    for (;;)
    {
        char* line = NULL;
        if (qmp_next_line(qc, &line) != 0)
            return -1;

        struct json_object* jo = json_tokener_parse(line);
        struct json_object* jid = NULL;
        bool reply = jo
            && (json_object_object_get_ex(jo, QMP_RETURN, NULL) || json_object_object_get_ex(jo, "error", NULL))
            && json_object_object_get_ex(jo, "id", &jid)
            && (unsigned long)json_object_get_int64(jid) == id;
        if (jo)
            json_object_put(jo);

        if (reply)
        {
            if (out)
                *out = line;
            else
                free(line);
            return 0;
        }
        free(line);
    }
}

/* Sends the given command to the QMPConnection and waits for its reply */
int qmp_communicate(qmp_connection* qc, const char* in, char** out)
{
    if (out)
        *out = NULL;
    struct json_object* jo = json_tokener_parse(in);
    if (!jo)
    {
        fprintf(stderr, "Not a QMP command: %s\n", in);
        return -1;
    }
    struct json_object* reply = NULL;
    int ret = qmp_communicate_json(qc, jo, out ? &reply : NULL);
    if (reply)
    {
        *out = strdup(json_object_to_json_string(reply));
        json_object_put(reply);
    }
    json_object_put(jo);
    return ret;
}

/* Clean-up */
int qmp_close_conn(qmp_connection* qc)
{
    return close(qc->fd);
}
