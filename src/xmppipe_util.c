/* Copyright (c) 2015, Michael Santos <michael.santos@gmail.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include "xmppipe.h"

#include <fcntl.h>

    int
xmppipe_set_nonblock(int fd)
{
    int flags = 0;

    flags = fcntl(fd, F_GETFD);
    if (flags < 0)
        return -1;

    if (fcntl(fd, F_SETFD, flags|O_NONBLOCK) < 0)
        return -1;

    return 0;
}

    char *
xmppipe_getenv(const char *s)
{
    char *p = getenv(s);

    if (!p)
        return NULL;

    return xmppipe_strdup(p);
}

    char *
xmppipe_strdup(const char *s)
{
    char *buf = NULL;

    if (!*s)
        errx(2, "invalid string");

    buf = strdup(s);
    if (!buf)
        err(3, "allocation failure");

    return buf;
}

    void *
xmppipe_malloc(size_t size)
{
    char *buf = NULL;

    if (size == 0 || size > 0xffff)
        errx(2, "invalid size: %zd", size);

    buf = malloc(size);
    if (!buf)
        err(3, "allocation failure");

    return buf;
}

    void *
xmppipe_calloc(size_t nmemb, size_t size)
{
    char *buf = NULL;

    /* XXX overflow */
    buf = calloc(nmemb, size);
    if (!buf)
        err(3, "allocation failure");

    return buf;
}

    char *
xmppipe_servername(char *jid)
{
    char *buf = xmppipe_strdup(jid);
    char *p = strchr(buf, '@');
    char *q;

    if (!p)
        return NULL;

    *p++ = '\0';

    q = xmppipe_strdup(p);
    free(buf);

    return q;
}

    char *
xmppipe_conference(char *room, char *mucservice)
{
    size_t len = strlen(room) + 1 + strlen(mucservice) + 1;
    char *buf = xmppipe_malloc(len);

    (void)snprintf(buf, len, "%s@%s", room, mucservice);

    return buf;
}

    char *
xmppipe_mucjid(char *muc, char *resource)
{
    size_t len = strlen(muc) + 1 + strlen(resource) + 1;
    char *buf = xmppipe_malloc(len);

    (void)snprintf(buf, len, "%s/%s", muc, resource);

    return buf;
}

    char *
xmppipe_roomname(char *label)
{
    char *buf = NULL;
    size_t len = 64;
    char name[16] = {0};

    buf = xmppipe_malloc(len);
    (void)gethostname(name, sizeof(name));
    name[sizeof(name)-1] = '\0';

    (void)snprintf(buf, len, "%s-%s-%d", label, name, getpid());

    return buf;
}
