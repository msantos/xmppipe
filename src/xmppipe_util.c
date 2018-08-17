/* Copyright (c) 2015-2018, Michael Santos <michael.santos@gmail.com>
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

#define XMPPIPE_NULL(a_) \
    if ((a_) == NULL) { \
        errx(3, "invalid argument: %s/%s (%s:%d)", \
            __FUNCTION__, \
            #a_, \
            __FILE__, \
            __LINE__); }

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

    if (p == NULL)
        return NULL;

    return xmppipe_strdup(p);
}

    char *
xmppipe_strdup(const char *s)
{
    char *buf = NULL;

    if (s == NULL)
        errx(2, "invalid string");

    buf = strdup(s);
    if (buf == NULL)
        err(3, "xmppipe_strdup");

    return buf;
}

    void *
xmppipe_malloc(size_t size)
{
    char *buf = NULL;

    if (size == 0 || size > 0xffff)
        errx(2, "invalid size: %zd", size);

    buf = malloc(size);
    if (buf == NULL)
        err(3, "xmppipe_malloc: %zu", size);

    return buf;
}

    void *
xmppipe_calloc(size_t nmemb, size_t size)
{
    char *buf = NULL;

    buf = calloc(nmemb, size);
    if (buf == NULL)
        err(3, "xmppipe_calloc: %zu/%zu", nmemb, size);

    return buf;
}

// https://stackoverflow.com/a/30295426
    char
*xmppipe_strtok(char *str, char const *delims)
{
    static char *src = NULL;
    char *p, *ret = 0;

    if (str != NULL) src = str;

    if (src == NULL || *src == '\0')
        return NULL;

    ret = src;
    if ((p = strpbrk(src, delims)) != NULL)
    {
        *p  = 0;
        src = ++p;
    }
    else
        src += strlen(src);

    return ret;
}

    xmpp_stanza_t *
xmppipe_stanza_new(xmpp_ctx_t *ctx)
{
    xmpp_stanza_t *s = xmpp_stanza_new(ctx);

    if (s == NULL)
        err(3, "xmppipe_stanza_new");

    return s;
}

    void
xmppipe_stanza_set_attribute(xmpp_stanza_t * const stanza,
        const char * const key, const char * const value)
{
    XMPPIPE_NULL(stanza);
    XMPPIPE_NULL(key);
    XMPPIPE_NULL(value);

    if (xmpp_stanza_set_attribute(stanza, key, value) < 0)
        err(3, "xmppipe_stanza_set_attribute");
}

    void
xmppipe_stanza_set_id(xmpp_stanza_t * const stanza, const char * const id)
{
    XMPPIPE_NULL(stanza);
    XMPPIPE_NULL(id);

    if (xmpp_stanza_set_id(stanza, id) < 0)
        err(3, "xmppipe_stanza_set_id");
}

    void
xmppipe_stanza_set_name(xmpp_stanza_t *stanza, const char * const name)
{
    XMPPIPE_NULL(stanza);
    XMPPIPE_NULL(name);

    switch (xmpp_stanza_set_name(stanza, name)) {
        case 0:
            return;
        case XMPP_EMEM:
            err(3, "xmppipe_stanza_set_name");
        case XMPP_EINVOP:
            err(4, "invalid operation");
        default:
            err(5, "unknown error");
    }
}

    void
xmppipe_stanza_set_ns(xmpp_stanza_t * const stanza, const char * const ns)
{
    XMPPIPE_NULL(stanza);
    XMPPIPE_NULL(ns);

    if (xmpp_stanza_set_ns(stanza, ns) < 0)
        err(3, "xmppipe_stanza_set_ns");
}

    void
xmppipe_stanza_set_text(xmpp_stanza_t *stanza, const char * const text)
{
    XMPPIPE_NULL(stanza);
    XMPPIPE_NULL(text);

    if (xmpp_stanza_set_text(stanza, text) < 0)
        err(3, "xmppipe_stanza_set_text");
}

    void
xmppipe_stanza_set_type(xmpp_stanza_t * const stanza, const char * const type)
{
    XMPPIPE_NULL(stanza);
    XMPPIPE_NULL(type);

    if (xmpp_stanza_set_type(stanza, type) < 0)
        err(3, "xmppipe_stanza_set_type");
}

    void
xmppipe_stanza_add_child(xmpp_stanza_t * stanza, xmpp_stanza_t * child)
{
    XMPPIPE_NULL(stanza);
    XMPPIPE_NULL(child);

    if (xmpp_stanza_add_child(stanza, child) < 0)
        err(3, "xmppipe_stanza_add_child");
}

    char *
xmppipe_servername(char *jid)
{
    char *buf = xmppipe_strdup(jid);
    char *p = strchr(buf, '@');
    char *q;

    if (p == NULL) {
        free(buf);
        return NULL;
    }

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
    if (gethostname(name, sizeof(name)) < 0) {
        (void)snprintf(name, sizeof(name)-1, "%s", XMPPIPE_RESOURCE);
    }
    name[sizeof(name)-1] = '\0';

    (void)snprintf(buf, len, "%s-%s-%d", label, name, getuid());

    return buf;
}
