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

static unsigned char rfc3986[256];

    void
encode_init()
{
    int i = 0;

    for (i = 0; i < 256; i++)
        rfc3986[i] = isalnum(i) || i == '~' || i == '-' || i == '.' || i == '_'
            ? i : 0;
}
    char *
encode(const char *s)
{
    // XXX overflow
    size_t len = strlen(s);
    char *buf = xmppipe_calloc(1, len * 3 + 1);
    char *p = buf;
    int n = 0;

    for (; *s; s++) {
        // XXX signed
        unsigned char c = *s;
        n = rfc3986[c]
            ? sprintf(p, "%c", rfc3986[c])
            : sprintf(p, "%%%02X", c);
        p += n;
    }

    return buf;
}
