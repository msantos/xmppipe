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

#if defined(__linux__) || defined(__sunos__) || (defined(__APPLE__) && defined(__MACH__))
#include <uuid/uuid.h>
#elif defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#include <uuid.h>
#endif

    char *
xmppipe_id_alloc()
{
    uuid_t uuid = {0};
    char *out = NULL;

#if defined(__linux__) || defined(__sunos__) || (defined(__APPLE__) && defined(__MACH__))
    out = xmppipe_calloc(37,1);
    uuid_generate(uuid);
    uuid_unparse(uuid, out);
#elif defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    uint32_t status = 0;

    uuid_create(&uuid, &status);
    if (status != uuid_s_ok)
        return NULL;

    uuid_to_string(&uuid, &out, &status);
    if (status != uuid_s_ok)
        return NULL;
#endif

    return out;
}
