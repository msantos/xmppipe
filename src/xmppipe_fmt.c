/* Copyright (c) 2015-2023, Michael Santos <michael.santos@gmail.com>
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
#include "errno.h"
#include "xmppipe.h"

static unsigned char rfc3986[256];

int xmppipe_fmt_init(void) {
  int i;

  for (i = 0; i < 256; i++)
    rfc3986[i] = (i >= '0' && i <= '9') || (i >= 'a' && i <= 'z') ||
                         (i >= 'A' && i <= 'Z') || i == '~' || i == '-' ||
                         i == '.' || i == '_' || i == '@' || i == '/'
                     ? i
                     : 0;

  return 0;
}

char *xmppipe_nfmt_encode(const char *s, size_t len) {
  char *buf = xmppipe_calloc(len * 3 + 1, 1);
  char *p = buf;
  size_t i;

  for (i = 0; i < len; i++) {
    unsigned char c = s[i];
    if (rfc3986[c]) {
      *p = c;
      p++;
    } else {
      p += sprintf(p, "%%%02X", c);
    }
  }

  return buf;
}

char *xmppipe_fmt_encode(const char *s) {
  return xmppipe_nfmt_encode(s, strlen(s));
}

char *xmppipe_nfmt_decode(const char *s, size_t len) {
  char *buf;
  char *p;
  size_t i;
  char fmt[3] = {0};
  char *endptr;

  buf = xmppipe_calloc(len + 1, 1);
  p = buf;

  for (i = 0; i < len; i++) {
    unsigned char c = s[i];
    if (c == '%') {
      unsigned char n = 0;

      if (i + 2 > len)
        goto XMPPIPE_ERR;

      (void)memcpy(fmt, s + i + 1, 2);

      errno = 0;
      n = strtol(fmt, &endptr, 16);

      if ((errno != 0) || (endptr == fmt))
        goto XMPPIPE_ERR;

      *p++ = n;
      i += 2;
    } else {
      *p++ = c;
    }
  }

  return buf;

XMPPIPE_ERR:
  free(buf);
  return NULL;
}

char *xmppipe_fmt_decode(const char *s) {
  if (s == NULL)
    return NULL;

  return xmppipe_nfmt_decode(s, strlen(s));
}
