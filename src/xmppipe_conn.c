/* Copyright (c) 2017, Michael Santos <michael.santos@gmail.com>
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
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

/* Retrieve the XMPP socket opened by libstrophe.
 *
 * Ideally getting the XMPP socket would be as simple as:
 *
 * state->conn->sock
 *
 * But xmpp_conn_t is defined as an opaque type.
 *
 * The alternative is hardcoding the offsets based on the libstrophe version.
 */
int xmppipe_conn_fd(xmppipe_state_t *state) {
  int fd = 0;
  struct rlimit rl = {0};
  struct stat st = {0};

  if (getrlimit(RLIMIT_NOFILE, &rl) < 0)
    return -1;

  for (fd = rl.rlim_cur; fd > STDERR_FILENO; fd--) {
    if (fcntl(fd, F_GETFD, 0) < 0)
      continue;

    if (fstat(fd, &st) < 0)
      return -1;

    if (!S_ISSOCK(st.st_mode))
      continue;

    return fd;
  }

  return -1;
}
