/* Copyright (c) 2017-2023, Michael Santos <michael.santos@gmail.com>
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
#ifdef RESTRICT_PROCESS_rlimit
#include <sys/resource.h>
#include <sys/time.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>

#include "xmppipe.h"

int restrict_process_init(xmppipe_state_t *state) {
  struct rlimit rl_zero = {0};
  struct stat sb = {0};

  if (fstat(STDOUT_FILENO, &sb) < 0)
    return -1;

  if (!S_ISREG(sb.st_mode)) {
    if (setrlimit(RLIMIT_FSIZE, &rl_zero) < 0)
      return -1;
  }

  return setrlimit(RLIMIT_NPROC, &rl_zero);
}

int restrict_process_stdin(xmppipe_state_t *state) {
  struct rlimit rl = {0};

  rl.rlim_cur = RESTRICT_PROCESS_RLIMIT_NOFILE;
  rl.rlim_max = RESTRICT_PROCESS_RLIMIT_NOFILE;

  if (rl.rlim_cur == (rlim_t)-1) {
    int fd = xmppipe_conn_fd(state);
    if (fd < 0)
      return -1;
    rl.rlim_cur = rl.rlim_max = fd + 1;
  }

  return setrlimit(RLIMIT_NOFILE, &rl);
}
#endif
