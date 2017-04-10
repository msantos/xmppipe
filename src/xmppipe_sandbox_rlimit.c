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
#ifdef XMPPIPE_SANDBOX_RLIMIT
#include <sys/time.h>
#include <sys/resource.h>

#include "xmppipe.h"

    int
xmppipe_sandbox_init(xmppipe_state_t *state)
{
    return 0;
}

    int
xmppipe_sandbox_stdin(xmppipe_state_t *state)
{
    struct rlimit rl_zero = {0};
    struct rlimit rl_nofile = {0};

    rl_zero.rlim_cur = 0;
    rl_zero.rlim_max = 0;

    rl_nofile.rlim_cur = XMPPIPE_SANDBOX_RLIMIT_NOFILE;
    rl_nofile.rlim_max = XMPPIPE_SANDBOX_RLIMIT_NOFILE;

#ifdef RLIMIT_NPROC
    if (setrlimit(RLIMIT_NPROC, &rl_zero) < 0)
        return -1;
#endif

#ifdef RLIMIT_NOFILE
    if (rl_nofile.rlim_cur == (rlim_t)-1) {
        int fd = xmppipe_conn_fd(state);
        if (fd < 0) return -1;
        rl_nofile.rlim_cur = rl_nofile.rlim_max = fd + 1;
    }
    if (setrlimit(RLIMIT_NOFILE, &rl_nofile) < 0)
        return -1;
#endif

	return 0;
}
#endif
