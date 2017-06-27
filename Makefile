.PHONY: all static clean test

PROG=xmppipe
RM=rm

UNAME_SYS := $(shell uname -s)
ifeq ($(UNAME_SYS), Linux)
	LDFLAGS += -lresolv -Wl,-Bsymbolic-functions -Wl,-z,relro
	CFLAGS ?= -D_FORTIFY_SOURCE=2 -O2 -fstack-protector \
			  --param=ssp-buffer-size=4 -Wformat -Werror=format-security \
			  -fno-strict-aliasing
	XMPPIPE_SANDBOX ?= XMPPIPE_SANDBOX_SECCOMP
	XMPPIPE_SANDBOX_RLIMIT_NOFILE ?= 0
else ifeq ($(UNAME_SYS), FreeBSD)
	CFLAGS ?= -DHAVE_STRTONUM \
			  -D_FORTIFY_SOURCE=2 -O2 -fstack-protector \
			  --param=ssp-buffer-size=4 -Wformat -Werror=format-security \
			  -fno-strict-aliasing
	XMPPIPE_SANDBOX ?= XMPPIPE_SANDBOX_CAPSICUM
else ifeq ($(UNAME_SYS), OpenBSD)
	XMPPIPE_SANDBOX ?= XMPPIPE_SANDBOX_PLEDGE
	CFLAGS ?= -DHAVE_STRTONUM \
			  -D_FORTIFY_SOURCE=2 -O2 -fstack-protector \
			  --param=ssp-buffer-size=4 -Wformat -Werror=format-security \
			  -fno-strict-aliasing
else ifeq ($(UNAME_SYS), SunOS)
	LDFLAGS += -lresolv
else ifeq ($(UNAME_SYS), Darwin)
	LDFLAGS += -lresolv
endif

XMPPIPE_SANDBOX ?= XMPPIPE_SANDBOX_RLIMIT
XMPPIPE_SANDBOX_RLIMIT_NOFILE ?= -1

XMPPIPE_CFLAGS ?= -g -Wall
CFLAGS += $(XMPPIPE_CFLAGS) \
		  -DXMPPIPE_SANDBOX=\"$(XMPPIPE_SANDBOX)\" -D$(XMPPIPE_SANDBOX) \
		  -DXMPPIPE_SANDBOX_RLIMIT_NOFILE=$(XMPPIPE_SANDBOX_RLIMIT_NOFILE)

LDFLAGS += $(XMPPIPE_LDFLAGS)

all: $(PROG)

$(PROG):
	$(CC) $(CFLAGS) -o xmppipe src/*.c $(LDFLAGS) -lstrophe

static:
	$(CC) $(CFLAGS) -g -Wall -o xmppipe src/*.c -Wl,--no-as-needed \
		-ldl -lz -lresolv \
		/usr/local/lib/libstrophe.a \
		/usr/lib/*/libssl.a \
		/usr/lib/*/libcrypto.a \
		/usr/lib/*/libexpat.a

clean:
	-@$(RM) $(PROG)

test: $(PROG)
	-@PATH=.:$$PATH bats test
