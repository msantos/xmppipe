.PHONY: all static clean test

PROG=xmppipe
RM=rm

UNAME_SYS := $(shell uname -s)
ifeq ($(UNAME_SYS), Linux)
	CFLAGS ?= -D_FORTIFY_SOURCE=2 -O2 -fstack-protector-strong \
			  -Wformat -Werror=format-security \
			  -fno-strict-aliasing
	XMPPIPE_SANDBOX ?= seccomp
	XMPPIPE_SANDBOX_RLIMIT_NOFILE ?= 0
else ifeq ($(UNAME_SYS), FreeBSD)
	CFLAGS ?= -DHAVE_STRTONUM \
			  -D_FORTIFY_SOURCE=2 -O2 -fstack-protector-strong \
			  -Wformat -Werror=format-security \
			  -fno-strict-aliasing
	XMPPIPE_SANDBOX ?= capsicum
else ifeq ($(UNAME_SYS), OpenBSD)
	CFLAGS ?= -DHAVE_STRTONUM \
			  -D_FORTIFY_SOURCE=2 -O2 -fstack-protector-strong \
			  -Wformat -Werror=format-security \
			  -fno-strict-aliasing
	XMPPIPE_SANDBOX ?= pledge
else ifeq ($(UNAME_SYS), SunOS)
else ifeq ($(UNAME_SYS), Darwin)
endif

XMPPIPE_SANDBOX ?= rlimit
XMPPIPE_SANDBOX_RLIMIT_NOFILE ?= -1

XMPPIPE_CFLAGS ?= -g -Wall
CFLAGS += $(XMPPIPE_CFLAGS) \
		  -fwrapv \
		  -DXMPPIPE_SANDBOX=\"$(XMPPIPE_SANDBOX)\" \
		  -DXMPPIPE_SANDBOX_$(XMPPIPE_SANDBOX) \
		  -DXMPPIPE_SANDBOX_RLIMIT_NOFILE=$(XMPPIPE_SANDBOX_RLIMIT_NOFILE)

LDFLAGS += $(XMPPIPE_LDFLAGS) -Wl,-z,relro,-z,now

all: $(PROG)

$(PROG):
	$(CC) $(CFLAGS) -o xmppipe src/*.c $(LDFLAGS) -lstrophe

static:
	$(CC) $(CFLAGS) -g -Wall -o xmppipe src/*.c -Wl,--no-as-needed \
		-ldl -lz -lresolv \
		-l:libstrophe.a \
		-l:libssl.a -l:libcrypto.a \
		-l:libexpat.a

clean:
	-@$(RM) $(PROG)

test: $(PROG)
	-@PATH=.:$$PATH bats test
