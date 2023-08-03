.PHONY: all static clean test

PROG=xmppipe
RM=rm

UNAME_SYS := $(shell uname -s)
ifeq ($(UNAME_SYS), Linux)
	CFLAGS ?= -D_FORTIFY_SOURCE=2 -O2 -fstack-protector-strong \
			  -Wformat -Werror=format-security \
			  -Wshadow \
			  -Wpointer-arith -Wcast-qual \
			  -Wstrict-prototypes -Wmissing-prototypes \
			  -pie -fPIE \
			  -fno-strict-aliasing
	RESTRICT_PROCESS ?= seccomp
	RESTRICT_PROCESS_RLIMIT_NOFILE ?= 0
	LDFLAGS ?= -Wl,-z,relro,-z,now -Wl,-z,noexecstack
else ifeq ($(UNAME_SYS), FreeBSD)
	CFLAGS ?= -DHAVE_STRTONUM \
			  -D_FORTIFY_SOURCE=2 -O2 -fstack-protector-strong \
			  -Wformat -Werror=format-security \
			  -pie -fPIE \
			  -fno-strict-aliasing
	RESTRICT_PROCESS ?= capsicum
	LDFLAGS ?= -Wl,-z,relro,-z,now -Wl,-z,noexecstack
else ifeq ($(UNAME_SYS), OpenBSD)
	CFLAGS ?= -DHAVE_STRTONUM \
			  -D_FORTIFY_SOURCE=2 -O2 -fstack-protector-strong \
			  -Wformat -Werror=format-security \
			  -pie -fPIE \
			  -fno-strict-aliasing
	RESTRICT_PROCESS ?= pledge
	LDFLAGS ?= -Wl,-z,relro,-z,now -Wl,-z,noexecstack
else ifeq ($(UNAME_SYS), SunOS)
else ifeq ($(UNAME_SYS), Darwin)
	CFLAGS ?= -D_FORTIFY_SOURCE=2 -O2 -fstack-protector-strong \
			  -Wformat -Werror=format-security \
			  -pie -fPIE \
			  -fno-strict-aliasing
endif

RESTRICT_PROCESS ?= rlimit
RESTRICT_PROCESS_RLIMIT_NOFILE ?= -1

XMPPIPE_CFLAGS ?= -g -Wall
CFLAGS += $(XMPPIPE_CFLAGS) \
		  -Wextra -Wno-unused-parameter \
		  -fwrapv \
		  -DRESTRICT_PROCESS=\"$(RESTRICT_PROCESS)\" \
		  -DRESTRICT_PROCESS_$(RESTRICT_PROCESS) \
		  -DRESTRICT_PROCESS_RLIMIT_NOFILE=$(RESTRICT_PROCESS_RLIMIT_NOFILE)

LDFLAGS += $(XMPPIPE_LDFLAGS)

all: $(PROG)

$(PROG):
	$(CC) $(CFLAGS) -o xmppipe src/*.c $(LDFLAGS) -lstrophe

static:
	$(CC) $(CFLAGS) \
		$(XMPPIPE_CFLAGS) \
		-o xmppipe src/*.c -Wl,--no-as-needed \
		$(LDFLAGS) -ldl -lpthread -lz -lresolv \
		-l:libstrophe.a \
		-l:libssl.a -l:libcrypto.a \
		-l:libexpat.a

clean:
	-@$(RM) $(PROG)

test: $(PROG)
	-@PATH=.:$$PATH bats test
