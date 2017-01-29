RM=rm

UNAME_SYS := $(shell uname -s)
ifeq ($(UNAME_SYS), Linux)
	LDFLAGS += -luuid -lresolv -Wl,-Bsymbolic-functions -Wl,-z,relro
	CFLAGS ?= -D_FORTIFY_SOURCE=2 -O2 -fstack-protector --param=ssp-buffer-size=4 -Wformat -Werror=format-security -fno-strict-aliasing
else ifeq ($(UNAME_SYS), SunOS)
	LDFLAGS += -luuid -lresolv
else ifeq ($(UNAME_SYS), Darwin)
	LDFLAGS += -lresolv
endif

XMPPIPE_SANDBOX ?= XMPPIPE_SANDBOX_NULL
CFLAGS += -D$(XMPPIPE_SANDBOX)

all:
	$(CC) -g -Wall $(CFLAGS) -o xmppipe src/*.c $(LDFLAGS) -lstrophe

static:
	$(CC) $(CFLAGS) -g -Wall -o xmppipe src/*.c -Wl,--no-as-needed -ldl -lz \
		/usr/local/lib/libstrophe.a \
		/usr/lib/*/libresolv.a \
		/usr/lib/*/libssl.a \
		/usr/lib/*/libcrypto.a \
		/usr/lib/*/libexpat.a \
		/usr/lib/*/libuuid.a

clean:
	-@$(RM) xmppipe
