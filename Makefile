RM=rm

UNAME_SYS := $(shell uname -s)
ifeq ($(UNAME_SYS), Linux)
	LDFLAGS += -luuid -lresolv
else ifeq ($(UNAME_SYS), SunOS)
	LDFLAGS += -luuid -lresolv
else ifeq ($(UNAME_SYS), Darwin)
	LDFLAGS += -lresolv
endif

all:
	$(CC) -g -Wall $(CFLAGS) -o xmppipe src/*.c $(LDFLAGS) -lstrophe

static:
	$(CC) -g -Wall -o xmppipe src/*.c -Wl,--no-as-needed -ldl -lz \
		/usr/local/lib/libstrophe.a \
		/usr/lib/*/libresolv.a \
		/usr/lib/*/libssl.a \
		/usr/lib/*/libcrypto.a \
		/usr/lib/*/libexpat.a \
		/usr/lib/*/libuuid.a

clean:
	-@$(RM) xmppipe
