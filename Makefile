RM=rm

all:
	$(CC) -g -Wall $(CFLAGS) -o xmppipe src/*.c $(LDFLAGS) -lstrophe -luuid -lresolv

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
