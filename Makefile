RM=rm

all:
	$(CC) -g -Wall $(CFLAGS) -o xmppipe src/*.c $(LDFLAGS) -lstrophe

clean:
	-@$(RM) xmppipe
