# compiler
CC=g++
CFLAGS_OLDOSSL= -I/usr/include -L/usr/include -W -Wall -Wno-variadic-macros -ansi \
			-pedantic -g -Wshadow -Wpointer-arith -Wcast-qual -fpermissive
CFLAGS_NEWOSSL= -W -Wall -Wno-variadic-macros -ansi \
						-pedantic -g -Wshadow -Wpointer-arith -Wcast-qual -fpermissive \
						-I${OPENSSLDIR}/include -L${OPENSSLDIR}/include
LIBS_OLDOSSL = -lcrypto -lssl
LIBS_NEWOSSL = -L${OPENSSLDIR}/lib -lcrypto -lssl
OPENSSLDIR = /opt/openssl/1.0.2n


TARGETS=talker listener
KEYS=*.key *.csr *.pem *.srl *.crt homekeys loopbackkeys workkeys
DOCS= README GENERATING_KEYS
FILES=core

all: $(TARGETS)
udp: talker listener


talker: talker.o common.o cookie_vault_o.o
	$(CC) $(CFLAGS_OLDOSSL) $^ $(LIBS_OLDOSSL) -o $@
listener: listener.o common.o cookie_vault_o.o
	$(CC) $(CFLAGS_OLDOSSL) $^ $(LIBS_OLDOSSL) -o $@
talker.o: talker.cpp common.h cookie_vault.h
	$(CC) $(CFLAGS_OLDOSSL) -c $< $(LIBS_OLDOSSL) -o $@
listener.o: listener.cpp common.h cookie_vault.h
	$(CC) $(CFLAGS_OLDOSSL) -c $< $(LIBS_OLDOSSL) -o $@


common.o: common.cpp common.h cookie_vault.h
	$(CC) $(CFLAGS_OLDOSSL) -c $< $(LIBS_OLDOSSL) -o $@
common.o: common.cpp common.h cookie_vault.h
	$(CC) $(CFLAGS_NEWOSSL) -c $< $(LIBS_NEWOSSL) -o $@

cookie_vault_o.o: cookie_vault.cpp cookie_vault.h
	$(CC) $(CFLAGS_OLDOSSL) -c $< $(LIBS_OLDOSSL) -o $@
cookie_vault_n.o: cookie_vault.cpp cookie_vault.h
	$(CC) $(CFLAGS_NEWOSSL) -c $< $(LIBS_NEWOSSL) -o $@


scrubrasppi:
	rm -rf *.BAK *.bak *.o *.gch *.cpp *.h $(TARGETS) $(FILES) $(KEYS) $(DOCS)
cleanfiles:
	rm -rf *.BAK *.bak *.o *.gch $(FILES)
clean:
	rm -rf *.BAK *.bak *.o *.gch $(TARGETS) $(FILES)
