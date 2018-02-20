CC=g++

CFLAGS=-c -Wall

SSLFLAGS=-lssl -lcrypto 

all: programs

programs: server.o client.o

server.o: certcom.cpp
			$(CC) $(CFLAGS) certcom.cpp -o certcom $(SSLFLAGS)

client.o: certclient.cpp
			$(CC) $(CFLAGS) certclient.cpp -o certclient $(SSLFLAGS)

clean:
			rm -rf *o  *pem certclient certcom