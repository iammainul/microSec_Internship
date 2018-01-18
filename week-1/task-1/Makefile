CC=gcc

CFLAGS=-c -Wall

all: programs

programs: server.o client.o

server.o: server.c
			$(CC) $(CFLAGS) server.c -o server

client.o: client.c
			$(CC) $(CFLAGS) client.c -o client


clean:
			rm -rf *o client server