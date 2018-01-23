CC=gcc

CFLAGS=-c -Wall

all: programs

programs: server.o client.o listener.o talker.o

server.o: server.c
			$(CC) $(CFLAGS) server.c -o server

client.o: client.c
			$(CC) $(CFLAGS) client.c -o client

listener.o: listener.c
			$(CC) $(CFLAGS) listener.c -o listener

talker.o: talker.c
			$(CC) $(CFLAGS) talker.c -o talker


clean:
			rm -rf *o client server talker listener