#include <cerrno>
#include <cstring>
#include <cstdarg>
#include <cstdio>
#include <netdb.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <unistd.h>

#include <pthread.h>

#include <list>

#include "common.h"
#include "SERVER.h"
#include "Client.h"



int define_socket_TCP(int port){

    struct sockaddr_in sin;
    int s;

    s = socket(AF_INET, SOCK_STREAM, 0);

    if (s<0)
        errexit("Error Creating Socket: %s\n", strerror(errno));

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_port = htons(port);

    if (bind(s, (struct sockaddr*)&sin, sizeof(sin)) < 0)
        errexit("Bind Error: %s\n", strerror(errno));

    if (listen(s,5) < 0)
        errexit("Error Listening: %s\n", strerror(errno));
  
    return s;
}


void* run_client_connection(void *c){

    Client *connection = (Client *)c;
    connection->WaitForRequests();
  
    return NULL;
}


SERVER::SERVER(int port){
    
    this->port = port;
}


void SERVER::run(){

    struct sockaddr_in fsin;
    int ssock;
    socklen_t alen = sizeof(fsin);

    msock = define_socket_TCP(port);
    
    while (1){

        pthread_t thread;
        ssock = accept(msock, (struct sockaddr *)&fsin, &alen);
  
        if(ssock < 0)
            errexit("Error Accepting: %s\n", strerror(errno));


        Client *connection = new Client(ssock,fsin.sin_addr.s_addr);

        
        pthread_create(&thread, NULL, run_client_connection, (void*)connection);
    }
}


void SERVER::stop(){

    close(msock);
    shutdown(msock, SHUT_RDWR);
}