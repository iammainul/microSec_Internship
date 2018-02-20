#include <iostream>
#include <signal.h>

#include "SERVER.h"


SERVER *server;

extern "C" void sighandler(int signal, siginfo_t *info, void *ptr){
  
    std::cout << "Error" << std::endl;  
    server->stop();
    exit(-1);
}


void exit_handler(){
    
    server->stop();
}


int main(int argc, char **argv){

    struct sigaction action;
    
    action.sa_sigaction = sighandler;
    action.sa_flags = SA_SIGINFO;
    sigaction(SIGINT, &action , NULL);
    
    server = new SERVER(2121);
    atexit(exit_handler);
    
    server->run();
}