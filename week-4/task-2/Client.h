#if !defined Client_H
#define Client_H

#include <pthread.h>

#include <cstdio>
#include <cstdint>


const int MAX_BUFF = 512;


class Client{

    private:  

        bool ok;        
        
        FILE *fd;       
      
        char command[MAX_BUFF];     
        char arg[MAX_BUFF];          
        char arg2[MAX_BUFF];         
        
        int data_socket;            
        int control_socket;         
        
        bool parar;

        unsigned long server_address;   
        bool passive;                   

    public:

        Client(int s, unsigned long ip);
        ~Client();
        
        void WaitForRequests();
        void stop();
};

#endif