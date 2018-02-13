/*
** listener.c -- a datagram sockets "server" demo
*/
#include "common.h"

#ifndef OPENSSL_NO_ENGINE
# include <openssl/engine.h>
#endif

#define MAXBUFLEN 100
using namespace std;


int CreateUDPServerSocket(sockaddr_in addr)
{
  int fd;
  // Create a socket.
  fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (fd == -1)
  {
    perror("Could not create socket.");
    return -1;
  }

  int optval = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval)) == -1)
    ErrorHandler("Error setting socket options");

  // Bind to any of the server’s addresses.
  if (bind(fd, (struct sockaddr*) &addr, sizeof addr) == -1)
  {
    perror("Could not bind socket.");
    close(fd);
    return -1;
  }
  return fd;
}

/*Connect to device*/
/**
* Opens a socket for the server to listen for connections on.
*
* @param port
Port to bind socket to.
* @param nQueued Maximum number of queued requests to allow.
*
* @return Socket to wait for new connections on.
*/

int CreateTCPServerSocket(sockaddr_in addr)
{
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd == -1)
  {
    perror("Could not create socket.");
    return -1;
  }
  int optval = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &optval,sizeof(optval)) == -1)
    ErrorHandler("Error setting socket options");

  if (bind(fd, (struct sockaddr*) &addr, sizeof addr) == -1){
    perror("Could not bind socket.");
    close(fd);
    return -1;
  }

  // Listen for request and allow up to nQueued outstanding.
  if (listen(fd, 0) == -1){
    perror("listen() failed.");
    close(fd);
    return -1;
  }
  return fd;
}


// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int main(int argc, char *argv[])
{
	int initServer_return;
	//#if OPENSSL_VERSION_NUMBER <= 0x1000115fL
	const SSL_METHOD *ssl_method = DTLSv1_server_method();

	char *PORT = argv[2];
  char *rbuff;

	DtlsBegin();

	printf("Generated %d cookie-secrets\n", ck_secrets_generate(CK_SECRET_MAX));
  /*Create socket, bind and wait for Alice*/
  	printf("Create Socket\n");
  	struct sockaddr_in serv_addr;
  	if (argc == 3){  
  		serv_addr = BuildServerAddressForServer(atoi(PORT));
  	}
    else{  
    	serv_addr = BuildServerAddressForServer(atoi(PORT));
    }
  	int sock = CreateUDPServerSocket(serv_addr);

  	DTLSParams server;

  	// Initialize the DTLS context from the keystore and then create the server
    // SSL state.
    
    initServer_return = DtlsInitServerContextFromKeystore(&server, B_CERT,
      B_PRIVATEKEY, CA_SELFSIGNEDCERTIFICATE, ssl_method);
    if (initServer_return < 0) {
        exit(EXIT_FAILURE);
    }


    if (DtlsInitServer(&server, sock) < 0){
    	exit(EXIT_FAILURE);
    }

        struct sockaddr_in cltaddr_in;
        bzero(&cltaddr_in, sizeof(cltaddr_in));

	// loop through all the results and bind to the first we can
	
	int i = DTLSv1_listen(server.ssl, (struct sockaddr *)&cltaddr_in);
    while (i==0){
    	i = DTLSv1_listen(server.ssl, (struct sockaddr *)&cltaddr_in);
    }

    if (i < 0){ 
    	SSLErrorHandler("Fatal error\n");
    }

    // Handle an incoming UDP (connection)

    /* Set new fd and set BIO to connected */
    BIO *cbio = SSL_get_rbio(server.ssl);
    int client_sock = -1;
    if (cbio){
    	BIO_get_fd(cbio, &client_sock);
    }
    if (!cbio){ 
    	SSLErrorHandler("ERROR - unable to connect\n");
    }


    // Attempt to complete the DTLS handshake
    // If successful, the DTLS link state is initialized internally
    printf("waiting for SSL_accept\n");
    int acc_r = SSL_accept(server.ssl);
    if (acc_r <= 0){
    	SSLReadWriteErrorHandler(server.ssl, acc_r);
    	perror("SSL connect error, handshake failed");
    }
    printf("SSL_accept complete\n");
    /* Handle connections*/
    int accepting = 1;
    while(accepting){
      printf("Trying to receive message from client\n");
      while(){

        rbuff = ReceiveMessageFromPeer(server.ssl);
        SendPeerAMessage(rbuff, server.ssl);
        sleep(5);
        

      }
      accepting = 0;

    } //end while(accepting)
        close(client_sock);
  /*  }*//*end while (true)*/
//DtlsShutdown(&server);

close(sock);

EVP_cleanup();
/* if you omit the next, a small leak may be left when you make use of the BIO (low level API) for e.g. base64 transformations */
CRYPTO_cleanup_all_ex_data();
//CRYPTO_mem_leaks(bio_err);
BIO_free(bio_err);
ERR_free_strings();
return 0;
}