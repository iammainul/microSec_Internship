/*
** client.c -- a stream socket client demo
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <malloc.h>
#include <resolv.h>

#include "openssl/ssl.h"
#include "openssl/err.h"


#define FAIL -1

#define MAXDATASIZE 1000 // max number of bytes we can get at once 

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

SSL_CTX* InitCTX(void)
{   
    SSL_CTX *ctx;
 
    OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
    SSL_load_error_strings();   /* Bring in and register error messages */
    ctx = SSL_CTX_new(SSLv23_client_method());   /* Create new context */
    if ( ctx == NULL ){
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}
 
void ShowCerts(SSL* ssl)
{   X509 *cert;
    char *line;
 
    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    if ( cert != NULL ){
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);       /* free the malloc'ed string */
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);       /* free the malloc'ed string */
        X509_free(cert);     /* free the malloc'ed certificate copy */
    }
    else
        printf("No certificates.\n");
}

int main(int argc, char *argv[])
{
	int sockfd, numbytes;  
	char buf[MAXDATASIZE], *PORT, *HOSTNAME;
	char* input = ":";
	struct addrinfo hints, *servinfo, *p;
	int rv;
	char s[INET6_ADDRSTRLEN];
	SSL_CTX *ctx;
	SSL *ssl;
	char msg[1024];
	int bytes;

	if (argc != 3) {
	    fprintf(stderr,"usage: client hostname & port\n eg: ./client -h 127.0.0.1:4545");
	    exit(1);
	}

	HOSTNAME = strtok(argv[2], input);
	PORT = strtok(NULL, ":");
	SSL_library_init();


	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;


	if ((rv = getaddrinfo(HOSTNAME, PORT, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
	}

	// loop through all the results and connect to the first we can
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
				p->ai_protocol)) == -1) {
			perror("client: socket");
			continue;
		}

		if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			perror("client: connect");
			close(sockfd);
			continue;
		}

		break;
	}


	if (p == NULL) {
		fprintf(stderr, "client: failed to connect\n");
		return 2;
	}

	inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),
			s, sizeof s);
	printf("client: connecting to %s\n", s);
	
	

	freeaddrinfo(servinfo); // all done with this structure

	if (send(sockfd, "Hello", 13, 0) == -1)
				perror("send");

	if ((numbytes = recv(sockfd, buf, MAXDATASIZE-1, 0)) == -1) {
	    perror("recv");
	    exit(1);
	}

	ssl = SSL_new(ctx);
	SSL_set_fd(ssl, sockfd);

	if ( SSL_connect(ssl) == FAIL )   /* perform the connection */
        ERR_print_errors_fp(stderr);
    else{   
    	printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
        ShowCerts(ssl); 
        while(1){
        printf("Client:");
        fgets(msg,sizeof(msg),stdin);
               /* get any certs */
        SSL_write(ssl, msg, strlen(msg));   /* encrypt & send message */
        bytes = SSL_read(ssl, buf, sizeof(buf)-1); /* get reply & decrypt */
        buf[bytes] = 0;
        printf("SERVER:%s", buf);
		}
        SSL_free(ssl);        /* release connection state */
    }

	buf[numbytes] = '\0';

	printf("client: received '%s'\n",buf);

	close(sockfd);
	SSL_CTX_free(ctx);  

	return 0;
}

