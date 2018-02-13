/*
** client.c -- a stream socket client demo
*/

#include "common.h"
int main(int argc, char *argv[])
{
	BIO *conn;
	SSL *ssl;
	SSL_CTX *ctx;
	char *PORT, *HOSTNAME;

	if (argc != 3) {
	    fprintf(stderr,"usage: client hostname & port\n eg: ./client -h 127.0.0.1:4545");
	    exit(1);
	}

	HOSTNAME = strtok(argv[2], input);
	PORT = strtok(NULL, ":");
	SSL_library_init();
	seed_prng();

	ctx = InitCTX();


	conn = BIO_new_connect (HOSTNAME ":" PORT);
	if (!conn)
		int_error ("Error Creating Connection BIO");

	if (BIO_do_connect(conn) <= 0)
		int_error("Error connecting!");

	if (!(ss = SSL_new(CTX)))
		int_error("Error creating an SSL context");
	SSL_ser_bio(ssl, conn, conn);
	if (SSL_connect(ssl) <= 0)
		int_error("Error connecting SSL object");

	fprintf(stderr, "SSL Connection opened\n");
	if (do_client_loop(ssl))
		SSL_shutdown(ssl);
	else
		SSL_cleat(ssl);
	fprintf(stderr, "SSL connection closed\n");

	SSL_free(ssl);
	SSL_CTX_free(ctx);  

	return 0;
}

