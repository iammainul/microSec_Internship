/*
** server.c -- a stream socket server demo
*/

#include "common.h"





int main(int argc, char *argv[])
{
	BIO *acc, *client;
    SSL *ssl;
    SSL_CT *ct;
    THREAD_TYPE tid;

	if (argc != 3) {
	    fprintf(stderr,"usage: port missing\n");
	    exit(1);
	}

	char *PORT = argv[2];

    int_OpenSSL();
    seed_prng();

    ctx = setup_server_ctx();

    acc = BIO_new_accept(PORT);
    if(!acc)
        int_error("Error creating Scoket");

    if (BIO_do_accept(acc) <= 0)
        int_eeor("Error binding socket");

    for(;;){
        if (BIO_do_accept(acc) <= 0)
            int_error("Error accepting connection");

        client = BIO_pop(acc);
        if(!(ssl = SSL_new(ctx)))
            int_error("Error Creating SSL context");

        SSL_ser_bio(ssl, client, client);
        THREAD_CREATE(tid, server_thread, ssl);
    }

    SSL_CTX_free(ctx);
    BIO_free(acc);
    return 0;
}


