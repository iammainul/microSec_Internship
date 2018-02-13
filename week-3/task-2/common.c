#include "common.h"


void ShowCerts(SSL* ssl)
{   X509 *cert;
    char *line;
 
    cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */
    if ( cert != NULL ){
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
        X509_free(cert);
    }
    else
        printf("No certificates.\n");
}

void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
    /* set the local certificate from CertFile */
    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 ){
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 ){
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* verify private key */
    if ( !SSL_CTX_check_private_key(ctx) ){
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}

SSL_CTX* InitServerCTX(void)
{
	SSL_CTX *ctx;
    OpenSSL_add_all_algorithms();  /* load & register all cryptos, etc. */
    SSL_load_error_strings();   /* load all error messages */
    ctx = SSL_CTX_new(TLSv1_server_method());   /* create new context from method */
        if (SSL_CTX_use_certificate_chain_file(ctx, CERTFILE) != 1)
		int_error("Error loading certificate from file");
	if (SSL_CTX_use_PrivateKey_file(ctx, CERTFILE, SSL_FILETYPE_PEM) != 1)
		int_error("Error loading private key from file");

    return ctx;

}
 
SSL_CTX* InitCTX(void)
{
	SSL_CTX *ctx;
    OpenSSL_add_all_algorithms();  /* load & register all cryptos, etc. */
    SSL_load_error_strings();   /* load all error messages */
    ctx = SSL_CTX_new(TLSv1_client_method());   /* create new context from method */
    if (SSL_CTX_use_certificate_chain_file(ctx, CERTFILE) != 1)
		int_error("Error loading certificate from file");
	if (SSL_CTX_use_PrivateKey_file(ctx, CERTFILE, SSL_FILETYPE_PEM) != 1)
		int_error("Error loading private key from file");

    return ctx;
}


void Servlet(SSL* ssl) /* Serve the connection -- threadable */
{   char buf[1024];
    char reply[1024];
    int sd, bytes;
    const char* HTMLecho="%s";
 
    if ( SSL_accept(ssl) == FAIL )     /* do SSL-protocol accept */
        ERR_print_errors_fp(stderr);
    else{
        ShowCerts(ssl);        /* get any certificates */
   while(1){
        bytes = SSL_read(ssl, buf, sizeof(buf)); /* get request */
        if ( bytes > 0 ){
            buf[bytes] = 0;
            printf("Client msg:%s", buf);
            strcpy(reply,buf);   /* construct reply */
            SSL_write(ssl, reply, strlen(reply)); /* send reply */
        }
        else
            ERR_print_errors_fp(stderr);
      }
    }
    sd = SSL_get_fd(ssl);       /* get socket connection */
    SSL_free(ssl);         /* release SSL state */
    close(sd);          /* close connection */
}

int do_client_loop(SSL *ssl)
{
	int err, nwritten;
	char buf[80];
	for (;;){
		if (!fgets(buf, sizeof(buf), stdin))
			break;
		for (nwritten = 0; nwritten < sizeof(buf); nwritten +=err){
			err = SSL_write(ssl, buf + nwritten, strlen(buf) -nwritten);
			if (err <= 0)
				return 0;
		}
	}
	return 1;
}

int do_server_loop(SSL *ssl)
{
	int err, nread;
	char buf[80];
	do{
		for (nread = 0; nread < sizeof(buf); nread += err){
			err = SSL_read(ssl, buf + nread, sizeof(buf) -nread);
			if (err <= 0)
				break;
		}
		fwrite(buf, 1, nread, stdout);
	}while (err > 0);
	return (SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN) ? 1 : 0;
}

void THREAD_CC server_thread (void *arg)
{
	SSL *ssl = (SSL *)arg;

	if (SSL_accept(ssl) <=0)
		int_error("Error accepting connection");
	fprintf(stderr, "SSL Connection Opened\n");
	if (do_server_leep(ssl))
		SSL_shutdown(ssl);
	else
		SSL_clear(ssl);

	fprintf(stderr, "SSL connection closed\n");

	SSL_free(ssl);

	ERR_remove_state(0);
}