/*
** talker.c -- a datagram "client" demo
*/

#include "common.h"

#ifndef OPENSSL_NO_ENGINE
# include <openssl/engine.h>
#endif


using namespace std;


void CheckCertificate(SSL *ssl,char*host)
{
    X509 *peer;
    char peer_CN[256];

    if(SSL_get_verify_result(ssl)!=X509_V_OK)
      SSLErrorHandler("Certificate doesn't verify");

    /*Check the cert chain. The chain length
      is automatically checked by OpenSSL when
      we set the verify depth in the ctx */

    /*Check the common name*/
    peer=SSL_get_peer_certificate(ssl);
    X509_NAME_get_text_by_NID(X509_get_subject_name(peer),
     NID_commonName,peer_CN, 256);
    if(strcasecmp(peer_CN,host))
      ErrorHandler("Common name doesn't match host name");
}


int main(int argc, char *argv[])
{
	char *PORT, *HOSTNAME;
	char* input = ":";
	int initClient_return;
	const SSL_METHOD *ssl_method = DTLSv1_client_method();

	if (argc != 4) {
		fprintf(stderr,"usage: talker hostname message\n");
		exit(1);
	}

	HOSTNAME = strtok(argv[2], input);
	PORT = strtok(NULL, ":");

	DtlsBegin();

	DTLSParams client;
  // Initialize the DTLS context from the keystore and then create the server
    // SSL state.
    initClient_return = DtlsInitClientContextFromKeystore(&client, A_CERT, A_PRIVATEKEY,
         CA_SELFSIGNEDCERTIFICATE, ssl_method);
  if (initClient_return < 0) {
        exit(EXIT_FAILURE);
    }
    sockaddr_in server_addr = BuildServerAddressForClient(HOSTNAME, atoi(PORT));
  printf("Trying to connect to Bob via UDP socket\n");
  int client_fd = CreateUDPClientSocket(server_addr);

  printf("Trying to create new datagram socket\n");
  client.bio = BIO_new_dgram(client_fd, BIO_NOCLOSE);
  if (client.bio == NULL){
  	SSLErrorHandler("Error: creating datagram BIO from socket\n");
  }

  BIO_ctrl(client.bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &server_addr);
  printf("Set datagram BIO connection to server\n");

  client.ssl = SSL_new(client.ctx);
  SSL_set_bio(client.ssl, client.bio, client.bio);
  if (client.ssl == NULL)
  {SSLErrorHandler("Error: creating SSL instance from BIO\n");}
  //SSL_set_options(client.ssl, SSL_OP_COOKIE_EXCHANGE);
  // Attempt to connect to the server and complete the handshake.
  //SSL_set_connect_state(client.ssl);
  printf("Trying to connect to Bob via ssl\n");

  int conn_r = SSL_connect(client.ssl);
  if (conn_r != 1){
    SSLReadWriteErrorHandler(client.ssl, conn_r);
    perror("SSL connect error, handshake failed");
}

  int sending = 1;
  while(sending)
  {
    printf("Trying to send message to Bob \n");
    SendPeerAMessage((char*)"Hi Bob!", client.ssl);
    sleep(5);
    ReceiveMessageFromPeer(client.ssl);
    SendPeerAMessage((char*)"Have you got any cigarettes?", client.ssl);
    sleep(5);
    ReceiveMessageFromPeer(client.ssl);
    SendPeerAMessage((char*)"Ok no problem. Ciao!", client.ssl);
    sleep(5);
    ReceiveMessageFromPeer(client.ssl);
    sending = 0;
  }/*end while*/

  /*Close connection to CA*/
  close(client_fd);
  //BIO_free(sbio);
  //SSL_free(ssl);
  //SSL_CTX_free(ssl_context);
  //DtlsShutdown(&client);

  EVP_cleanup();
  /* if you omit the next, a small leak may be left when you make use of the BIO (low level API) for e.g. base64 transformations */
  CRYPTO_cleanup_all_ex_data();
  //CRYPTO_mem_leaks(bio_err);
  //BIO_free(bio_err);
  ERR_free_strings();
  return 0;
}
