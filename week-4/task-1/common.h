#ifndef H_COMMON
#define H_COMMON

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netdb.h>
#include <syslog.h>
#include <assert.h>
#include <err.h>
#include <arpa/inet.h>

#include <iostream>
#include <fstream>
#include <vector>
#include <string>


#include <openssl/opensslv.h>
#include <openssl/engine.h>
#include <openssl/bio.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/crypto.h>
#include <sys/types.h>

#include "cookie_vault.h"


#define CA_PRIVATEKEY "certauth.key"
#define CA_PUBLICKEY "certauth-pub.key"
#define CA_SELFSIGNEDCERTIFICATE "certauth.crt"
#define CA_LIST "ca_list.pem"
#define A_PUBLICKEY "alice-pub.key"
#define A_PRIVATEKEY "alice.key"
#define A_CERT "alice.crt"
#define B_PUBLICKEY "bob-pub.key"
#define B_PRIVATEKEY "bob.key"
#define B_CERT "bob.crt"
#define PORTNUMBER "65534"
#define HOST "127.0.0.1"
#define NUMQUEUED 10
#define BUFLENGTH 1024
#define CIPHERLIST "ECDHE-ECDSA-AES128-SHA256"
#define FULLCIPHERLIST "ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-SHA384"
#define MOSTCIPHERS "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH"



static BIO *bio_err=0;

int ErrorHandler(const char *msg);
int SSLErrorHandler(const char * string);
void SSLReadWriteErrorHandler(SSL* ssl, int readwritten);
void InitialiseOpenSSL(void);

typedef struct {
    SSL_CTX *ctx;
    SSL *ssl;
    BIO *bio;
} DTLSParams;

void DtlsBegin(void);
int DtlsInitServerContextFromKeystore(DTLSParams* params, const char* cert_file,
    const char* privkey_file, const char* cacert_file, const SSL_METHOD *meth);
int DtlsInitClientContextFromKeystore(DTLSParams* params, const char* cert_file,
        const char* privkey_file, const char* cacert_file, const SSL_METHOD *meth);
int DtlsInitServer(DTLSParams* params, int sockfd);
int DtlsInitClient(DTLSParams* params, const char *address);
void DtlsShutdown(DTLSParams* params);
void DtlsEnd(void);


SSL_CTX *CreateSSLContext(void);
SSL_CTX *ConfigureOpenSSLContext(SSL_CTX *ctx,
        const char* cert_file, const char* privkey_file, const char* cacert_file);
SSL_CTX * LoadECParamsInContext(SSL_CTX *ctx);

sockaddr_in BuildServerAddressForClient(const char* host, const int port);
sockaddr_in BuildServerAddressForServer(const int port);
int CreateUDPClientSocket(sockaddr_in server_addr);
int CreateTCPClientSocket(sockaddr_in server_addr);

int GetSizeOfFile(const char* filepath);
void SendPeerSizeOfFile(const int filesize, SSL* ssl);
void SendPeerFileData(const char* filepath, const int filesize, SSL* ssl);
void SendPeerAFile(const char* filepath, SSL* ssl);
int ReceiveSizeOfFileFromPeer (SSL* ssl);
void ReceiveFileDataFromPeer(const char* filepath,
        const int filesize, SSL* ssl);
void ReceiveAFileFromPeer(const char* filepath, SSL* ssl);

void SendPeerLengthOfMessage(char* msg, SSL* ssl);
void SendPeerMessageData(char * msg, SSL* ssl);
void SendPeerAMessage(char * msg, SSL* ssl);
int ReceiveLengthOfMessageFromPeer(SSL* ssl);
std::string ReceiveMessageDataFromPeer(int msg_length, SSL* ssl);
void ReceiveMessageFromPeer(SSL* ssl);


void DestroySSLContext(SSL_CTX *ctx);
void CleanupOpenSSL(void);


#endif
