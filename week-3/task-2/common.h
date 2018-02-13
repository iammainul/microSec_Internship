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
#include <malloc.h>
#include <pthread.h>

//ssl

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


//functions

SSL_CTX* InitCTX(void);
void ShowCerts(SSL* ssl);
void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile);
void Servlet(SSL* ssl);
SSL_CTX* InitServerCTX(void);
void Servlet(SSL* ssl);
