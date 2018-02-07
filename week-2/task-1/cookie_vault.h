
#ifndef COOKIE_VAULT_H
#define COOKIE_VAULT_H

#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CK_SECRET_MAX 20
#define CK_SECRET_LENGTH 16

/*
Vault that contains the secrets
*/
static unsigned char ck_secrets_vault[CK_SECRET_MAX][CK_SECRET_LENGTH];

/*
Picks a random secret off the vault
*/
unsigned char *ck_secrets_random( void );

/*
Returns the amount of secrets in the vault
*/
unsigned int ck_secrets_count( void );

/*
Creates and stores an amount of secrets
into the vault
*/
int ck_secrets_generate( unsigned int amount );

/*
Tests whether cookie matches on of the secrets
in the vault
*/
int ck_secrets_exist( unsigned char* peer, unsigned int plen,
        unsigned char *cookie, unsigned int clen );

#ifdef __cplusplus
}
#endif

#endif /* COOKIE_VAULT_H */