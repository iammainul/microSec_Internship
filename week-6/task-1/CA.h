#ifndef CA_H
#define CA_H

#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/sha.h>



typedef unsigned char byte;
const char hn[] = "SHA256";
#define BUFF 100
#define ECCTYPE    "prime256v1"


int sign_it(const byte* msg, size_t mlen, byte** sig, size_t* slen, EVP_PKEY* pkey)
{
    /* Returned to caller */
    int result = -1;
    
    if(!msg || !mlen || !sig || !pkey) {
        assert(0);
        return -1;
    }
    
    if(*sig)
        OPENSSL_free(*sig);
    
    *sig = NULL;
    *slen = 0;
    
    EVP_MD_CTX* ctx = NULL;
    
    do
    {
        ctx = EVP_MD_CTX_create();
        assert(ctx != NULL);
        if(ctx == NULL) {
            printf("EVP_MD_CTX_create failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        const EVP_MD* md = EVP_get_digestbyname(hn);
        assert(md != NULL);
        if(md == NULL) {
            printf("EVP_get_digestbyname failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        int rc = EVP_DigestInit_ex(ctx, md, NULL);
        assert(rc == 1);
        if(rc != 1) {
            printf("EVP_DigestInit_ex failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        rc = EVP_DigestSignInit(ctx, NULL, md, NULL, pkey);
        assert(rc == 1);
        if(rc != 1) {
            printf("EVP_DigestSignInit failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        rc = EVP_DigestSignUpdate(ctx, msg, mlen);
        assert(rc == 1);
        if(rc != 1) {
            printf("EVP_DigestSignUpdate failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        size_t req = 0;
        rc = EVP_DigestSignFinal(ctx, NULL, &req);
        assert(rc == 1);
        if(rc != 1) {
            printf("EVP_DigestSignFinal failed (1), error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        assert(req > 0);
        if(!(req > 0)) {
            printf("EVP_DigestSignFinal failed (2), error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        *sig = OPENSSL_malloc(req);
        assert(*sig != NULL);
        if(*sig == NULL) {
            printf("OPENSSL_malloc failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        *slen = req;
        rc = EVP_DigestSignFinal(ctx, *sig, slen);
        assert(rc == 1);
        if(rc != 1) {
            printf("EVP_DigestSignFinal failed (3), return code %d, error 0x%lx\n", rc, ERR_get_error());
            break; /* failed */
        }
        
        assert(req == *slen);
        if(rc != 1) {
            printf("EVP_DigestSignFinal failed, mismatched signature sizes %ld, %ld", req, *slen);
            break; /* failed */
        }
        
        result = 0;
        
    } while(0);
    
    if(ctx) {
        EVP_MD_CTX_destroy(ctx);
        ctx = NULL;
    }
    
    return !!result;
}

int verify_it(const byte* msg, size_t mlen, const byte* sig, size_t slen, EVP_PKEY* pkey)
{
    /* Returned to caller */
    int result = -1;
    
    if(!msg || !mlen || !sig || !slen || !pkey) {
        assert(0);
        return -1;
    }
    
    EVP_MD_CTX* ctx = NULL;
    
    do
    {
        ctx = EVP_MD_CTX_create();
        assert(ctx != NULL);
        if(ctx == NULL) {
            printf("EVP_MD_CTX_create failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        const EVP_MD* md = EVP_get_digestbyname(hn);
        assert(md != NULL);
        if(md == NULL) {
            printf("EVP_get_digestbyname failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        int rc = EVP_DigestInit_ex(ctx, md, NULL);
        assert(rc == 1);
        if(rc != 1) {
            printf("EVP_DigestInit_ex failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        rc = EVP_DigestVerifyInit(ctx, NULL, md, NULL, pkey);
        assert(rc == 1);
        if(rc != 1) {
            printf("EVP_DigestVerifyInit failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        rc = EVP_DigestVerifyUpdate(ctx, msg, mlen);
        assert(rc == 1);
        if(rc != 1) {
            printf("EVP_DigestVerifyUpdate failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        /* Clear any errors for the call below */
        ERR_clear_error();
        
        rc = EVP_DigestVerifyFinal(ctx, sig, slen);
        assert(rc == 1);
        if(rc != 1) {
            printf("EVP_DigestVerifyFinal failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        result = 0;
        
    } while(0);
    
    if(ctx) {
        EVP_MD_CTX_destroy(ctx);
        ctx = NULL;
    }
    
    return !!result;

}



#endif