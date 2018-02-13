#include "cookie_vault.h"


/*
Picks a random secret off the vault
*/
unsigned char *ck_secrets_random( void )
{
    unsigned int count = ck_secrets_count();

    return ( count > 0 ) ? ck_secrets_vault[rand() % count] : NULL;
}

/*
Returns the amount of secrets in the vault
*/
unsigned int ck_secrets_count( void )
{
    return ( sizeof( ck_secrets_vault ) / sizeof( ck_secrets_vault[0] ) );
}

/*
Creates and stores an amount of secrets
into the vault
*/
int ck_secrets_generate( unsigned int amount )
{
    unsigned int i = 0;

    do {
        if( amount <= 0
            || amount > CK_SECRET_MAX
            || !RAND_bytes( ck_secrets_vault[i], CK_SECRET_LENGTH ) )
            break;
        i++;
    } while( i < amount );

    return i;
}

/*
Tests whether cookie matches on of the secrets
in the vault
*/
int ck_secrets_exist( unsigned char* peer, unsigned int plen,
            unsigned char *cookie, unsigned int clen )
{
    int i, success = 0;
    unsigned char result[EVP_MAX_MD_SIZE];
    unsigned int reslen = 0, count = ck_secrets_count();

    for( i = 0; i < ( !count ) ? 0 : count; i++ )
    {
        memset( &result, 0, sizeof( result ) );

        HMAC( EVP_sha256(), (const void*)ck_secrets_vault[i], CK_SECRET_LENGTH,
        (const unsigned char*)peer, plen, result, &reslen );

        if( clen == reslen && memcmp( result, cookie, reslen ) == 0 )
        {
            success = 1;
            break;
        }
    }

    return success;
}
