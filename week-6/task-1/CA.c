
#include "CA.h"



typedef struct CSRToBeSigned{
    unsigned int deviceID;
    unsigned int orgID;
    unsigned char curveID;
    unsigned char *hashID;
    unsigned int pubKLen;
    EVP_PKEY *pubK ;
} CSR;

typedef struct MiniCertSR{
    unsigned int deviceID;
    unsigned int orgID;
    unsigned char curveID;
    unsigned char *hashID;
    unsigned int pubKLen;
    EVP_PKEY *pubK ;
    size_t sLen;
    byte *sig ;
} MCSR;

typedef struct CA{
    unsigned int deviceID;
    unsigned int orgID;
    unsigned char curveID;
    unsigned char *hashID;
    unsigned int pubKLen;
    EVP_PKEY *pubK ;
    unsigned int certSNo;
    unsigned int CAID;
    unsigned int validF;
    unsigned int validFor;
    
} CA;

int WriteCSRToFile (struct CSRToBeSigned csr)
{
    FILE *fp;
    fp = fopen("csr.der", "wb");

    fwrite(&csr, sizeof(csr), 1, fp);

    return 1;
}

int WriteMCSRToFile (struct MiniCertSR mcsr)
{
    FILE *fp;
    fp = fopen("mcsr.der", "wb");

    fwrite(&mcsr, sizeof(mcsr), 1, fp);

    return 1;
}

int WriteCAToFile(struct CA ca)
{
    FILE *fp;
    fp = fopen("ca.der", "wb");

    fwrite(&ca, sizeof(ca), 1, fp);

    return 1;
}


int main(){
    CSR csr;
    MCSR mcsr;
    CA ca;
    memset(&csr, 0, sizeof(csr));
    memset(&mcsr, 0 , sizeof(mcsr));
    memset(&ca, 0 , sizeof(ca));
    EVP_PKEY *PKey   = NULL;
    EVP_PKEY *pubK = NULL;
    int eccgrp;
    unsigned int pubKLen;
    unsigned char csrbuff[BUFF] = {};
    int ret;
    size_t sLen = 0;
    byte *sig = NULL;
    BIO  *outbio = NULL;


    //Generating Keys
    eccgrp = OBJ_txt2nid(ECCTYPE);
    
    pubK = EC_KEY_new_by_curve_name(eccgrp);
    if (! (EC_KEY_generate_key(pubK)))
        BIO_printf(outbio, "Error generating the ECC key.");
    
    pubKLen = EVP_PKEY_bits(pubK);

    PKey=EVP_PKEY_new();
    if (!EVP_PKEY_assign_EC_KEY(PKey,pubK))
        BIO_printf(outbio, "Error assigning ECC key to EVP_PKEY structure.");

    
    //Filling up the CSRToBeSigned Structure
    csr.deviceID = (uint32_t)rand();
    csr.orgID = (uint32_t)rand();
    csr.curveID = ECCTYPE;
    csr.hashID = hn;
    csr.pubKLen = pubKLen;
    csr.pubK = pubK;

    ret = WriteCSRToFile(csr);

    if(ret != 1){
        printf("Error Writting CSR File");
        exit (1);
    }


    mcsr.deviceID = csr.deviceID;
    mcsr.orgID = csr.orgID;
    mcsr.curveID = csr.curveID;
    mcsr.hashID = csr.hashID;
    mcsr.pubK = csr.pubK;
    mcsr.pubKLen = csr.pubKLen;

    const byte *buff;
    memset(buff, '0', sizeof(buff));

    strcat(mcsr.hashID, mcsr.pubKLen);
    strcat(mcsr.curveID, mcsr.hashID);
    strcat(mcsr.orgID, mcsr.curveID);
    strcat(mcsr.deviceID, mcsr.orgID);
    strcat (buff, mcsr.deviceID);

    //creating the signature
    ret = sign_it(buff, sizeof(buff), &sig, &sLen, PKey);

    assert(ret == 0);
    if(ret == 0){
        printf ("Signature Creation Success");
    }
    else{
        printf("Fialed to create the signature\n");
        exit (1);
    }

    mcsr.deviceID = csr.deviceID;
    mcsr.orgID = csr.orgID;
    mcsr.curveID = csr.curveID;
    mcsr.hashID = csr.hashID;
    mcsr.pubK = csr.pubK;
    mcsr.pubKLen = csr.pubKLen;
    mcsr.sig = sig;
    mcsr.sLen = sLen;

    ret = WriteMCSRToFile(mcsr);
    if(ret != 1){
        printf("Error Writting MCSR File");
        exit (1);
    }

    //verifying the signature
    ret = verify_it(buff, sizeof(buff), sig, sLen, pubK);

    if(ret == 0) {
        printf("Verified signature\n");
    } else {
        printf("Failed to verify signature, return code %d\n", ret);
    }
    
    time_t validF, validFor;
    validFor = (validF + 31536000);
    
    ca.certSNo = (uint32_t)rand();
    ca.CAID = (uint32_t)rand();
    ca.deviceID = mcsr.deviceID;
    ca.orgID = mcsr.orgID;
    ca.curveID = mcsr.curveID;
    ca.hashID = mcsr.hashID;
    ca.pubK = mcsr.pubK;
    ca.pubKLen = mcsr.pubKLen;
    ca.validF = validF;
    ca.validFor = validFor;

    ret = WriteCAToFile(ca);
    if(ret != 1){
        printf("Error Writting CA File");
        exit (1);
    }

    if(sig)
        OPENSSL_free(sig);
    
    if(pubK)
        EVP_PKEY_free(pubK);
    
    if(PKey)
        EVP_PKEY_free(PKey);
    
    return 0;
}

