#include "CA.h"

typedef struct CSRToBeSigned{
    unsigned int deviceID;
    unsigned int orgID;
    char *curveID;
    char *hashID;
    unsigned int pubKLen;
    EVP_PKEY *pubK ;
} CSR;

typedef struct MiniCertSR{
    unsigned int deviceID;
    unsigned int orgID;
    char *curveID;
    char *hashID;
    unsigned int pubKLen;
    EVP_PKEY *pubK ;
    size_t sLen;
    byte *sig ;
} MCSR;

typedef struct CA{
    unsigned int deviceID;
    unsigned int orgID;
    char *curveID;
    char *hashID;
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
    FILE *fp, *fp1;
    memset(&csr, 0, sizeof(csr));
    memset(&mcsr, 0 , sizeof(mcsr));
    memset(&ca, 0 , sizeof(ca));
    EVP_PKEY *PUBKey   = NULL;
    EVP_PKEY **P_PUBKEY = NULL;
    EVP_PKEY *PRKEY = NULL;
    EVP_PKEY **P_PRKEY = NULL;
    unsigned int pubKLen;
    int ret;
    size_t sLen = 0;
    byte* sig = NULL;
    char hn[] = "SHA256";
    char ecctype[] = "SEPC256K1";
    unsigned int ar[3];



    //Reading Keys
    fp = fopen("mypubkey.pem", "r");

    PUBKey =  PEM_read_PUBKEY(fp, P_PUBKEY, NULL, NULL);

    fclose(fp);
    
    fp = fopen("mypubkey.pem", "r");

    PUBKey =  PEM_read_PUBKEY(fp, P_PUBKEY, NULL, NULL);

    fclose(fp);

    fp1 = fopen("secp256k1-key.pem", "r");

    PRKEY =  PEM_read_PrivateKey(fp, P_PRKEY, NULL, NULL);

    fclose(fp1);

    pubKLen = EVP_PKEY_bits(PUBKey);




    
    //Filling up the CSRToBeSigned Structure
    csr.deviceID = (uint32_t)rand();
    csr.orgID = (uint32_t)rand();
    csr.curveID = ecctype;
    csr.hashID = hn;
    csr.pubKLen = pubKLen;
    csr.pubK = PUBKey;

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

    
    ar[0] = mcsr.deviceID;
    ar[1] = mcsr.orgID;
    ar[2] = mcsr.pubKLen;
    
    unsigned char s[3] = {3};
    memcpy(s, (char*)&ar, sizeof(ar));

    unsigned char *m = (unsigned char*)mcsr.curveID;
    unsigned char *n = (unsigned char*)mcsr.hashID;

    byte *buff = NULL;
    stcat(m, n);
    stcat(s, m);

    buff = s;



    //creating the signature
    ret = sign_it(buff, sizeof(buff), &sig, &sLen, PRKEY);

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
    ret = verify_it(buff, sizeof(buff), sig, sLen, PUBKey);

    if(ret == 0) {
        printf("Verified signature\n");
    } else {
        printf("Failed to verify signature, return code %d\n", ret);
    }
    
    time_t validF;
    time_t validFor;
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
    if(PUBKey)
        EVP_PKEY_free(PUBKey);
    
    if(PRKEY)
        EVP_PKEY_free(PRKEY);
    
    return 0;
}
