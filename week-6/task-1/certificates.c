
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/pem.h> 

const char hn[] = "SHA256";


struct CSRToBeSigned{
	unsigned int deviceID;
	unsigned int orgID;
	unsigned char curveID;
	unsigned char *hashID;
	unsigned int pubKLen;
	EC_KEY pubK;
};

struct MiniCertSR{
	unsigned int deviceID;
	unsigned int orgID;
	unsigned char curveID;
	unsigned char *hashID;
	unsigned int pubKLen;
	char pubK;
	size_t sLen = 0;
	char *sig = NULL;
};

struct CA{
	unsigned int deviceID;
	unsigned int orgID;
	unsigned char curveID;
	unsigned char hashID;
	unsigned int pubKLen;
	EC_KEY pubK;
	unsigned int certSNo;
	unsigned int CAID;
	unsigned __int64 validF;
	unsigned int validFor;
	
};


int main(){
	CSRToBeSigned csr;
	MiniCertSR mcsr;
	CA ca;
	int eccgrp;
	EVP_PKEY *PKey   = NULL;
	EVP_MD CTX *mdctx = NULL;
	int ret;
	FILE *fp;

	printf("Enter the deviceID\n");
	scanf("%d". &csr.deviceID);
	
	printf("Enter the orgID\n");
	scanf("%d". &csr.orgID);
	
	printf("Enter the CurveID\n");
	scanf("%s", csr.curveID);
	
	csr.hashID = hn;

	eccgrp = OBJ_txt2nid(curveID);
    csr.pubK = EC_KEY_new_by_curve_name(eccgrp);
    if (! (EC_KEY_generate_key(csr.pubk)))
    	BIO_printf(outbio, "Error generating the ECC key.");
    
    csr.pubKLen = EC_size(csr.pubK);

    PKey=EVP_PKEY_new();
    if (!EVP_PKEY_assign_EC_KEY(Pkey,csr.pubK))
        BIO_printf(outbio, "Error assigning ECC key to EVP_PKEY structure.");

    if(!(mdctx = EVP_MD_CTXcreate())) goto err;
    	//Write something

    if(1 != ECP_DigestSignInit(mdctx, NULL, csr.hashID, NULL, Pkey)) goto err;
    	//
    
    if(1 != EVP_DigestSignFinal(mdctx, NULL, mcsr.sLen)) goto err;
 		/* Allocate memory for the signature based on size in slen */
 	
 	if(!(*mcsr.sig = OPENSSL_malloc(sizeof(unsigned char) * (*mcsr.sLen)))) goto err;
 		/* Obtain the signature */
 	
 	if(1 != EVP_DigestSignFinal(mdctx, *mcsr.sig, mcsr.sLen)) goto err;
    
 	ret = 1;

 	err:
 	if(ret != 1){
 		exit (1);
 	}

 	fp = fopen ("sign.der", "wb");

 	PEM_write(fp, mcsr.sig, NULL, NULL, NULL)

 	fclose (fp);



	if (1 != EVP_DigestVerifyInit(mdctx, NULL, csr.hashID; NULL, csr.pubK)) goto err;

	if(1 == EVP_DigestVerifyFinal(mdctx, mcsr.sig, mcsr.sLen){
    	printf("success");
	}
	else{
    	exit (1);
	}








	return 0;
}

