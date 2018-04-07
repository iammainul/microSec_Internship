#include "demo.h"
#include "demo.pb.h"

using namespace std;

int main(){

	EVP_PKEY *PUBKey   = NULL;
    EVP_PKEY **P_PUBKEY = NULL;
    EVP_PKEY *PRKEY = NULL;
    EVP_PKEY **P_PRKEY = NULL;
    unsigned int pubKLen;

    int ret;
    size_t sLen = 0;
    byte* sig = NULL;
    char h[] = "SHA256";
    char ecctype[] = "SEPC256K1";
    unsigned int ar[3];
    FILE *fp;
   	const char *sig1;
    fstream fo("./csbts.der",ios::out | ios::trunc | ios::binary);


    CSR::CSTBS cstbs;

	    //Reading Keys
    
    fp = fopen("mypubkey.pem", "r");

    PUBKey =  PEM_read_PUBKEY(fp, P_PUBKEY, NULL, NULL);

    fclose(fp);

    fp = fopen("secp256k1-key.pem", "r");

    PRKEY =  PEM_read_PrivateKey(fp, P_PRKEY, NULL, NULL);

    fclose(fp);

    pubKLen = EVP_PKEY_bits(PUBKey);

    printf("%d = pubKLen \n", pubKLen );

    uint64_t d_id, o_id;
    d_id = (uint64_t)rand();
    printf("%ld deviceid\n", d_id);
    cstbs.set_deviceid(d_id);
    o_id = (uint64_t)rand();
    printf("%ld orgid \n", o_id);
    cstbs.set_orgid(o_id);

    cstbs.set_curveid(ecctype);
    cstbs.set_hashid(h);
    cstbs.set_pubklen(pubKLen);

    cstbs.SerializeToOstream(&fo);

    fo.close();

    fp = fopen("cstbs.der", "w+");
    if(fp == NULL){
    	printf("Cannot Open cstbs.der\n");
    	exit(1);
    }

    fwrite(&PUBKey, 1, sizeof(PUBKey), fp);
    fclose(fp);


    return 0;
}