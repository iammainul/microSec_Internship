#include "cauth.h"
#include "demo.pb.h"

using namespace std;
using google::protobuf::util::TimeUtil;


int main(){

	GOOGLE_PROTOBUF_VERIFY_VERSION;

	EVP_PKEY *PUBKey   = NULL;
    EVP_PKEY **P_PUBKEY = NULL;
    EVP_PKEY *PRKEY = NULL;
    EVP_PKEY **P_PRKEY = NULL;
    unsigned int pubKLen;
    //int ret;
    //size_t sLen = 0;
    //byte* sig = NULL;
    char h[] = "SHA256";
    char ecctype[] = "SEPC256K1";
    //unsigned int ar[3];
    FILE *fp;
    //char *sig1;
    fstream fo("./csbts.der",ios::out | ios::trunc | ios::binary);







	    //Reading Keys
    fp = fopen("mypubkey.pem", "r");

    PUBKey =  PEM_read_PUBKEY(fp, P_PUBKEY, NULL, NULL);

    fclose(fp);
    
    fp = fopen("mypubkey.pem", "r");

    PUBKey =  PEM_read_PUBKEY(fp, P_PUBKEY, NULL, NULL);

    fclose(fp);

    fp = fopen("secp256k1-key.pem", "r");

    PRKEY =  PEM_read_PrivateKey(fp, P_PRKEY, NULL, NULL);

    fclose(fp);

    pubKLen = EVP_PKEY_bits(PUBKey);


    CSV::CSTBS cstbs;


    uint64_t d_id, o_id;
    d_id = (uint64_t)rand();
    cstbs.set_deviceid(d_id);
    //mcsr.set_deviceid(d_id);
    //ca.set_deviceid(d_id);
    o_id = (uint64_t)rand();
    cstbs.set_orgid(o_id);
    //mcsr.set_orgid(o_id);
    //ca.set_orgid(o_id);


    cstbs.set_curveid(ecctype);
    //mcsr.set_curveid(ecctype);
    //ca.set_curveid(ecctype);
    cstbs.set_hashid(h);
    //mcsr.set_hashid(h);
    //ca.set_hashid(h);
    cstbs.set_pubklen(pubKLen);
    //mcsr.set_pubklen(pubKLen);
    //ca.set_pubklen(pubKLen);

    cstbs.SerializeToOstream(&fo);

    fp = fopen("cstbs.der", "a");
    if(fp == NULL){
        printf("Cannot Open cstbs.der\n");
        exit(1);
    }

    fwrite(&PUBKey, sizeof(PUBKey), 1, fp);
    fclose(fp);

    if(PUBKey)
        EVP_PKEY_free(PUBKey);
    
    if(PRKEY)
        EVP_PKEY_free(PRKEY);

    return 0;
}