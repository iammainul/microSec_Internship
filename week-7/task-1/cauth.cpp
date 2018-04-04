#include "cauth.h"
#include "csrtbs.pb.h"

using namespace std;



int main(){

	GOOGLE_PROTOBUF_VERIFY_VERSION;

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
    FILE *fp;
    char *sig1;
    fstream fo("./csbts.der",ios::out | ios::trunc | ios::binary);
    fstream f1("./mcsr.der",ios::out | ios::trunc | ios::binary);
    fstream f2("./ca.der",ios::out | ios::trunc | ios::binary);






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

    CSV::CSTBS *cstbs;
    CSV::MCSR *mcsr;
    CSV::CA *ca;


    //Polpulating the CSRToBeSigned Structure
    //Generating ID's
    unsigned int d_id, o_id;
    d_id = (uint32_t)rand();
    cstbs->set_deviceid(d_id);
    mcsr->set_deviceid(d_id);
    ca->set_deviceid(d_id);
    o_id = (uint32_t)rand();
    cstbs->set_orgid(o_id);
    mcsr->set_orgid(o_id);
    ca->set_orgid(o_id);


    //Storing the ID's
    cstbs->set_curveid(ecctype);
    mcsr->set_curveid(ecctype);
    ca->set_curveid(ecctype);
    cstbs->set_hashid(hn);
    mcsr->set_hashid(hn);
    ca->set_hashid(hn);
    cstbs->set_pubklen(pubKLen);
    mcsr->set_pubklen(pubKLen);
    ca->set_pubklen(pubKLen);

    cstbs.SerializeToOstream(&fo);




    fp = fopen("cstbs.der", "a");
    if(fp == NULL){
    	printf("Cannot Open cstbs.der\n");
    	exit(1);
    }

    fwrite(&PUBKey, sizeof(PUBKey), 1, fp);
    fclose(fp);

    //Polpulating the MiniCertSignRequest Structure

    ar[0] = d_id;
    ar[1] = o_id;
    ar[2] = pubKLen;
    
    unsigned char s[3] = {3};
    memcpy(s, (char*)&ar, sizeof(ar));

    unsigned char *m = (unsigned char*)ecctype;
    unsigned char *n = (unsigned char*)hn;

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

    sig1 = (char *)sig;
    mcsr->set_sigl(sLen);
    mcsr->set_sig(sig1);
   

    //writting to a fp
 	mcsr.SerializeToOstream(&f2);

 	fp = fopen("mcsr.der", "a");
    if(fp == NULL){
    	printf("Cannot Open mcsr.der\n");
    	exit(1);
    }

    fwrite(&PUBKey, sizeof(PUBKey), 1, fp);
    fclose(fp);

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

    ca->set_validf(validF);
    ca->set_validfor(validFor);

    int ca_id, ca_sno;
    ca_id = (uint32_t)rand();
    ca_sno = (uint32_t)rand();
    ca->set_certsno(ca_sno);
    ca->set_caid(ca_id);

        //writting to a fp
	ca.SerializeToOstream(&f2);

    fp = fopen("ca.der", "a");
    if(fp == NULL){
    	printf("Cannot Open ca.der\n");
    	exit(1);
    }

    fwrite(&PUBKey, sizeof(PUBKey), 1, fp);
    fclose(fp);


    if(sig)
        OPENSSL_free(sig);
    if(PUBKey)
        EVP_PKEY_free(PUBKey);
    
    if(PRKEY)
        EVP_PKEY_free(PRKEY);




    return 0;
}