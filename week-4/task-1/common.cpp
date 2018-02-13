#include "common.h"

using namespace std;


//static BIO *bio_err=0;
static int My_pem_password_cb(char*buf, int size, int rwflag, void *password);
static int VerifyCertificate(int ok, X509_STORE_CTX *ctx);
static int GenerateCookie( SSL *ssl, unsigned char *cookie, unsigned int *clen );
static int VerifyCookie( SSL *ssl, unsigned char *cookie, unsigned int clen );
static void sigpipe_handle(int x);



/*Error handling*/
int ErrorHandler(const char *msg)
{
  perror(msg);
  exit(0);
}
/* Print SSL errors and exit*/
int SSLErrorHandler(const char * string)
{
  BIO_printf(bio_err,"%s\n",string);
  ERR_print_errors(bio_err);
  perror(string);
  exit(0);
}

void SSLReadWriteErrorHandler(SSL* ssl, int readwritten)
{
  char buf[480]={};
  unsigned long e;
  switch (SSL_get_error(ssl, readwritten))
  {
    case SSL_ERROR_NONE:
      break;
    /*If you use ERR_get_error and ERR_error_string
    etc. you should loop until you get 0 because there may be more
     than one code. */
    case SSL_ERROR_SSL:
    {
      perror("SSL protocol error, connection failed");
      e = ERR_get_error();
      while (e != 0)
      {
       ERR_error_string(e, buf);
       perror(buf);
       e = ERR_get_error();
      }
      break;
    }
    case SSL_ERROR_WANT_READ:
      perror("no data available for reading and socket is in non-blocking mode; try again later");
        break;
    case SSL_ERROR_WANT_WRITE:
      perror("socket is blocked from sending data; try again later");
        break;
    case SSL_ERROR_SYSCALL:
    {
      perror("I/O error; check sock_err");
      e = ERR_get_error();
      while (e != 0)
      {
       ERR_error_string(e, buf);
       perror(buf);
       e = ERR_get_error();
      }
          break;
    }
    case SSL_ERROR_ZERO_RETURN:
    {
        perror("Connection shut down remotely");
        e = ERR_get_error();
        while (e != 0)
        {
          ERR_error_string(e, buf);
          perror(buf);
          e = ERR_get_error();
        }
      break;
    }
    case SSL_ERROR_WANT_CONNECT:
      perror("SSL session not completely started; try again");
      break;
    default:
    {
      perror("SSL read problem");
      e = ERR_get_error();
      while (e != 0)
      {
        ERR_error_string(e, buf);
        perror(buf);
        e = ERR_get_error();
      }
      break;
    }
  }/*end switch*/
}

static void sigpipe_handle(int x){
}

void InitialiseOpenSSL(void)
{
  #if OPENSSL_VERSION_NUMBER < 0x10100000L
  SSL_library_init();
  #else
  OPENSSL_init_ssl(0, NULL);
  #endif

  SSL_load_error_strings();
  /* Load the human readable error strings for libcrypto */
  ERR_load_crypto_strings();
  ERR_load_BIO_strings();
  /* Load all digest and cipher algorithms */
  OpenSSL_add_all_algorithms();
  //CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
}

void DtlsBegin()
{
  #if OPENSSL_VERSION_NUMBER < 0x10100000L
  SSL_library_init();
  #else
  OPENSSL_init_ssl(0, NULL);
  #endif
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();
    //CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
}




int DtlsInitServerContextFromKeystore(DTLSParams* params, const char* cert_file,
    const char* privkey_file, const char* cacert_file, const SSL_METHOD *meth)
{
    int result = 0;

    // Create a new context using DTLS
    params->ctx = SSL_CTX_new(meth);
    if (params->ctx == NULL) {
         SSLErrorHandler("Cannot create SSL Context");
    }
    // Set our supported ciphers
    result = SSL_CTX_set_cipher_list(params->ctx, MOSTCIPHERS);
    if (result != 1)
    {  SSLErrorHandler("Error setting cipher list");}

    SSL_CTX_set_default_passwd_cb(params->ctx, My_pem_password_cb);

    SSL_CTX_set_verify(params->ctx, SSL_VERIFY_PEER, VerifyCertificate);

    // Load the certificate file; contains also the public key
    result = SSL_CTX_use_certificate_file(params->ctx, cert_file,
            SSL_FILETYPE_PEM);
    if (result != 1)
      {  SSLErrorHandler("Can't read certificate file\n");}

    // Load private key
    result = SSL_CTX_use_PrivateKey_file(params->ctx, privkey_file, SSL_FILETYPE_PEM);
    if (result != 1)
      {SSLErrorHandler("Can't read key file\n");}

    // Check if the private key is valid
    result = SSL_CTX_check_private_key(params->ctx);
    if (result != 1)
        {SSLErrorHandler("Error: checking the private key failed. \n");}

    if(!(SSL_CTX_load_verify_locations(params->ctx, cacert_file,"/etc/ssl/certs/ca-certificates.crt"))){
      SSLErrorHandler("Can't load_verify_locations");
    }

    LoadECParamsInContext(params->ctx);

    SSL_CTX_set_cookie_generate_cb(params->ctx, GenerateCookie);
    SSL_CTX_set_cookie_verify_cb(params->ctx, VerifyCookie);

    return 0;
}

int DtlsInitClientContextFromKeystore(DTLSParams* params, const char* cert_file,
    const char* privkey_file, const char* cacert_file, const SSL_METHOD *meth)
{
    int result = 0;

    // Create a new context using DTLS
    params->ctx = SSL_CTX_new(meth);
    if (params->ctx == NULL) {
         SSLErrorHandler("Cannot create SSL Context");
    }

    SSL_CTX_set_default_passwd_cb(params->ctx, My_pem_password_cb);
    // Set our supported ciphers
    LoadECParamsInContext(params->ctx);
    result = SSL_CTX_set_cipher_list(params->ctx, MOSTCIPHERS);
    if (result != 1)
    {  SSLErrorHandler("Error setting cipher list");}

    SSL_CTX_set_verify(params->ctx, SSL_VERIFY_PEER, VerifyCertificate);

    // Load the certificate file; contains also the public key
    result = SSL_CTX_use_certificate_file(params->ctx, cert_file,
            SSL_FILETYPE_PEM);
    if (result != 1)
      {  SSLErrorHandler("Can't read certificate file\n");}

    // Load private key
    result = SSL_CTX_use_PrivateKey_file(params->ctx, privkey_file, SSL_FILETYPE_PEM);
    if (result != 1)
      {SSLErrorHandler("Can't read key file\n");}

    // Check if the private key is valid
    result = SSL_CTX_check_private_key(params->ctx);
    if (result != 1)
        {SSLErrorHandler("Error: checking the private key failed. \n");}

    if(!(SSL_CTX_load_verify_locations(params->ctx, cacert_file,"/etc/ssl/certs/ca-certificates.crt")))
        {SSLErrorHandler("Can't load_verify_locations");}

        //SSL_CTX_set_cookie_generate_cb(params->ctx, GenerateCookie);
        //SSL_CTX_set_cookie_verify_cb(params->ctx, VerifyCookie);

    return 0;
}

int DtlsInitServer(DTLSParams* params, int sock)
{
    params->bio = BIO_new_dgram(sock, BIO_NOCLOSE);
    if (params->bio == NULL)
      {SSLErrorHandler("Error: connecting with BIOs\n");}

    params->ssl = SSL_new(params->ctx);
    SSL_set_bio(params->ssl, params->bio, params->bio);
    if (params->ssl == NULL)
    {SSLErrorHandler("Error: creating SSL instance from BIO\n");}
    SSL_set_options(params->ssl, SSL_OP_COOKIE_EXCHANGE);
    return 0;
}

int DtlsInitClient(DTLSParams* params, const char *address)
{
  /*creates the BIO from the SSL_CTX*/
    params->bio = BIO_new_ssl_connect(params->ctx);
    if (params->bio == NULL) {
        fprintf(stderr, "error connecting to server\n");
        return -1;
    }
  /* set details of connection to server*/
    BIO_set_conn_hostname(params->bio, address);
    /*creates the SSL instance from the BIO*/
    BIO_get_ssl(params->bio, &(params->ssl));
    if (params->ssl == NULL) {
        fprintf(stderr, "params null, exit\n");
        return -1;
    }

    SSL_set_connect_state(params->ssl);
    SSL_set_mode(params->ssl, SSL_MODE_AUTO_RETRY);

    return 0;
}

void DtlsShutdown(DTLSParams* params)
{
    if (params == NULL) {
        return;
    }

    if (params->ctx != NULL) {
        SSL_CTX_free(params->ctx);
        params->ctx = NULL;
    }

    if (params->ssl != NULL) {
        SSL_free(params->ssl);
        params->ssl = NULL;
    }
}

void DtlsEnd()
{
    //ERR_remove_state(0);
    ENGINE_cleanup();
    CONF_modules_unload(1);
    EVP_cleanup();
    sk_SSL_COMP_free(SSL_COMP_get_compression_methods());
    CRYPTO_cleanup_all_ex_data();
    //CRYPTO_mem_leaks(bio_err);
    BIO_free(bio_err);
    ERR_free_strings();
}


SSL_CTX *CreateSSLContext()
{
  if (!bio_err)
  {
    #if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_library_init();
    #else
    OPENSSL_init_ssl(0, NULL);
    #endif

    SSL_load_error_strings();
    ERR_load_crypto_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();

    srand ( time(NULL) );
    //RAND_seed(randbuf,strlen(randbuf));
    /* An error write context */
    bio_err=BIO_new_fp(stderr,BIO_NOCLOSE);
  }/*end if*/

  /* Set up a SIGPIPE handler */
  signal(SIGPIPE,sigpipe_handle);

  /*Create SSL context*/
  const SSL_METHOD *method;
  SSL_CTX *ctx;
  method = SSLv23_method();
  ctx = SSL_CTX_new(method);
  if (!ctx)
    SSLErrorHandler("Unable to create SSL context\n");
  return ctx;
}



/*The password code is not thread safe, returns characters in buf to calling function*/
static  int My_pem_password_cb(char*buf, int size, int rwflag, void *password)
{
  int len;
  char tmp[20];
  printf("Enter pass phrase:");
  scanf("%s", tmp);
  len = strlen(tmp);
  if (len <= 0)
    return 0;
  if (len > size)
    len = size;
  memcpy(buf, tmp, len);
  return len;
}



SSL_CTX * ConfigureOpenSSLContext(SSL_CTX *ctx, const char* cert_file, const char* privkey_file, const char* cacert_file)
{
SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,0);

if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0)
SSLErrorHandler("Can't read certificate file\n");
SSL_CTX_set_default_passwd_cb(ctx, My_pem_password_cb);
if (SSL_CTX_use_PrivateKey_file(ctx, privkey_file, SSL_FILETYPE_PEM) <= 0 )
SSLErrorHandler("Can't read key file\n");

if(!(SSL_CTX_load_verify_locations(ctx, cacert_file,"/etc/ssl/certs/ca-certificates.crt")))
SSLErrorHandler("Can't load_verify_locations");

if (SSL_CTX_set_cipher_list(ctx, CIPHERLIST)==0)
SSLErrorHandler("Error setting cipher list");

LoadECParamsInContext(ctx);

return ctx;
}



SSL_CTX * LoadECParamsInContext(SSL_CTX *ctx)
{
  EC_KEY *ecdh;
  ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  if (ecdh == NULL) /* error */
    SSLErrorHandler("Couldn't link ec_key to named curve\n");
  if(SSL_CTX_set_tmp_ecdh(ctx,ecdh)<0)
    SSLErrorHandler("Couldn't set EC parameters for context\n");
  return ctx;
}


// openssl-1.0.2k/apps/s_cb.c
static int VerifyCertificate(int ok, X509_STORE_CTX *ctx)
{
  int verify_depth = 0;
  int verify_quiet = 0;
  int verify_error = X509_V_OK;
  int verify_return_error = 0;
  X509 *err_cert;
  int err, depth;

    err_cert = X509_STORE_CTX_get_current_cert(ctx);
    err = X509_STORE_CTX_get_error(ctx);
    depth = X509_STORE_CTX_get_error_depth(ctx);

    if (!verify_quiet || !ok) {
        BIO_printf(bio_err, "depth=%d ", depth);
        if (err_cert) {
            X509_NAME_print_ex(bio_err,
                               X509_get_subject_name(err_cert),
                               0, XN_FLAG_ONELINE);
            BIO_puts(bio_err, "\n");
        } else
            BIO_puts(bio_err, "<no cert>\n");
    }
    if (!ok) {
        BIO_printf(bio_err, "verify error:num=%d:%s\n", err,
                   X509_verify_cert_error_string(err));
        if (verify_depth >= depth) {
            if (!verify_return_error)
                ok = 1;
            verify_error = X509_V_OK;
        } else {
            ok = 0;
            verify_error = X509_V_ERR_CERT_CHAIN_TOO_LONG;
        }
    }
    switch (err) {
    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
        BIO_puts(bio_err, "issuer= ");
        X509_NAME_print_ex(bio_err, X509_get_issuer_name(err_cert),
                           0, XN_FLAG_ONELINE);
        BIO_puts(bio_err, "\n");
        break;
    case X509_V_ERR_CERT_NOT_YET_VALID:
    case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
        BIO_printf(bio_err, "notBefore=");
        ASN1_TIME_print(bio_err, X509_get_notBefore(err_cert));
        BIO_printf(bio_err, "\n");
        break;
    case X509_V_ERR_CERT_HAS_EXPIRED:
    case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
        BIO_printf(bio_err, "notAfter=");
        ASN1_TIME_print(bio_err, X509_get_notAfter(err_cert));
        BIO_printf(bio_err, "\n");
        break;
    case X509_V_ERR_NO_EXPLICIT_POLICY:
        if (!verify_quiet)
            BIO_printf(bio_err, "\n");
        break;
    }
    if (err == X509_V_OK && ok == 2 && !verify_quiet)
        BIO_printf(bio_err, "\n");
    if (ok && !verify_quiet)
        BIO_printf(bio_err, "verify return:%d\n", ok);
    return (ok);
}


// The content is arbitrary, but for security reasons it should contain
//the client's address, a timestamp and should be signed.
static int GenerateCookie( SSL *ssl, unsigned char *cookie,
  unsigned int *cookie_len )
{

  /* Get peer information, allocate a buffer [...] */
  char *buff, result[EVP_MAX_MD_SIZE];
  unsigned int length, resultlength;

  union {
        struct sockaddr_storage sa;
        struct sockaddr_in s4;
      } peer;


  (void) BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

  /* Create buffer with peer's address and port */
  length = 0;
  length += sizeof(struct in_addr);
  length += sizeof(peer.s4.sin_port);

  buff = (char*)OPENSSL_malloc(length);

  if (buff == NULL) {
        BIO_printf(bio_err, "out of memory\n");
        return 0;
    }

  memcpy(buff, &peer.s4.sin_port, sizeof(peer.s4.sin_port));
  memcpy(buff + sizeof(peer.s4.sin_port), &peer.s4.sin_addr,
              sizeof(struct in_addr));

  /* Generate the cookie with a random secret in buff ... */
  HMAC(EVP_sha256(), ck_secrets_random(), CK_SECRET_LENGTH,
          (unsigned char *)buff,length,
          (unsigned char *)result, &resultlength);

  /* and copy buff to the provided *cookie memory location [...] */
  memcpy(cookie, result, resultlength);
  *cookie_len = resultlength;

    /* Clean up all the stuff [...] */
  OPENSSL_free(buff);

  return 1;
}

static int VerifyCookie( SSL *ssl, unsigned char *cookie,
    unsigned int cookie_len )
{
  /* Get peer information, allocate a buffer [...] */
  char *buff;
  unsigned int length;

  union {
        struct sockaddr_storage sa;
        struct sockaddr_in s4;
      } peer;
  /* Handle ssl & cookie stuff [......] */

  (void) BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

  /* Create buffer with peer's address and port */
  length = 0;
  length += sizeof(struct in_addr);
  length += sizeof(peer.s4.sin_port);

  buff = (char*)OPENSSL_malloc(length);

  if (buff == NULL)
  {
      BIO_printf(bio_err, "out of memory\n");
      return 0;
  }

  memcpy(buff, &peer.s4.sin_port, sizeof(peer.s4.sin_port));
  memcpy(buff + sizeof(peer.s4.sin_port), &peer.s4.sin_addr,
                            sizeof(struct in_addr));

  /* Tests whether cookie matches one of our secrets */
  if(ck_secrets_exist((unsigned char *)buff, length,
                      (unsigned char *)cookie, cookie_len) == 1 )
    {return 1;}

    return 0;
}

sockaddr_in BuildServerAddressForClient(const char* host, const int port)
{
  struct hostent *hp;
  struct sockaddr_in addr;
  if(!(hp=gethostbyname(host)))
    SSLErrorHandler("Couldn't resolve host");

  memset(&addr,0,sizeof(addr));
  addr.sin_family=hp->h_addrtype;
  addr.sin_port=htons(port);
  memcpy((void*) &addr.sin_addr, hp->h_addr, hp->h_length);

  return addr;
}

sockaddr_in BuildServerAddressForServer(const int port)
{
  struct sockaddr_in addr;

  bzero(&addr, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port = htons((uint16_t)port);

  return addr;
}

/**
* Opens a socket for the client .
* @return Socket
*/
int CreateUDPClientSocket(sockaddr_in server_addr)
{
  int sock;

  if((sock=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP))<0)
    ErrorHandler("Couldn't create socket");

  if(connect(sock,(struct sockaddr *)&server_addr,sizeof(server_addr))<0)
    ErrorHandler("Couldn't connect socket");

  return sock;
}


/**
* Opens a socket for the client .
* @return Socket
*/
int CreateTCPClientSocket(sockaddr_in server_addr)
{
  int sock, conn;

  if((sock=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP))<0)
  {  ErrorHandler("Couldn't create socket");}
  int optval = 1;
  if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval)) == -1)
  {    ErrorHandler("Error setting socket options\n");}
  if((conn=connect(sock,(struct sockaddr *)&server_addr,sizeof(server_addr)))<0)
  {  ErrorHandler("Couldn't connect socket");}
  return sock;
}
int GetSizeOfFile(const char* filepath)
{
  struct stat fileinfo;
  if (stat(filepath, &fileinfo) == -1)
  ErrorHandler("Can't return file info");
  int filesize = fileinfo.st_size;
  return filesize;
}

void SendPeerSizeOfFile(const int filesize, SSL* ssl)
{
  char filesize_string[10];
  sprintf(filesize_string, "%d", filesize);
  int ssl_send_filesize = SSL_write(ssl, filesize_string,
    strlen(filesize_string));
  if (ssl_send_filesize <=0)
    {SSLErrorHandler("Error writing filesize to SSL");}
  }

  void SendPeerFileData(const char* filepath, const int filesize, SSL* ssl)
  {
    char to_send_buf[filesize];
    int pending = 1, read=0, ssl_written=0;
    FILE* send_file = fopen(filepath, "r");
    BIO* send_bio = BIO_new(BIO_s_file());
    BIO_set_fp(send_bio, send_file, BIO_CLOSE);
    while (pending > 0 || ssl_written < filesize)
    {
      read = BIO_read(send_bio, to_send_buf, filesize);
      pending = BIO_ctrl_pending(send_bio);
      ssl_written = SSL_write(ssl, to_send_buf, filesize);

      switch (SSL_get_error(ssl, ssl_written))
      {
        case SSL_ERROR_NONE:
          break;
        case SSL_ERROR_SSL:
          perror("Error in SSL Library");
        case SSL_ERROR_WANT_READ:
          perror("no data available for reading and socket \
            is in non-blocking mode; try again later");
        case SSL_ERROR_WANT_WRITE:
          perror("socket is blocked from sending data \
            ; try again later");
        case SSL_ERROR_SYSCALL:
          perror("I/O error; check sock_err");
        case SSL_ERROR_ZERO_RETURN:
          perror("Connection shut down remotely");
        case SSL_ERROR_WANT_CONNECT:
          perror("SSL session not completely started; try again");
        default:
          perror("SSL read problem");
        }/*end switch*/
      }/*end while*/

      printf("Pending %d,read: %d, written: %d\n", pending,
        read, ssl_written);
      BIO_free(send_bio);
}

void SendPeerAFile(const char* filepath, SSL* ssl)
{
  printf("Trying to get file size\n");
  int filesize = GetSizeOfFile(filepath);
  printf("Trying to send peer file size\n");
  SendPeerSizeOfFile(filesize, ssl);
  printf("Trying to send peer file data\n");
  SendPeerFileData(filepath, filesize, ssl);
}

int ReceiveSizeOfFileFromPeer (SSL* ssl)
{
  char filesize_string[10];
  int ssl_receive_filesize = SSL_read(ssl, filesize_string,
  strlen(filesize_string));
  if (ssl_receive_filesize <=0)
    SSLErrorHandler("Error reading filesize to SSL");
  int filesize = atoi(filesize_string);
  return filesize;
}

void ReceiveFileDataFromPeer(const char* filepath, const int filesize, SSL* ssl)
{
  char received_buf[filesize];
  int ssl_read = 0, written=0, pending = 1;
  FILE* receive_file = fopen(filepath, "w");
  BIO* receive_bio = BIO_new(BIO_s_file());
  BIO_set_fp(receive_bio, receive_file, BIO_CLOSE);
  while (pending > 0 || ssl_read < filesize)
  {
    ssl_read = SSL_read(ssl, received_buf, filesize);

    switch (SSL_get_error(ssl, ssl_read))
    {
      case SSL_ERROR_NONE:
        break;
      case SSL_ERROR_SSL:
        perror("Error in SSL Library");
      case SSL_ERROR_WANT_READ:
        perror("no data available for reading and socket \
          is in non-blocking mode; try again later");
      case SSL_ERROR_WANT_WRITE:
        perror("socket is blocked from sending data \
          ; try again later");
      case SSL_ERROR_SYSCALL:
        perror("I/O error; check sock_err");
      case SSL_ERROR_ZERO_RETURN:
        perror("Connection shut down remotely");
      case SSL_ERROR_WANT_CONNECT:
        perror("SSL session not completely started; try again");
      default:
        perror("SSL read problem");
    }/*end switch*/

    /*Flush to ensure output is written to file*/
    if (BIO_flush(receive_bio) !=1)
    {
      SSLErrorHandler("Error flushing contents of memory BIO\n");
    }
    /*Write contents of received_buf into receive_bio (FILE BIO) */
    written = BIO_write(receive_bio, received_buf, filesize);
    pending = BIO_ctrl_pending(receive_bio);
  }/*end while*/
  printf("Pending %d,read over SSL: %d, written to file: %d\n", pending,
  ssl_read, written);
  printf("Finished receiving %s\n", filepath);
  BIO_free(receive_bio);
}

void ReceiveAFileFromPeer(const char* filepath, SSL* ssl)
{
  printf("Trying to receive file size from client\n");
  int filesize = ReceiveSizeOfFileFromPeer (ssl);
  printf("Trying to receive file data from client\n");
  ReceiveFileDataFromPeer(filepath, filesize, ssl);
}

void SendPeerLengthOfMessage(char* msg, SSL* ssl)
{
  /*add a null terminating character*/
  int msg_length = strlen(msg)+1;
  char msg_length_string[10];
  sprintf(msg_length_string, "%d", msg_length);
  int ssl_send_msg_length = SSL_write(ssl, msg_length_string,
    strlen(msg_length_string));
  if (ssl_send_msg_length <=0)
  {
    SSLReadWriteErrorHandler(ssl, ssl_send_msg_length);
    perror("Error writing message length to SSL");;
  }
}

void SendPeerMessageData(char* msg, SSL* ssl)
{
  int msg_length = strlen(msg)+1;
  strcat(msg,"\0");

  int ssl_written= SSL_write(ssl, msg, msg_length);
  if (ssl_written <=0)
  {
    perror("Error writing message to SSL");
    SSLReadWriteErrorHandler(ssl, ssl_written);
  }
  printf("Written %s to SSL connection: %d bytes\n", msg, ssl_written);
}

void SendPeerAMessage(char* msg, SSL* ssl)
{
  SendPeerLengthOfMessage(msg, ssl);
  SendPeerMessageData(msg, ssl);
}

int ReceiveLengthOfMessageFromPeer(SSL* ssl)
{
  char msg_length_string[10];
  int ssl_receive_msg_length = SSL_read(ssl, msg_length_string, 10);
  if (ssl_receive_msg_length <=0)
  {
    SSLReadWriteErrorHandler(ssl, ssl_receive_msg_length);
    perror("Error reading message length from SSL");

    fprintf( stderr, "%s\n", strerror( errno ));
  }
int msg_length = atoi(msg_length_string);
return msg_length;
}

std::string ReceiveMessageDataFromPeer(const int msg_length, SSL* ssl)
{
  char received_buf[BUFLENGTH];
  int ssl_read = 0;

  ssl_read = SSL_read(ssl, received_buf, BUFLENGTH);
  if (ssl_read <=0)
  {
    SSLReadWriteErrorHandler(ssl, ssl_read);
    perror("Error reading message from SSL");

    fprintf( stderr, "%s\n", strerror( errno ));
  }
  printf("Read from SSL Connection: %d bytes\n", ssl_read);
  string output = received_buf;
  output.push_back('\0');
  return output;
}

void ReceiveMessageFromPeer(SSL* ssl)
{
  int msg_length = ReceiveLengthOfMessageFromPeer(ssl);
  string msg = ReceiveMessageDataFromPeer(msg_length, ssl);
  return msg; 
}



void DestroySSLContext(SSL_CTX *ctx)
{
  SSL_CTX_free(ctx);
}
void CleanupOpenSSL()
{
  EVP_cleanup();
}
