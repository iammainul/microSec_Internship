Hello Reader,

Inorder to run these programs you need to first of all generate the selfsigned cetificates.
To generate the certificates:

```
openssl ecparam -genkey -name prime256v1 -out key.pem
openssl req -new -sha256 -key key.pem -out csr.csr
openssl req -x509 -sha256 -days 365 -key key.pem -in csr.csr -out certificate.pem

```

