#Self created certificate

Hi,
This is a program to create a mini-certificate which doesn't follow the x509 structure.
This prgogram helps in to develop the knowledge how a mini certificate can be createde and verified by the CA.
The ***demo.c*** shows how to verify the certificates and sign them.
The ***CA.cpp*** is the main program here. The descriptions of the functions can be found in the ***CA.h*** file.
To run this
```
g++ -o <objectname> <programname.cpp> -lssl -lcrypto
./<objectname>
```
