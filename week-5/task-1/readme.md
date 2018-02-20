###Using OpenSSL API to Create PEM

Hi,
You can find the needed description in the programs how they work. The **example.cpp** shows how the keys are created and how it looks.

The other **two** programs create the certificate and key for server(**certcom.cpp**) and client(**certclient.cpp**).

To run this
```
g++ -o <objectname> <programname.cpp> -lssl -lcrypto
./<objectname>
```

or you can just run the make file.
```
make all
```
