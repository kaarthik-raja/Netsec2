How to execute:
    >make : 'make kdc' for compiling kdc.cpp
    >make : 'make client' compiles and executes client.cpp

Sample Commands:
    >KDC code : ./kdc -p 1235 -o log.txt -f pwd.txt
    >Client code : ./client -n myname -m S -o othername -i plain.txt -a 127.0.0.1 -p 8080
    >Replace 127.0.0.1 with server IP for different machines

Web or any other help:
    >Encryption and Decryption functions used from links which were given as reference by sir:
        https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
        and https://wiki.openssl.org/index.php/Libcrypto_API
    >Rest of the code written independently.

Weakness:
    >No error cases known.

Members:
    >Pranav Gadikar and Kaarthik Raja(CS16B108)