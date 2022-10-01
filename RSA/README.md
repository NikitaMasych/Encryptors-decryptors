This is RSA via java. 
Implemented RSAES-OAEP, RSAES-PKCS1-V1_5 encryption and decryption functions and RSASSA-PSS as digital signature generation and verification operations.
So far it allows user to set hashing algorithm (EVEN IF IT IS NOT CRYPTOGRAPHICALLY SECURE), salt length for DS and length of the key.
Additional functionality leads in key pair generation via internal java library for achieving strong level of reliability and security. (Though maybe later I will write it myself).
MADE IN EDUCATIONAL PURPOSES. REQUIRES MODIFYING TO USE IN REAL PROJECTS.
