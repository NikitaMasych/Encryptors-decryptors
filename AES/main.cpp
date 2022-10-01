#include <iostream>
#include "AES.h"


void testViaHex(){
    AES instance;

    instance.enterPlaintextAsHex();
    instance.requestKey();

    instance.encryptPlaintext();
    instance.outputCiphertext();

    instance.decryptCiphertext();
    instance.outputDecryptedCiphertextAsHex();

}

void testViaASCII(){
    AES instance;

    instance.enterPlaintext();
    instance.requestKey();

    instance.encryptPlaintext();
    instance.outputCiphertext();

    instance.decryptCiphertext();
    instance.outputDecryptedCiphertext();

}

int main()
{

    testViaHex();
    testViaASCII();

    return 0;
}
