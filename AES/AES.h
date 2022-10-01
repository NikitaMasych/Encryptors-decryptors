#ifndef AES_H_INCLUDED
#define AES_H_INCLUDED

#include <vector>


class AES{
private:
    std::vector <uint_fast8_t> plaintext, ciphertext,
                        decryptedCiphertext, key, IV;
    size_t keyLen, paddedBytes;
    size_t Nk, Nr;
    std::vector<std::vector<uint_fast8_t> > sBox, invSBox;
    void enterKey();
    void enterKeyLength();
    void initializeSBox();
    void initializeInvSBox();
    void keyExpansion();
    void subWord(std::vector<uint_fast8_t> &temp);
    void addRoundKey(std::vector<std::vector<uint_fast8_t> > &state,
                     size_t pos);
    void subBytes(std::vector<std::vector<uint_fast8_t> > &state);
    void invSubBytes(std::vector<std::vector<uint_fast8_t> > &state);
    void paddingPKCS7();
    std::vector<std::vector<uint_fast8_t> > encryptBlock(
            std::vector<std::vector<uint_fast8_t> > state);
    std::vector<std::vector<uint_fast8_t> > decryptBlock(
            std::vector<std::vector<uint_fast8_t> > state);
    void generateIV();
public:
    void requestKey();
    void enterPlaintext();
    void enterPlaintextAsHex();
    void encryptPlaintext();
    void decryptCiphertext();
    void outputCiphertext();
    void outputDecryptedCiphertext();
    void outputDecryptedCiphertextAsHex();
    void outputExpandedKeys();
    std::vector <uint_fast8_t> getPlaintext();
    std::vector <uint_fast8_t> getCiphertext();
    AES();
};

#endif // AES_H_INCLUDED
