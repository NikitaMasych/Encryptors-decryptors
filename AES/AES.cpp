#include <iostream>
#include <iomanip>
#include <random>
#include "AES.h"


std::vector<std::vector<uint_fast8_t> > calculateBlock(size_t pos,
                            const std::vector <uint_fast8_t> & message){
    // creates two-dimensional array 4 * 4 from plaintext
    std::vector<std::vector<uint_fast8_t> >  res(4, std::vector<uint_fast8_t> (4,0));
    for(size_t i = 0; i != 4; ++i)
        for(size_t j = 0; j != 4; ++j){
            res[j][i] = message[pos];
            pos++;
        }
    return res;
};

void rotWord(std::vector<uint_fast8_t> &temp){
    // one byte circular shift
    uint_fast8_t tmp = temp[0];
    for (size_t i = 0; i != 3; i ++){
        temp[i] = temp[i+1];
    }
    temp[3] = tmp;
}

void AES::subWord(std::vector<uint_fast8_t> &temp){
    // replace each byte using SBox
    for (size_t i = 0; i != 4; ++i){
        temp[i] = sBox[temp[i] / 16] [ temp[i] % 16 ];
    }
}

void rConWord(std::vector<uint_fast8_t> &temp, uint_fast8_t& rcon){
    // implements \xor rcon operation and computes next rcon
    temp[0] ^= rcon;
    rcon = (rcon << 1) ^ (0x11b & -(rcon >> 7));
}

void AES::keyExpansion(){
    // expands key to the required extent
    uint_fast8_t rcon = 0x01;
    std::vector<uint_fast8_t> temp(4,0);

    for (size_t i = 4 * Nk; i != 16 * (Nr + 1); i += 4){
        temp[0] = key[i-4];
        temp[1] = key[i-3];
        temp[2] = key[i-2];
        temp[3] = key[i-1];
        if (i/4 % Nk == 0){
            rotWord(temp);
            subWord(temp);
            rConWord(temp, rcon);
        }
        else if (Nk > 6 && i / 4 % Nk  == 4)
            subWord(temp);

        for (size_t j = 0; j != 4; ++j) key.push_back(temp[j] ^ key[i + j - 4 * Nk]);
    }
}

void AES::addRoundKey(std::vector<std::vector<uint_fast8_t> > &state, size_t pos){
    // state \xor key operation
    for (size_t i = 0; i != 4; ++i)
        for (size_t j = 0; j != 4; ++j){
            state[j][i] ^= key[pos];
            pos ++;
        }
}

void AES::subBytes(std::vector<std::vector<uint_fast8_t> > &state){
    // replace each byte using SBox
    for (size_t i = 0; i != 4; ++i){
        for (size_t j = 0; j != 4; ++j){
            state[i][j] = sBox[state[i][j] / 16][state[i][j] % 16];
        }
    }
}

void shiftRows(std::vector<std::vector<uint_fast8_t> > &state){
    // implements cyclical shift transformation
    // for each row by its index
    rotWord(state[1]);
    rotWord(state[2]); rotWord(state[2]);
    rotWord(state[3]); rotWord(state[3]); rotWord(state[3]);
}

uint_fast8_t GMul(uint_fast8_t a, uint_fast8_t b) {
    // Galois Field (256) Multiplication of two Bytes
    uint_fast8_t p = 0;
    for (size_t i = 0; i != 8; ++i){
        if ((b & 1) != 0)
            p ^= a;

        bool hi_bit_set = (a & 0x80) != 0;
        a <<= 1;
        if (hi_bit_set) {
            a ^= 0x1B; /* x^8 + x^4 + x^3 + x + 1 */
        }
        b >>= 1;
    }

    return p;
}

void mixColumns(std::vector <std::vector<uint_fast8_t> > &state){
    std::vector <std::vector<uint_fast8_t> > res(4, std::vector<uint_fast8_t>(4,0));
    for (size_t j = 0; j != 4; ++j){
        res[0][j] = GMul(0x02, state[0][j]) ^ GMul(0x03, state[1][j]) ^ GMul(0x01, state[2][j]) ^ GMul(0x01, state[3][j]);
        res[1][j] = GMul(0x01, state[0][j]) ^ GMul(0x02, state[1][j]) ^ GMul(0x03, state[2][j]) ^ GMul(0x01, state[3][j]);
        res[2][j] = GMul(0x01, state[0][j]) ^ GMul(0x01, state[1][j]) ^ GMul(0x02, state[2][j]) ^ GMul(0x03, state[3][j]);
        res[3][j] = GMul(0x03, state[0][j]) ^ GMul(0x01, state[1][j]) ^ GMul(0x01, state[2][j]) ^ GMul(0x02, state[3][j]);
    }
    state = res;
}

std::vector<uint_fast8_t> convertStates(std::vector <std::vector<std::vector<uint_fast8_t> > > states){
    std::vector<uint_fast8_t> statesLine;
    for (size_t i = 0; i != states.size(); ++i){
        for(size_t j = 0; j != 16; ++j){
            statesLine.push_back(states[i][j%4][j/4]);
        }
    }
    return statesLine;
}

void AES::paddingPKCS7(){
    // implements PKCS#7 padding
    AES::paddedBytes = 16 - plaintext.size() % 16;
    for (size_t i = 0; i != AES::paddedBytes; ++i){
        plaintext.push_back(static_cast<uint_fast8_t>(AES::paddedBytes));
    }
}

void AES::generateIV(){
    std::random_device rd;
    std::mt19937 e{rd()};
    std::uniform_int_distribution<uint_fast8_t> dist(0,255);
    std::vector<uint_fast8_t> IV(16);
    for(size_t i = 0; i != 16; ++i)
        IV[i] = dist(rd);
    AES::IV = IV;
}

std::vector<std::vector<uint_fast8_t> > AES::encryptBlock(
            std::vector<std::vector<uint_fast8_t> > state){
    addRoundKey(state, 0);
    for (size_t round = 1; round != Nr; ++ round){
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, round*16);
    }
    subBytes(state);
    shiftRows(state);
    addRoundKey(state, 16*Nr);
    return state;
}

std::vector<std::vector<uint_fast8_t> > XORVectors(
                std::vector<std::vector<uint_fast8_t> > state,
                const std::vector<std::vector<uint_fast8_t> >& term){
    std::vector<std::vector<uint_fast8_t> > res(4, std::vector<uint_fast8_t>(4,0));
    for (size_t i = 0; i != 4; ++i)
        for (size_t j = 0; j != 4; ++j)
            res[i][j] = state[i][j] ^ term[i][j];
    return res;
}

void AES::encryptPlaintext(){
    keyExpansion();
    paddingPKCS7();
    std::vector <std::vector<std::vector<uint_fast8_t> > > states;
    std::vector<std::vector<uint_fast8_t> > previous = calculateBlock(0, IV);
    for (size_t i = 0; i != plaintext.size(); i += 16){
        states.push_back(encryptBlock(XORVectors(calculateBlock(i, plaintext), previous)));
        previous = states[states.size()-1];
    }
    ciphertext = convertStates(states);
};

void invShiftRows(std::vector<std::vector<uint_fast8_t> > &state){
    // implements inversive cyclical shift transformation
    rotWord(state[1]); rotWord(state[1]); rotWord(state[1]);
    rotWord(state[2]); rotWord(state[2]);
    rotWord(state[3]);
}

void AES::invSubBytes(std::vector<std::vector<uint_fast8_t> > &state){
    // replace each byte using inversive SBox
    for (size_t i = 0; i != 4; ++i){
        for (size_t j = 0; j != 4; ++j){
            state[i][j] = invSBox[state[i][j] / 16][state[i][j] % 16];
        }
    }
}

void invMixColumns(std::vector<std::vector<uint_fast8_t> > &state){
    std::vector <std::vector<uint_fast8_t> > res(4, std::vector<uint_fast8_t>(4,0));
    for (size_t j = 0; j != 4; ++j){
        res[0][j] = GMul(0x0e, state[0][j]) ^ GMul(0x0b, state[1][j]) ^ GMul(0x0d, state[2][j]) ^ GMul(0x09, state[3][j]);
        res[1][j] = GMul(0x09, state[0][j]) ^ GMul(0x0e, state[1][j]) ^ GMul(0x0b, state[2][j]) ^ GMul(0x0d, state[3][j]);
        res[2][j] = GMul(0x0d, state[0][j]) ^ GMul(0x09, state[1][j]) ^ GMul(0x0e, state[2][j]) ^ GMul(0x0b, state[3][j]);
        res[3][j] = GMul(0x0b, state[0][j]) ^ GMul(0x0d, state[1][j]) ^ GMul(0x09, state[2][j]) ^ GMul(0x0e, state[3][j]);
    }
    state = res;
}

std::vector<std::vector<uint_fast8_t> > AES::decryptBlock(
            std::vector<std::vector<uint_fast8_t> > state){
    addRoundKey(state, 16*Nr);
    for (size_t round = Nr-1; round != 0; -- round){
        invShiftRows(state);
        invSubBytes(state);
        addRoundKey(state, round*16);
        invMixColumns(state);
    }
    invShiftRows(state);
    invSubBytes(state);
    addRoundKey(state, 0);
    return state;
}

void AES::decryptCiphertext(){
    std::vector <std::vector<std::vector<uint_fast8_t> > > states;
    std::vector<std::vector<uint_fast8_t> > previous = calculateBlock(0, IV);
    for(size_t i = 0; i != plaintext.size(); i += 16){
        states.push_back(XORVectors(decryptBlock(calculateBlock(i, ciphertext)), previous));
        previous = calculateBlock(i, ciphertext);
    }
    decryptedCiphertext = convertStates(states);
    // remove padded bytes:
    decryptedCiphertext = std::vector<uint_fast8_t>(decryptedCiphertext.begin(),
                                                    decryptedCiphertext.end() - paddedBytes);
};

