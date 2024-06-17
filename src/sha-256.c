#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// constant values
static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// utils

// right spin
uint32_t ROTR(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

// right shift
uint32_t SHR(uint32_t x, uint32_t n) {
    return x >> n;
}

// select
uint32_t Ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}

// majority
uint32_t Maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

// capptal sigma0
uint32_t Sigma0(uint32_t x) {
    return ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22);
}

// capital sigma1
uint32_t Sigma1(uint32_t x) {
    return ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25);
}

// sigma0
uint32_t sigma0(uint32_t x) {
    return ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3);
}

uint32_t sigma1(uint32_t x) {
    return ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10);
}


// init hash value
uint32_t H[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

// padding message
uint32_t* padMessage(const uint8_t* message, size_t length, size_t* paddedLength) {
    // new length after padding
    size_t newLength = length + 1;
    while (newLength % 64 != 56)
    {
        newLength++;
    }
    *paddedLength = newLength + 8;

    // alloc memory
    uint8_t* paddedMessage = (uint8_t*)malloc(*paddedLength);
    if (!paddedMessage) {
        perror("Failed to allocate memory!");
        exit(EXIT_FAILURE);
    }

    // copy original message
    memcpy(paddedMessage, message, length);
    paddedMessage[length] = 0x80;
    memset(paddedMessage + length + 1, 0, newLength = length - 1);

    // entail message length with big endian (64 bits)
    uint64_t bitLength = length * 8;
    for (int i = 0; i < 8; i++) {
        paddedMessage[*paddedLength - 1 - i] = (bitLength >> (8 * i)) & 0xff;
    }
    
    return paddedMessage;
}


// process message by block (per 512 bits), updates hash value
void processBlock(const uint8_t* block, uint32_t* hash) {
    uint32_t W[64];
    uint32_t a, b, c, d, e, f, g, h;

    for (int i = 0; i < 16; i++) {
        W[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) | (block[i * 4 + 2] << 8) | block[i * 4 + 3];
    }
    for (int i = 16; i < 64; i++) {
        W[i] = sigma1(W[i - 2]) + W[i - 7] + sigma0(W[i - 15]) + W[i - 16];
    }

    a = hash[0];
    b = hash[1];
    c = hash[2];   
    d = hash[3];   
    e = hash[4];   
    f = hash[5];   
    g = hash[6];   
    h = hash[7];

    for (int i = 0; i < 64; i++) {
        uint32_t T1 = h + Sigma1(e) + Ch(e, f, g) + K[i] + W[i];
        uint32_t T2 = Sigma0(a) + Maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2; 
    }   

    hash[0] += a;
    hash[1] += b;
    hash[2] += c;
    hash[3] += d;
    hash[4] += e;
    hash[5] += f;
    hash[6] += g;
    hash[7] += h;
}

// calculate sha256
void sha256(const uint8_t* message, size_t length, uint8_t hash[32]) {
    size_t paddedLength;
    uint8_t* paddedMessage = padMessage(message, length, &paddedLength);

    uint32_t hashValues[8];
    memcpy(hashValues, H, sizeof(H));

    for (size_t i = 0; i < paddedLength; i += 64) {
        processBlock(paddedMessage + i, hashValues);
    }

    for (int i = 0; i < 8; i++) {
        hash[i * 4]     = (hashValues[i] >> 24) & 0xff;
        hash[i * 4 + 1] = (hashValues[i] >> 16) & 0xff;
        hash[i * 4 + 2] = (hashValues[i] >> 8) & 0xff;
        hash[i * 4 + 3] = (hashValues[i]) & 0xff;
    }

    free(paddedMessage);
}

// print
void printHash(const uint8_t hash[32]) {
    for (int i = 0; i < 32; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <message>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char* message = argv[1];
    uint8_t hash[32];

    sha256((const uint8_t*)message, strlen(message), hash);
    printHash(hash);

    return 0;
}