#include <cstdio>
#include <iostream>
#include <fstream>
#include <cinttypes>
#include <vector>
#include <string>
#include <time.h>
#include <stdio.h>
using namespace std;
uint32_t pla[16] = { 0 };//存储明文
uint32_t ciphertext[16] = { 0 };//存储密文

uint32_t left_rotate(const uint32_t x, const uint32_t i) {      //循环左移
    return x << i | (x >> (sizeof(uint32_t) * 8 - i));
}

uint32_t tauTransformation(const uint32_t x) {    //τ变换
    const uint8_t Sbox[256] = {
        0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
        0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
        0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
        0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
        0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
        0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
        0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
        0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
        0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
        0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
        0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
        0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
        0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
        0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
        0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
        0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
    };
    uint32_t val;
    val = Sbox[x >> 0 & 0xff] << 0 | Sbox[x >> 8 & 0xff] << 8 |
        Sbox[x >> 16 & 0xff] << 16 | Sbox[x >> 24 & 0xff] << 24;
    return val;
}

uint32_t endianConvert(const uint32_t x) {      //密文变序
    return (x << 24 & 0xff000000) | (x << 8 & 0x00ff0000) |
        (x >> 8 & 0x0000ff00) | (x >> 24 & 0x000000ff);
}

uint32_t LTransformation(const uint32_t x) {                  //L变换
    return x ^
        left_rotate(x, 2) ^ left_rotate(x, 10) ^
        left_rotate(x, 18) ^ left_rotate(x, 24);
}

uint32_t L1Transformation(const uint32_t x) {                 //L'变换
    return x ^ left_rotate(x, 13) ^ left_rotate(x, 23);
}

uint32_t TTransformation(const uint32_t x) {                  //T变换
    return LTransformation(tauTransformation(x));
}

uint32_t FFunction(const uint32_t x[], const uint32_t rkey) { //F变换
    return x[0] ^ TTransformation(x[1] ^ x[2] ^ x[3] ^ rkey);
}

// key: 16 bytes
// keys: 32 * 4 bytes
void keyExpansion(const uint8_t key[], uint32_t keys[], int a) {  //密钥扩展
    uint32_t mk[4];
    mk[0] = key[0] << 24 | key[1] << 16 | key[2] << 8 | key[3] << 0;
    mk[1] = key[4] << 24 | key[5] << 16 | key[6] << 8 | key[7] << 0;
    mk[2] = key[8] << 24 | key[9] << 16 | key[10] << 8 | key[11] << 0;
    mk[3] = key[12] << 24 | key[13] << 16 | key[14] << 8 | key[15] << 0;
    const  uint32_t FK[4] = { 0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC };
    const  uint32_t CK[32] = {
        0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
        0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
        0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
        0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
        0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
        0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
        0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
        0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
    };
    uint32_t k[36];
    k[0] = mk[0] ^ FK[0], k[1] = mk[1] ^ FK[1],
        k[2] = mk[2] ^ FK[2], k[3] = mk[3] ^ FK[3];

    for (size_t i = 0; i < 32; ++i)
    {
        k[i + 4] = k[i] ^ L1Transformation(tauTransformation(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ CK[i]));
        keys[i] = k[i + 4];
        if (a)
        {
            cout << "rk" << i << ' ';
            printf("%x\n", keys[i]);
        }

    }

}

void sm4Iteration(const uint32_t keys[], uint32_t cipher[], int a) {    // 加密/解密过程
    uint32_t x[36], plain[4];
    if (a)
    {
        plain[0] = pla[0] << 24 | pla[1] << 16 | pla[2] << 8 | pla[3] << 0;
        plain[1] = pla[4] << 24 | pla[5] << 16 | pla[6] << 8 | pla[7] << 0;
        plain[2] = pla[8] << 24 | pla[9] << 16 | pla[10] << 8 | pla[11] << 0;
        plain[3] = pla[12] << 24 | pla[13] << 16 | pla[14] << 8 | pla[15] << 0;
    }
    else
    {
        plain[0] = ciphertext[0] << 24 | ciphertext[1] << 16 | ciphertext[2] << 8 | ciphertext[3] << 0;
        plain[1] = ciphertext[4] << 24 | ciphertext[5] << 16 | ciphertext[6] << 8 | ciphertext[7] << 0;
        plain[2] = ciphertext[8] << 24 | ciphertext[9] << 16 | ciphertext[10] << 8 | ciphertext[11] << 0;
        plain[3] = ciphertext[12] << 24 | ciphertext[13] << 16 | ciphertext[14] << 8 | ciphertext[15] << 0;
    }


    // x[0] = endianConvert(plain[0]);
     //x[1] = endianConvert(plain[1]);
    // x[2] = endianConvert(plain[2]);
     //x[3] = endianConvert(plain[3]);*/

    x[0] = plain[0];
    x[1] = plain[1];
    x[2] = plain[2];
    x[3] = plain[3];

    if (a)
    {
        for (size_t i = 0; i < 32; ++i)
        {
            x[i + 4] = FFunction(x + i, keys[i]);
            cout << 'X' << i + 4 << ": ";
            printf("%x\n", x[i + 4]);
        }
    }
    else
    {
        for (size_t i = 0; i < 32; ++i)
        {
            x[i + 4] = FFunction(x + i, keys[31 - i]);
        }
    }


    cipher[0] = endianConvert(x[35]);
    cipher[1] = endianConvert(x[34]);
    cipher[2] = endianConvert(x[33]);
    cipher[3] = endianConvert(x[32]);

}

void sm4_ecb(const size_t length, const void* key, void* cipher, int a) {
    //const uint32_t* plain_ = (const uint32_t*)(plain);
    uint32_t* cipher_ = (uint32_t*)(cipher);

    uint32_t keys[32];
    keyExpansion((const uint8_t*)(key), keys, a);

    for (size_t i = 0; i < length / 32; ++i) {
        sm4Iteration(keys, cipher_ + 4 * i, a);
    }
}

int main() {


    ifstream fin("plain.txt");

    fin.seekg(0, std::ios::beg);
    char buffer[33] = { 0 };
    for (int i = 0; i < 16; ++i) {
        fin.read(buffer, 2);
        pla[i] = stoi(buffer, 0, 16);//读取明文并存储为数字
        //cout << "plain"; printf("%02x\n", pla[i]);
    }
    fin.close();
    // 128 bit key size
    unsigned char key[16] = { 0 };


    fin.open("key.txt");
    fin.seekg(0, ios::beg);
    char buffe[3] = { 0 };
    for (int i = 0; i < 16; ++i) {
        fin.read(buffe, 2);
        key[i] = stoi(buffe, 0, 16);
        //cout << "key"; printf("%02x\n", key[i]);
    }
    fin.close();


    vector<char> cipher(32, 0);
    sm4_ecb(32, key, &cipher[0], 1);//最后一个参数为1.表示加密过程
    cout << "加密后的密文为：";
    for (size_t i = 0; i < 16; ++i)
    {

        printf("%02x", int(cipher[i]) & 0xff);//按16进制，每8位输出密文
        ciphertext[i] = int(cipher[i] & 0xff);//转录密文以进行下一步解密
    }
    printf("\n");
    sm4_ecb(32, key, &cipher[0], 0);//最后一个参数为0.表示解密过程
    cout << "解密后的明文为：";
    for (size_t i = 0; i < 16; ++i)
    {

        printf("%02x", int(cipher[i]) & 0xff);
    }
    printf("\n");
    printf("运行时间 = %.2fs\n", (double)clock() / CLOCKS_PER_SEC);


    return 0;
}