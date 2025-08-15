#include <iostream>
#include <iomanip>
#include <cstring>
#include <immintrin.h>
#include <chrono>
#include <vector>
#include <stdexcept>


const uint32_t SM4_BLOCK_SIZE = 16;  
const uint32_t SM4_NUM_ROUNDS = 32;  

const uint8_t SM4_SBOX[256] = {
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

const uint32_t CK[32] = {
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
};

inline uint32_t left_rotate(uint32_t x, uint32_t n) {
    return (x << n) | (x >> (32 - n));
}

inline uint32_t sm4_sbox(uint32_t x) {
    uint32_t out = 0;
    for (int i = 0; i < 4; i++) {
        out <<= 8;
        out |= SM4_SBOX[(x >> (24 - i * 8)) & 0xFF];
    }
    return out;
}

inline uint32_t sm4_l_transform(uint32_t x) {
    return x ^ left_rotate(x, 2) ^ left_rotate(x, 10) ^
        left_rotate(x, 18) ^ left_rotate(x, 24);
}

inline uint32_t sm4_lp_transform(uint32_t x) {
    return x ^ left_rotate(x, 13) ^ left_rotate(x, 23);
}

inline uint32_t sm4_round_function(uint32_t x0, uint32_t x1, uint32_t x2, uint32_t x3, uint32_t rk) {
    uint32_t t = x1 ^ x2 ^ x3 ^ rk;
    t = sm4_sbox(t);          
    t = sm4_l_transform(t);   
    return x0 ^ t;            
}

//基础SM4实现
class SM4Basic {
public:
    void set_key(const uint8_t key[16]) {
        uint32_t mk[4];
        for (int i = 0; i < 4; i++) {
            mk[i] = (key[i * 4] << 24) | (key[i * 4 + 1] << 16) | (key[i * 4 + 2] << 8) | key[i * 4 + 3];
        }

        uint32_t k[36];
        k[0] = mk[0] ^ 0xA3B1BAC6; 
        k[1] = mk[1] ^ 0x56AA3350;  
        k[2] = mk[2] ^ 0x677D9197;  
        k[3] = mk[3] ^ 0xB27022DC;  

        for (int i = 0; i < 32; i++) {
            uint32_t t = k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ CK[i];
            t = sm4_sbox(t);
            t = sm4_lp_transform(t);
            k[i + 4] = k[i] ^ t;
            rk[i] = k[i + 4];
        }
    }

    void encrypt_block(const uint8_t in[16], uint8_t out[16]) {
        uint32_t x[36];
        for (int i = 0; i < 4; i++) {
            x[i] = (in[i * 4] << 24) | (in[i * 4 + 1] << 16) | (in[i * 4 + 2] << 8) | in[i * 4 + 3];
        }

        for (int i = 0; i < 32; i++) {
            x[i + 4] = sm4_round_function(x[i], x[i + 1], x[i + 2], x[i + 3], rk[i]);
        }

        for (int i = 0; i < 4; i++) {
            uint32_t word = x[35 - i];
            out[i * 4] = (word >> 24) & 0xFF;
            out[i * 4 + 1] = (word >> 16) & 0xFF;
            out[i * 4 + 2] = (word >> 8) & 0xFF;
            out[i * 4 + 3] = word & 0xFF;
        }
    }

    void encrypt_ecb(const uint8_t* in, uint8_t* out, size_t blocks) {
        for (size_t i = 0; i < blocks; i++) {
            encrypt_block(in + i * SM4_BLOCK_SIZE, out + i * SM4_BLOCK_SIZE);
        }
    }

    void decrypt_block(const uint8_t in[16], uint8_t out[16]) {
        uint32_t rev_rk[32];
        for (int i = 0; i < 32; i++) {
            rev_rk[i] = rk[31 - i];
        }

        uint32_t x[36];
        for (int i = 0; i < 4; i++) {
            x[i] = (in[i * 4] << 24) | (in[i * 4 + 1] << 16) | (in[i * 4 + 2] << 8) | in[i * 4 + 3];
        }

        for (int i = 0; i < 32; i++) {
            x[i + 4] = sm4_round_function(x[i], x[i + 1], x[i + 2], x[i + 3], rev_rk[i]);
        }

        for (int i = 0; i < 4; i++) {
            uint32_t word = x[35 - i];
            out[i * 4] = (word >> 24) & 0xFF;
            out[i * 4 + 1] = (word >> 16) & 0xFF;
            out[i * 4 + 2] = (word >> 8) & 0xFF;
            out[i * 4 + 3] = word & 0xFF;
        }
    }

private:
    uint32_t rk[32]; 
};

//  T-table优化SM4实现 
class SM4TTable {
public:
    SM4TTable() {

        for (int i = 0; i < 256; i++) {
            uint32_t s = SM4_SBOX[i];
            T0[i] = s ^ left_rotate(s, 2) ^ left_rotate(s, 10) ^
                left_rotate(s, 18) ^ left_rotate(s, 24);
            T1[i] = left_rotate(T0[i], 8);
            T2[i] = left_rotate(T0[i], 16);
            T3[i] = left_rotate(T0[i], 24);
        }
    }

    void set_key(const uint8_t key[16]) {

        SM4Basic sm4;
        sm4.set_key(key);
        memcpy(rk, sm4.rk, sizeof(rk));
    }

    void encrypt_block(const uint8_t in[16], uint8_t out[16]) {
        uint32_t x[36];
        for (int i = 0; i < 4; i++) {
            x[i] = (in[i * 4] << 24) | (in[i * 4 + 1] << 16) | (in[i * 4 + 2] << 8) | in[i * 4 + 3];
        }

        for (int i = 0; i < 32; i++) {
     
            uint32_t t = x[i + 1] ^ x[i + 2] ^ x[i + 3] ^ rk[i];
            x[i + 4] = x[i] ^ T0[(t >> 24) & 0xFF] ^
                T1[(t >> 16) & 0xFF] ^
                T2[(t >> 8) & 0xFF] ^
                T3[t & 0xFF];
        }

        for (int i = 0; i < 4; i++) {
            uint32_t word = x[35 - i];
            out[i * 4] = (word >> 24) & 0xFF;
            out[i * 4 + 1] = (word >> 16) & 0xFF;
            out[i * 4 + 2] = (word >> 8) & 0xFF;
            out[i * 4 + 3] = word & 0xFF;
        }
    }

    void encrypt_ecb(const uint8_t* in, uint8_t* out, size_t blocks) {
        for (size_t i = 0; i < blocks; i++) {
            encrypt_block(in + i * SM4_BLOCK_SIZE, out + i * SM4_BLOCK_SIZE);
        }
    }

    void decrypt_block(const uint8_t in[16], uint8_t out[16]) {
        uint32_t rev_rk[32];
        for (int i = 0; i < 32; i++) {
            rev_rk[i] = rk[31 - i];
        }

        uint32_t x[36];
        for (int i = 0; i < 4; i++) {
            x[i] = (in[i * 4] << 24) | (in[i * 4 + 1] << 16) | (in[i * 4 + 2] << 8) | in[i * 4 + 3];
        }

        for (int i = 0; i < 32; i++) {
            uint32_t t = x[i + 1] ^ x[i + 2] ^ x[i + 3] ^ rev_rk[i];
            x[i + 4] = x[i] ^ T0[(t >> 24) & 0xFF] ^
                T1[(t >> 16) & 0xFF] ^
                T2[(t >> 8) & 0xFF] ^
                T3[t & 0xFF];
        }

        for (int i = 0; i < 4; i++) {
            uint32_t word = x[35 - i];
            out[i * 4] = (word >> 24) & 0xFF;
            out[i * 4 + 1] = (word >> 16) & 0xFF;
            out[i * 4 + 2] = (word >> 8) & 0xFF;
            out[i * 4 + 3] = word & 0xFF;
        }
    }

private:
    uint32_t rk[32];
    uint32_t T0[256], T1[256], T2[256], T3[256];  // T-table
};

// GCM核心功能实现
class SM4_GCM {
public:

    SM4_GCM(SM4Basic& cipher) : sm4(cipher) { init_gcm(); }
    SM4_GCM(SM4TTable& cipher) : sm4(cipher) { init_gcm(); }

    void set_key(const uint8_t key[16]) {
        sm4.set_key(key);

        //计算GHASH密钥H = SM4(0^128)
        uint8_t zero_block[16] = { 0 };
        sm4.encrypt_block(zero_block, H);
    }

    //GCM加密和认证
    void encrypt(const uint8_t* plaintext, size_t len,
        const uint8_t* iv, size_t iv_len,
        const uint8_t* aad, size_t aad_len,
        uint8_t* ciphertext,
        uint8_t tag[16]) {
        //初始化计数器
        init_counter(iv, iv_len);

        //处理附加认证数据(AAD)
        process_aad(aad, aad_len);

        //加密数据
        encrypt_data(plaintext, len, ciphertext);

        //计算认证标签
        compute_tag(tag, len, aad_len);
    }

    //GCM解密和验证
    bool decrypt(const uint8_t* ciphertext, size_t len,
        const uint8_t* iv, size_t iv_len,
        const uint8_t* aad, size_t aad_len,
        uint8_t* plaintext,
        const uint8_t tag[16]) {
        init_counter(iv, iv_len);
        process_aad(aad, aad_len);
        decrypt_data(ciphertext, len, plaintext);

        return verify_tag(tag, len, aad_len);
    }

private:
    //封装SM4实现
    struct SM4Wrapper {
        SM4Basic basic;
        SM4TTable ttable;
        bool use_ttable;

        SM4Wrapper(SM4Basic& c) : basic(c), use_ttable(false) {}
        SM4Wrapper(SM4TTable& c) : ttable(c), use_ttable(true) {}

        void set_key(const uint8_t key[16]) {
            use_ttable ? ttable.set_key(key) : basic.set_key(key);
        }

        void encrypt_block(const uint8_t in[16], uint8_t out[16]) {
            use_ttable ? ttable.encrypt_block(in, out) : basic.encrypt_block(in, out);
        }

        void encrypt_ecb(const uint8_t* in, uint8_t* out, size_t blocks) {
            use_ttable ? ttable.encrypt_ecb(in, out, blocks) : basic.encrypt_ecb(in, out, blocks);
        }
    };

    SM4Wrapper sm4;
    uint8_t H[16]; 
    uint8_t J0[16]; 
    uint8_t EK0[16]; 
    uint64_t lenA;   
    uint64_t lenC;  
    uint8_t buffer[16] = { 0 };
    size_t buffer_len = 0;    

    void init_gcm() {
        memset(buffer, 0, sizeof(buffer));
        buffer_len = 0;
        lenA = 0;
        lenC = 0;
    }

    void init_counter(const uint8_t* iv, size_t iv_len) {
        if (iv_len == 12) {
           
            memcpy(J0, iv, 12);
            memset(J0 + 12, 0, 3);
            J0[15] = 0x01;
        }
        else {
            
            ghash(iv, iv_len, J0);

          
            uint8_t len_block[16];
            memset(len_block, 0, 16);
            uint64_t iv_bits = iv_len * 8;
            len_block[8] = (iv_bits >> 56) & 0xFF;
            len_block[9] = (iv_bits >> 48) & 0xFF;
            len_block[10] = (iv_bits >> 40) & 0xFF;
            len_block[11] = (iv_bits >> 32) & 0xFF;
            len_block[12] = (iv_bits >> 24) & 0xFF;
            len_block[13] = (iv_bits >> 16) & 0xFF;
            len_block[14] = (iv_bits >> 8) & 0xFF;
            len_block[15] = iv_bits & 0xFF;

            ghash_block(J0, len_block);
        }

        sm4.encrypt_block(J0, EK0);
    }

    void process_aad(const uint8_t* aad, size_t aad_len) {
        if (aad_len > 0) {
            ghash(aad, aad_len, buffer);
        }
        lenA = aad_len * 8;
    }

    void encrypt_data(const uint8_t* plaintext, size_t len, uint8_t* ciphertext) {
        ctr_crypt(plaintext, len, ciphertext);
        lenC = len * 8;
        ghash(ciphertext, len, buffer);
    }

    void decrypt_data(const uint8_t* ciphertext, size_t len, uint8_t* plaintext) {
        ghash(ciphertext, len, buffer);

        lenC = len * 8;
        ctr_crypt(ciphertext, len, plaintext);
    }

    //CTR模式加解密
    void ctr_crypt(const uint8_t* input, size_t len, uint8_t* output) {
        uint8_t counter[16];
        memcpy(counter, J0, 16);

        uint8_t keystream[16];
        size_t pos = 0;

        while (len - pos >= 16) {
            increment_counter(counter);

            sm4.encrypt_block(counter, keystream);

            for (int i = 0; i < 16; i++) {
                output[pos + i] = input[pos + i] ^ keystream[i];
            }

            pos += 16;
        }

        if (len - pos > 0) {
            increment_counter(counter);
            sm4.encrypt_block(counter, keystream);

            for (size_t i = 0; i < len - pos; i++) {
                output[pos + i] = input[pos + i] ^ keystream[i];
            }
        }
    }

    void increment_counter(uint8_t counter[16]) {
        for (int i = 15; i >= 0; i--) {
            if (++counter[i] != 0) break;
        }
    }

    void compute_tag(uint8_t tag[16], size_t data_len, size_t aad_len) {

        uint8_t len_block[16];
        memset(len_block, 0, 16);

        uint64_t lenA_bits = lenA;
        len_block[0] = (lenA_bits >> 56) & 0xFF;
        len_block[1] = (lenA_bits >> 48) & 0xFF;
        len_block[2] = (lenA_bits >> 40) & 0xFF;
        len_block[3] = (lenA_bits >> 32) & 0xFF;
        len_block[4] = (lenA_bits >> 24) & 0xFF;
        len_block[5] = (lenA_bits >> 16) & 0xFF;
        len_block[6] = (lenA_bits >> 8) & 0xFF;
        len_block[7] = lenA_bits & 0xFF;

        uint64_t lenC_bits = lenC;
        len_block[8] = (lenC_bits >> 56) & 0xFF;
        len_block[9] = (lenC_bits >> 48) & 0xFF;
        len_block[10] = (lenC_bits >> 40) & 0xFF;
        len_block[11] = (lenC_bits >> 32) & 0xFF;
        len_block[12] = (lenC_bits >> 24) & 0xFF;
        len_block[13] = (lenC_bits >> 16) & 0xFF;
        len_block[14] = (lenC_bits >> 8) & 0xFF;
        len_block[15] = lenC_bits & 0xFF;

        ghash_block(buffer, len_block);

        uint8_t S[16];
        memcpy(S, buffer, 16);


        for (int i = 0; i < 16; i++) {
            tag[i] = S[i] ^ EK0[i];
        }
    }


    bool verify_tag(const uint8_t tag[16], size_t data_len, size_t aad_len) {
        uint8_t computed_tag[16];
        compute_tag(computed_tag, data_len, aad_len);
        return memcmp(tag, computed_tag, 16) == 0;
    }

    //GHASH实现 
    void ghash(const uint8_t* data, size_t len, uint8_t result[16]) {

        size_t full_blocks = len / 16;
        if (full_blocks > 0) {
            ghash_blocks(data, full_blocks, result);
            data += full_blocks * 16;
            len -= full_blocks * 16;
        }


        if (len > 0) {
            uint8_t block[16] = { 0 };
            memcpy(block, data, len);
            ghash_block(result, block);
        }
    }


    void ghash_block(uint8_t x[16], const uint8_t y[16]) {

        for (int i = 0; i < 16; i++) {
            x[i] ^= y[i];
        }

        gf_mult(x, H, x);
    }

    void gf_mult(const uint8_t x[16], const uint8_t y[16], uint8_t z[16]) {
        uint8_t v[16];
        memcpy(v, y, 16);
        memset(z, 0, 16);

        for (int i = 0; i < 16; i++) {
            for (int j = 7; j >= 0; j--) {
                uint8_t byte = x[i];
                if (byte & (1 << j)) {
                    for (int k = 0; k < 16; k++) {
                        z[k] ^= v[k];
                    }
                }

                uint8_t carry = v[0] & 0x80;
                for (int k = 0; k < 15; k++) {
                    v[k] = (v[k] << 1) | ((v[k + 1] & 0x80) >> 7);
                }
                v[15] = v[15] << 1;

                if (carry) {
                    v[15] ^= 0x87;
                }
            }
        }
    }

    void ghash_blocks(const uint8_t* data, size_t blocks, uint8_t result[16]) {
        uint8_t H_table[16][16];
        precompute_H_table(H, H_table);

        for (size_t i = 0; i < blocks; i++) {
            for (int j = 0; j < 16; j++) {
                result[j] ^= data[i * 16 + j];
            }

            gf_mult_with_table(result, H_table, result);
        }
    }


    void precompute_H_table(const uint8_t H[16], uint8_t H_table[16][16]) {
        uint8_t current[16];
        memcpy(current, H, 16);


        memcpy(H_table[1], H, 16);

        for (int i = 2; i < 16; i++) {
            gf_mult(current, H, current);
            memcpy(H_table[i], current, 16);
        }
    }

    //使用预计算表的GF乘法
    void gf_mult_with_table(uint8_t x[16], const uint8_t H_table[16][16], uint8_t z[16]) {
        uint8_t temp[16] = { 0 };

        for (int i = 0; i < 16; i++) {
            uint8_t low = x[i] & 0x0F;
            uint8_t high = (x[i] >> 4) & 0x0F;

            if (high != 0) {
                const uint8_t* H_high = H_table[high];
                for (int j = 0; j < 16; j++) {
                    temp[j] ^= H_high[j];
                }
            }

            if (low != 0) {
                const uint8_t* H_low = H_table[low];
                for (int j = 0; j < 16; j++) {
                    temp[j] ^= H_low[j];
                }
            }

 
            uint8_t carry = temp[0] & 0x80;
            for (int j = 0; j < 15; j++) {
                temp[j] = (temp[j] << 1) | ((temp[j + 1] & 0x80) >> 7);
            }
            temp[15] = temp[15] << 1;

            if (carry) {
                temp[15] ^= 0x87;
            }
        }

        memcpy(z, temp, 16);
    }

    // 使用PCLMULQDQ指令优化GHASH
#ifdef __PCLMUL__
    void gf_mult_pclmul(const uint8_t x[16], const uint8_t y[16], uint8_t z[16]) {
        __m128i a = _mm_loadu_si128((const __m128i*)x);
        __m128i b = _mm_loadu_si128((const __m128i*)y);

        __m128i c = _mm_clmulepi64_si128(a, b, 0x00);
        __m128i d = _mm_clmulepi64_si128(a, b, 0x01);
        __m128i e = _mm_clmulepi64_si128(a, b, 0x10);
        __m128i f = _mm_clmulepi64_si128(a, b, 0x11);

        d = _mm_xor_si128(d, e);
        e = _mm_slli_si128(d, 8);
        d = _mm_srli_si128(d, 8);
        c = _mm_xor_si128(c, e);
        f = _mm_xor_si128(f, d);

        __m128i mod = _mm_set_epi64x(0, 0x87);
        __m128i g = _mm_clmulepi64_si128(f, mod, 0x00);
        __m128i h = _mm_clmulepi64_si128(f, mod, 0x10);
        h = _mm_xor_si128(h, g);
        h = _mm_xor_si128(h, f);
        __m128i result = _mm_xor_si128(c, h);

        _mm_storeu_si128((__m128i*)z, result);
    }
#endif
};

void print_hex(const char* label, const uint8_t* data, size_t len) {
    std::cout << label << ": ";
    for (size_t i = 0; i < len; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    std::cout << std::dec << std::endl;
}

void test_sm4_gcm() {
    uint8_t key[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    uint8_t iv[12] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B
    };

    uint8_t aad[20] = {
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
        0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
        0x00, 0x11, 0x22, 0x33
    };

    uint8_t plaintext[32] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00
    };

    uint8_t ciphertext[32];
    uint8_t tag[16];
    uint8_t decrypted[32];

    SM4Basic sm4_basic;
    SM4_GCM gcm_basic(sm4_basic);

    std::cout << "=== Basic SM4-GCM Test ===" << std::endl;
    gcm_basic.set_key(key);
    gcm_basic.encrypt(plaintext, 32, iv, 12, aad, 20, ciphertext, tag);
    print_hex("Ciphertext", ciphertext, 32);
    print_hex("Tag", tag, 16);

    bool valid = gcm_basic.decrypt(ciphertext, 32, iv, 12, aad, 20, decrypted, tag);
    std::cout << "Decryption valid: " << (valid ? "true" : "false") << std::endl;
    print_hex("Decrypted", decrypted, 32);

    SM4TTable sm4_ttable;
    SM4_GCM gcm_ttable(sm4_ttable);

    std::cout << "\n=== T-table SM4-GCM Test ===" << std::endl;
    gcm_ttable.set_key(key);
    gcm_ttable.encrypt(plaintext, 32, iv, 12, aad, 20, ciphertext, tag);
    print_hex("Ciphertext", ciphertext, 32);
    print_hex("Tag", tag, 16);

    valid = gcm_ttable.decrypt(ciphertext, 32, iv, 12, aad, 20, decrypted, tag);
    std::cout << "Decryption valid: " << (valid ? "true" : "false") << std::endl;
    print_hex("Decrypted", decrypted, 32);
}

void benchmark_sm4_gcm() {
    const size_t TEST_SIZE = 16 * 1024 * 1024;

    uint8_t key[16] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                       0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 };
    uint8_t iv[12] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                      0x08, 0x09, 0x0A, 0x0B };
    uint8_t aad[20] = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
                       0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
                       0x00, 0x11, 0x22, 0x33 };

    uint8_t* plaintext = new uint8_t[TEST_SIZE];
    uint8_t* ciphertext = new uint8_t[TEST_SIZE];
    uint8_t* decrypted = new uint8_t[TEST_SIZE];
    uint8_t tag[16];


    memset(plaintext, 0xAA, TEST_SIZE);

    auto run_benchmark = [&](auto& gcm, const char* name) {
        gcm.set_key(key);
        auto start = std::chrono::high_resolution_clock::now();

        gcm.encrypt(plaintext, TEST_SIZE, iv, 12, aad, 20, ciphertext, tag);

        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        double speed = (double)TEST_SIZE / duration.count() * 1000; 

        std::cout << name << " Encryption Speed: " << std::fixed << std::setprecision(2)
            << speed << " MB/s" << std::endl;

        start = std::chrono::high_resolution_clock::now();
        bool valid = gcm.decrypt(ciphertext, TEST_SIZE, iv, 12, aad, 20, decrypted, tag);
        end = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        speed = (double)TEST_SIZE / duration.count() * 1000;

        std::cout << name << " Decryption Speed: " << speed << " MB/s" << std::endl;
        std::cout << "Tag valid: " << (valid ? "true" : "false") << std::endl;
    };

    SM4Basic sm4_basic;
    SM4_GCM gcm_basic(sm4_basic);
    std::cout << "\n=== Basic SM4-GCM Benchmark ===" << std::endl;
    run_benchmark(gcm_basic, "Basic");

    SM4TTable sm4_ttable;
    SM4_GCM gcm_ttable(sm4_ttable);
    std::cout << "\n=== T-table SM4-GCM Benchmark ===" << std::endl;
    run_benchmark(gcm_ttable, "T-table");

    delete[] plaintext;
    delete[] ciphertext;
    delete[] decrypted;
}

int main() {
    std::cout << "=== SM4-GCM Correctness Test ===" << std::endl;
    test_sm4_gcm();

    std::cout << "\n=== SM4-GCM Performance Benchmark ===" << std::endl;
    benchmark_sm4_gcm();

    return 0;
}