#include <iostream>
#include <iomanip>
#include <cstring>
#include <immintrin.h>
#include <chrono>

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

//循环左移函数
inline uint32_t left_rotate(uint32_t x, uint32_t n) {
    return (x << n) | (x >> (32 - n));
}

//基础S盒变换
inline uint32_t sm4_sbox(uint32_t x) {
    uint32_t out = 0;
    for (int i = 0; i < 4; i++) {
        out <<= 8;
        out |= SM4_SBOX[(x >> (24 - i * 8)) & 0xFF];
    }
    return out;
}

//线性变换L (用于加密轮函数)
inline uint32_t sm4_l_transform(uint32_t x) {
    return x ^ left_rotate(x, 2) ^ left_rotate(x, 10) ^
        left_rotate(x, 18) ^ left_rotate(x, 24);
}

//线性变换L' (用于密钥扩展)
inline uint32_t sm4_lp_transform(uint32_t x) {
    return x ^ left_rotate(x, 13) ^ left_rotate(x, 23);
}

//轮函数F
inline uint32_t sm4_round_function(uint32_t x0, uint32_t x1, uint32_t x2, uint32_t x3, uint32_t rk) {
    uint32_t t = x1 ^ x2 ^ x3 ^ rk;
    t = sm4_sbox(t);          // S盒非线性变换
    t = sm4_l_transform(t);   // 线性变换
    return x0 ^ t;        
}

class SM4Basic {
public:
    void set_key(const uint8_t key[16]) {
        uint32_t mk[4];
        for (int i = 0; i < 4; i++) {
            mk[i] = (key[i * 4] << 24) | (key[i * 4 + 1] << 16) | (key[i * 4 + 2] << 8) | key[i * 4 + 3];
        }

        //密钥扩展算法
        uint32_t k[36];
        k[0] = mk[0] ^ 0xA3B1BAC6;  
        k[1] = mk[1] ^ 0x56AA3350;  
        k[2] = mk[2] ^ 0x677D9197;  
        k[3] = mk[3] ^ 0xB27022DC;  

        // 生成轮密钥
        for (int i = 0; i < 32; i++) {
            uint32_t t = k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ CK[i];
            t = sm4_sbox(t);
            t = sm4_lp_transform(t);
            k[i + 4] = k[i] ^ t;
            rk[i] = k[i + 4];
        }
    }

    void encrypt(const uint8_t in[16], uint8_t out[16]) {
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

    void decrypt(const uint8_t in[16], uint8_t out[16]) {

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

// T-table优化实现 
class SM4TTable {
public:
    SM4TTable() {
        // 预计算T-table
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

    void encrypt(const uint8_t in[16], uint8_t out[16]) {
        uint32_t x[36];
        for (int i = 0; i < 4; i++) {
            x[i] = (in[i * 4] << 24) | (in[i * 4 + 1] << 16) | (in[i * 4 + 2] << 8) | in[i * 4 + 3];
        }

        for (int i = 0; i < 32; i++) {
            // T-table优化轮函数
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

    void decrypt(const uint8_t in[16], uint8_t out[16]) {
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

//GFNI+AVX512优化实现
#ifdef __AVX512F__
class SM4GFNI {
public:
    void set_key(const uint8_t key[16]) {
        SM4Basic sm4;
        sm4.set_key(key);
        memcpy(rk, sm4.rk, sizeof(rk));

        for (int i = 0; i < 32; i += 4) {
            rk_vec[i / 4] = _mm512_set_epi32(
                rk[i + 3], rk[i + 2], rk[i + 1], rk[i],
                rk[i + 3], rk[i + 2], rk[i + 1], rk[i],
                rk[i + 3], rk[i + 2], rk[i + 1], rk[i],
                rk[i + 3], rk[i + 2], rk[i + 1], rk[i]
            );
        }
    }

    void encrypt(const uint8_t in[16], uint8_t out[16]) {
        __m512i state = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)in));

        for (int i = 0; i < 32; i += 4) {
            state = _sm4_round(state, rk_vec[i / 4]);
        }

        state = _mm512_shuffle_epi32(state, _MM_PERM_DCBA);
        _mm_storeu_si128((__m128i*)out, _mm512_extracti32x4_epi32(state, 0));
    }

private:
    __m512i _sm4_round(__m512i state, __m512i rk) {
        const __m512i sbox_affine = _mm512_set1_epi64(0xC2CED2AEDAE0AEE0);
        const __m512i inv_affine = _mm512_set1_epi64(0x0E0507030F08060A);

        __m512i t = _mm512_rolv_epi32(state, _mm512_set_epi32(1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0));
        t = _mm512_xor_si512(t, rk);

        t = _mm512_gf2p8affineinv_epi64_epi8(t, inv_affine, 0);
        t = _mm512_gf2p8affine_epi64_epi8(t, sbox_affine, 0);

        __m512i l = _mm512_rol_epi32(t, 2);
        l = _mm512_xor_si512(l, _mm512_rol_epi32(t, 10));
        l = _mm512_xor_si512(l, _mm512_rol_epi32(t, 18));
        l = _mm512_xor_si512(l, _mm512_rol_epi32(t, 24));

        return _mm512_xor_si512(state, l);
    }

    uint32_t rk[32];
    __m512i rk_vec[8];  
};
#endif

void print_hex(const char* label, const uint8_t* data, size_t len) {
    std::cout << label << ": ";
    for (size_t i = 0; i < len; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    std::cout << std::dec << std::endl;
}

void test_sm4() {
    uint8_t key[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    uint8_t plaintext[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    uint8_t ciphertext[16];
    uint8_t decrypted[16];

    SM4Basic sm4_basic;
    sm4_basic.set_key(key);
    sm4_basic.encrypt(plaintext, ciphertext);
    print_hex("Basic Encrypt", ciphertext, 16);
    sm4_basic.decrypt(ciphertext, decrypted);
    print_hex("Basic Decrypt", decrypted, 16);

    SM4TTable sm4_ttable;
    sm4_ttable.set_key(key);
    sm4_ttable.encrypt(plaintext, ciphertext);
    print_hex("T-Table Encrypt", ciphertext, 16);
    sm4_ttable.decrypt(ciphertext, decrypted);
    print_hex("T-Table Decrypt", decrypted, 16);

#ifdef __AVX512F__

    SM4GFNI sm4_gfni;
    sm4_gfni.set_key(key);
    sm4_gfni.encrypt(plaintext, ciphertext);
    print_hex("GFNI Encrypt", ciphertext, 16);
    sm4_gfni.decrypt(ciphertext, decrypted);
    print_hex("GFNI Decrypt", decrypted, 16);
#endif
}

void benchmark_sm4() {
    const int TEST_SIZE = 16 * 1024 * 1024;  
    const int BLOCKS = TEST_SIZE / SM4_BLOCK_SIZE;

    uint8_t key[16] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                       0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 };
    uint8_t* data = new uint8_t[TEST_SIZE];
    uint8_t* out = new uint8_t[TEST_SIZE];

    memset(data, 0xAA, TEST_SIZE);

    auto run_benchmark = [&](auto& sm4, const char* name) {
        sm4.set_key(key);
        auto start = std::chrono::high_resolution_clock::now();

        for (int i = 0; i < BLOCKS; i++) {
            sm4.encrypt(data + i * SM4_BLOCK_SIZE, out + i * SM4_BLOCK_SIZE);
        }

        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        double speed = (double)TEST_SIZE / duration.count() * 1000;  

        std::cout << name << " Speed: " << std::fixed << std::setprecision(2)
            << speed << " MB/s" << std::endl;
    };

    SM4Basic sm4_basic;
    run_benchmark(sm4_basic, "Basic SM4");

    SM4TTable sm4_ttable;
    run_benchmark(sm4_ttable, "T-Table SM4");

#ifdef __AVX512F__
    SM4GFNI sm4_gfni;
    run_benchmark(sm4_gfni, "GFNI SM4");
#endif

    delete[] data;
    delete[] out;
}

int main() {
    std::cout << "SM4 Correctness Test " << std::endl;
    test_sm4();

    std::cout << "\nSM4 Performance Benchmark " << std::endl;
    benchmark_sm4();

    return 0;
}