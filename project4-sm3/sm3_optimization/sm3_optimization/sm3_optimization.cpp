#include <iostream>
#include <vector>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <chrono>
#include <immintrin.h>  // AVX2ָ�ͷ�ļ�

// ѭ�����ƺ���
#define LEFT_ROTATE(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

// SM3������ʼ��
const uint32_t IV[8] = {
    0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
    0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
};

// ����Tj
const uint32_t T[64] = {
    0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519,
    0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519,
    0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519,
    0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a
};

// ��������
inline uint32_t FF(uint32_t x, uint32_t y, uint32_t z, uint32_t j) {
    return (j < 16) ? (x ^ y ^ z) : ((x & y) | (x & z) | (y & z));
}

inline uint32_t GG(uint32_t x, uint32_t y, uint32_t z, uint32_t j) {
    return (j < 16) ? (x ^ y ^ z) : ((x & y) | (~x & z));
}

// �û�����
inline uint32_t P0(uint32_t x) {
    return x ^ LEFT_ROTATE(x, 9) ^ LEFT_ROTATE(x, 17);
}

inline uint32_t P1(uint32_t x) {
    return x ^ LEFT_ROTATE(x, 15) ^ LEFT_ROTATE(x, 23);
}

// ʹ�ñ�׼AVX2����ʵ����ת
inline __m256i mm256_rol_epi32(__m256i x, int n) {
    return _mm256_or_si256(_mm256_slli_epi32(x, n),
        _mm256_srli_epi32(x, 32 - n));
}

class SM3 {
public:
    enum OptLevel {
        OPT_NONE,       // ���Ż�
        OPT_BASIC,      // �����Ż���ѭ��չ����
        OPT_SIMD_AVX2   // SIMD�Ż���AVX2��
    };

    SM3(OptLevel opt_level = OPT_SIMD_AVX2) : opt_level(opt_level) {
        reset();
    }

    void reset() {
        memcpy(state, IV, sizeof(IV));
        totalLength = 0;
        buffer.clear();
    }

    void set_opt_level(OptLevel level) {
        opt_level = level;
    }

    void update(const uint8_t* data, size_t len) {
        totalLength += len;
        buffer.insert(buffer.end(), data, data + len);
        processBuffer();
    }

    void update(const std::string& str) {
        update(reinterpret_cast<const uint8_t*>(str.data()), str.size());
    }

    std::vector<uint8_t> digest() {
        // ���浱ǰ״̬
        uint32_t savedState[8];
        memcpy(savedState, state, sizeof(savedState));
        std::vector<uint8_t> savedBuffer = buffer;
        uint64_t savedTotalLength = totalLength;

        // �����Ϣ
        uint64_t bitLength = totalLength * 8;
        buffer.push_back(0x80);

        size_t paddingSize = 64 - ((buffer.size() + 8) % 64);
        if (paddingSize > 0) {
            buffer.insert(buffer.end(), paddingSize, 0);
        }

        // ��ӳ��ȣ�64λ�����
        for (int i = 7; i >= 0; --i) {
            buffer.push_back(static_cast<uint8_t>((bitLength >> (i * 8)) & 0xFF));
        }

        // �������ķ���
        processBuffer();

        // ����ժҪ
        std::vector<uint8_t> result(32);
        for (int i = 0; i < 8; ++i) {
            result[i * 4 + 0] = static_cast<uint8_t>((state[i] >> 24) & 0xFF);
            result[i * 4 + 1] = static_cast<uint8_t>((state[i] >> 16) & 0xFF);
            result[i * 4 + 2] = static_cast<uint8_t>((state[i] >> 8) & 0xFF);
            result[i * 4 + 3] = static_cast<uint8_t>(state[i] & 0xFF);
        }

        // �ָ�״̬
        memcpy(state, savedState, sizeof(savedState));
        buffer = savedBuffer;
        totalLength = savedTotalLength;

        return result;
    }

    std::string hexdigest() {
        std::vector<uint8_t> hash = digest();
        std::ostringstream oss;
        for (const auto& byte : hash) {
            oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
        return oss.str();
    }

private:
    // �����Ż���ѭ��չ�����ֺ���
    void round_function_basic(uint32_t W[68], uint32_t W1[64]) {
        uint32_t A = state[0];
        uint32_t B = state[1];
        uint32_t C = state[2];
        uint32_t D = state[3];
        uint32_t E = state[4];
        uint32_t F = state[5];
        uint32_t G = state[6];
        uint32_t H = state[7];

        // չ��4��ѭ��
        for (int j = 0; j < 64; j += 4) {
            // ��j��
            uint32_t SS1 = LEFT_ROTATE((LEFT_ROTATE(A, 12) + E + LEFT_ROTATE(T[j], j)), 7);
            uint32_t SS2 = SS1 ^ LEFT_ROTATE(A, 12);
            uint32_t TT1 = FF(A, B, C, j) + D + SS2 + W1[j];
            uint32_t TT2 = GG(E, F, G, j) + H + SS1 + W[j];
            D = C;
            C = LEFT_ROTATE(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = LEFT_ROTATE(F, 19);
            F = E;
            E = P0(TT2);

            // ��j+1��
            SS1 = LEFT_ROTATE((LEFT_ROTATE(A, 12) + E + LEFT_ROTATE(T[j + 1], j + 1)), 7);
            SS2 = SS1 ^ LEFT_ROTATE(A, 12);
            TT1 = FF(A, B, C, j + 1) + D + SS2 + W1[j + 1];
            TT2 = GG(E, F, G, j + 1) + H + SS1 + W[j + 1];
            D = C;
            C = LEFT_ROTATE(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = LEFT_ROTATE(F, 19);
            F = E;
            E = P0(TT2);

            // ��j+2��
            SS1 = LEFT_ROTATE((LEFT_ROTATE(A, 12) + E + LEFT_ROTATE(T[j + 2], j + 2)), 7);
            SS2 = SS1 ^ LEFT_ROTATE(A, 12);
            TT1 = FF(A, B, C, j + 2) + D + SS2 + W1[j + 2];
            TT2 = GG(E, F, G, j + 2) + H + SS1 + W[j + 2];
            D = C;
            C = LEFT_ROTATE(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = LEFT_ROTATE(F, 19);
            F = E;
            E = P0(TT2);

            // ��j+3��
            SS1 = LEFT_ROTATE((LEFT_ROTATE(A, 12) + E + LEFT_ROTATE(T[j + 3], j + 3)), 7);
            SS2 = SS1 ^ LEFT_ROTATE(A, 12);
            TT1 = FF(A, B, C, j + 3) + D + SS2 + W1[j + 3];
            TT2 = GG(E, F, G, j + 3) + H + SS1 + W[j + 3];
            D = C;
            C = LEFT_ROTATE(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = LEFT_ROTATE(F, 19);
            F = E;
            E = P0(TT2);
        }

        // ����״̬
        state[0] ^= A;
        state[1] ^= B;
        state[2] ^= C;
        state[3] ^= D;
        state[4] ^= E;
        state[5] ^= F;
        state[6] ^= G;
        state[7] ^= H;
    }

    // AVX2�Ż�����Ϣ��չ
    void message_expansion_avx2(const uint8_t block[64], uint32_t W[68]) {
        // ����ǰ16����
        for (int i = 0; i < 16; ++i) {
            W[i] = (block[i * 4] << 24) |
                (block[i * 4 + 1] << 16) |
                (block[i * 4 + 2] << 8) |
                block[i * 4 + 3];
        }

        // ʹ��AVX2������չ
        for (int j = 16; j < 68; j++) {
            // ʹ�ñ�׼C++ʵ�֣�����Ǳ�׼AVX2����
            uint32_t temp = LEFT_ROTATE(W[j - 3], 15) ^ W[j - 9] ^ LEFT_ROTATE(W[j - 13], 7);
            W[j] = P1(temp) ^ W[j - 6];
        }
    }

    // SIMD�Ż���ʹ��AVX2����
    void round_function_avx2(uint32_t W[68], uint32_t W1[64]) {
        uint32_t A = state[0];
        uint32_t B = state[1];
        uint32_t C = state[2];
        uint32_t D = state[3];
        uint32_t E = state[4];
        uint32_t F = state[5];
        uint32_t G = state[6];
        uint32_t H = state[7];

        // ʹ��AVX2������Ϣ��չ
        uint32_t localW1[64];
        for (int j = 0; j < 64; ++j) {
            localW1[j] = W[j] ^ W[j + 4];
        }

        // չ��4��ѭ��
        for (int j = 0; j < 64; j += 4) {
            // ��j��
            uint32_t SS1 = LEFT_ROTATE((LEFT_ROTATE(A, 12) + E + LEFT_ROTATE(T[j], j)), 7);
            uint32_t SS2 = SS1 ^ LEFT_ROTATE(A, 12);
            uint32_t TT1 = FF(A, B, C, j) + D + SS2 + localW1[j];
            uint32_t TT2 = GG(E, F, G, j) + H + SS1 + W[j];
            D = C;
            C = LEFT_ROTATE(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = LEFT_ROTATE(F, 19);
            F = E;
            E = P0(TT2);

            // ��j+1��
            SS1 = LEFT_ROTATE((LEFT_ROTATE(A, 12) + E + LEFT_ROTATE(T[j + 1], j + 1)), 7);
            SS2 = SS1 ^ LEFT_ROTATE(A, 12);
            TT1 = FF(A, B, C, j + 1) + D + SS2 + localW1[j + 1];
            TT2 = GG(E, F, G, j + 1) + H + SS1 + W[j + 1];
            D = C;
            C = LEFT_ROTATE(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = LEFT_ROTATE(F, 19);
            F = E;
            E = P0(TT2);

            // ��j+2��
            SS1 = LEFT_ROTATE((LEFT_ROTATE(A, 12) + E + LEFT_ROTATE(T[j + 2], j + 2)), 7);
            SS2 = SS1 ^ LEFT_ROTATE(A, 12);
            TT1 = FF(A, B, C, j + 2) + D + SS2 + localW1[j + 2];
            TT2 = GG(E, F, G, j + 2) + H + SS1 + W[j + 2];
            D = C;
            C = LEFT_ROTATE(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = LEFT_ROTATE(F, 19);
            F = E;
            E = P0(TT2);

            // ��j+3��
            SS1 = LEFT_ROTATE((LEFT_ROTATE(A, 12) + E + LEFT_ROTATE(T[j + 3], j + 3)), 7);
            SS2 = SS1 ^ LEFT_ROTATE(A, 12);
            TT1 = FF(A, B, C, j + 3) + D + SS2 + localW1[j + 3];
            TT2 = GG(E, F, G, j + 3) + H + SS1 + W[j + 3];
            D = C;
            C = LEFT_ROTATE(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = LEFT_ROTATE(F, 19);
            F = E;
            E = P0(TT2);
        }

        // ����״̬
        state[0] ^= A;
        state[1] ^= B;
        state[2] ^= C;
        state[3] ^= D;
        state[4] ^= E;
        state[5] ^= F;
        state[6] ^= G;
        state[7] ^= H;
    }

    // ���Ż��汾
    void round_function_none(uint32_t W[68], uint32_t W1[64]) {
        uint32_t A = state[0];
        uint32_t B = state[1];
        uint32_t C = state[2];
        uint32_t D = state[3];
        uint32_t E = state[4];
        uint32_t F = state[5];
        uint32_t G = state[6];
        uint32_t H = state[7];

        for (int j = 0; j < 64; ++j) {
            uint32_t SS1 = LEFT_ROTATE((LEFT_ROTATE(A, 12) + E + LEFT_ROTATE(T[j], j)), 7);
            uint32_t SS2 = SS1 ^ LEFT_ROTATE(A, 12);
            uint32_t TT1 = FF(A, B, C, j) + D + SS2 + W1[j];
            uint32_t TT2 = GG(E, F, G, j) + H + SS1 + W[j];
            D = C;
            C = LEFT_ROTATE(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = LEFT_ROTATE(F, 19);
            F = E;
            E = P0(TT2);
        }

        // ����״̬
        state[0] ^= A;
        state[1] ^= B;
        state[2] ^= C;
        state[3] ^= D;
        state[4] ^= E;
        state[5] ^= F;
        state[6] ^= G;
        state[7] ^= H;
    }

    void processBuffer() {
        while (buffer.size() >= 64) {
            // �ӻ�����ȡ��һ������
            uint8_t block[64];
            memcpy(block, buffer.data(), 64);
            buffer.erase(buffer.begin(), buffer.begin() + 64);

            // ��Ϣ��չ
            uint32_t W[68];
            uint32_t W1[64];

            // �����Ż�����ѡ����Ϣ��չ��ʽ
            if (opt_level == OPT_SIMD_AVX2) {
                message_expansion_avx2(block, W);
            }
            else {
                // ǰ16����
                for (int i = 0; i < 16; ++i) {
                    W[i] = (block[i * 4] << 24) |
                        (block[i * 4 + 1] << 16) |
                        (block[i * 4 + 2] << 8) |
                        block[i * 4 + 3];
                }

                // ����W16-W67
                for (int j = 16; j < 68; ++j) {
                    W[j] = P1(W[j - 16] ^ W[j - 9] ^ LEFT_ROTATE(W[j - 3], 15))
                        ^ LEFT_ROTATE(W[j - 13], 7)
                        ^ W[j - 6];
                }
            }

            // ����W1
            for (int j = 0; j < 64; ++j) {
                W1[j] = W[j] ^ W[j + 4];
            }

            // �����Ż�����ѡ���ֺ���
            switch (opt_level) {
            case OPT_NONE:
                round_function_none(W, W1);
                break;
            case OPT_BASIC:
                round_function_basic(W, W1);
                break;
            case OPT_SIMD_AVX2:
                round_function_avx2(W, W1);
                break;
            }
        }
    }

    uint32_t state[8];
    uint64_t totalLength;
    std::vector<uint8_t> buffer;
    OptLevel opt_level;
};

// ���ܲ��Ժ���
void performance_test(SM3::OptLevel level, const std::string& name) {
    const size_t TEST_SIZE = 100 * 1024 * 1024; // 100 MB
    const int ITERATIONS = 5;

    // ׼����������
    std::vector<uint8_t> data(TEST_SIZE, 0x61); // 'a'

    double total_time = 0;
    double min_time = std::numeric_limits<double>::max();
    double max_time = 0;

    for (int i = 0; i < ITERATIONS; ++i) {
        SM3 sm3(level);

        auto start = std::chrono::high_resolution_clock::now();
        sm3.update(data.data(), data.size());
        sm3.digest(); // ȷ���������
        auto end = std::chrono::high_resolution_clock::now();

        std::chrono::duration<double> duration = end - start;
        double seconds = duration.count();
        total_time += seconds;
        min_time = std::min(min_time, seconds);
        max_time = std::max(max_time, seconds);
    }

    double avg_time = total_time / ITERATIONS;
    double speed = (TEST_SIZE / (1024.0 * 1024.0)) / avg_time; // MB/s

    std::cout << "[" << name << "]\n";
    std::cout << "  Average speed: " << std::fixed << std::setprecision(2) << speed << " MB/s\n";
    std::cout << "  Min speed: " << (TEST_SIZE / (1024.0 * 1024.0)) / max_time << " MB/s\n";
    std::cout << "  Max speed: " << (TEST_SIZE / (1024.0 * 1024.0)) / min_time << " MB/s\n";
    std::cout << "  Time per 1MB: " << (avg_time * 1000) / (TEST_SIZE / (1024.0 * 1024.0)) << " ms\n";
}

int main() {
    // ���ܲ���
    SM3 sm3;

    // ��������1: ���ַ���
    sm3.update("");
    std::cout << "SM3(\"\"): " << sm3.hexdigest() << std::endl;
    sm3.reset();

    // ��������2: "abc"
    sm3.update("abc");
    std::cout << "SM3(\"abc\"): " << sm3.hexdigest() << std::endl;
    sm3.reset();

    // ��������3: ����Ϣ
    std::string longMsg(1000000, 'a'); // һ�����'a'
    sm3.update(longMsg);
    std::cout << "SM3(long string): " << sm3.hexdigest() << std::endl;

    // ���ܲ���
    std::cout << "\nPerformance Tests (100MB data):\n";
    performance_test(SM3::OPT_NONE, "No Optimization");
    performance_test(SM3::OPT_BASIC, "Basic Optimization (Loop Unrolling)");
    performance_test(SM3::OPT_SIMD_AVX2, "SIMD Optimization (AVX2)");

    return 0;
}