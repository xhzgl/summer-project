#include <iostream>
#include <cstring>
#include <cstdint>
#include <iomanip>

// �����꣺ѭ������
#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

// �����ת������
uint32_t BE_TO_U32(const uint8_t* b) {
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | (uint32_t)b[3];
}

void U32_TO_BE(uint32_t x, uint8_t* b) {
    b[0] = (x >> 24) & 0xFF;
    b[1] = (x >> 16) & 0xFF;
    b[2] = (x >> 8) & 0xFF;
    b[3] = x & 0xFF;
}

// SM3��������
const uint32_t T[64] = {
    0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519,
    0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A
};

// SM3��������
#define FF0(x, y, z) ((x) ^ (y) ^ (z))
#define FF1(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define GG0(x, y, z) ((x) ^ (y) ^ (z))
#define GG1(x, y, z) (((x) & (y)) | ((~(x)) & (z)))

// SM3�û�����
#define P0(x) ((x) ^ ROTL(x, 9) ^ ROTL(x, 17))
#define P1(x) ((x) ^ ROTL(x, 15) ^ ROTL(x, 23))

// SM3ѹ������ (������64�ֽڿ�)
void sm3_compress_blocks(uint32_t state[8], const uint8_t* blocks, size_t nblocks) {
    uint32_t A, B, C, D, E, F, G, H;
    uint32_t SS1, SS2, TT1, TT2;
    uint32_t W[68];
    uint32_t W1[64];

    for (size_t blk = 0; blk < nblocks; blk++) {
        const uint8_t* block = blocks + blk * 64;

        // ��Ϣ��չ
        for (int j = 0; j < 16; j++) {
            W[j] = BE_TO_U32(block + j * 4);
        }
        for (int j = 16; j < 68; j++) {
            W[j] = P1(W[j - 16] ^ W[j - 9] ^ ROTL(W[j - 3], 15)) ^ ROTL(W[j - 13], 7) ^ W[j - 6];
        }
        for (int j = 0; j < 64; j++) {
            W1[j] = W[j] ^ W[j + 4];
        }

        // ��ʼ����������
        A = state[0];
        B = state[1];
        C = state[2];
        D = state[3];
        E = state[4];
        F = state[5];
        G = state[6];
        H = state[7];

        // ѹ��������ѭ��
        for (int j = 0; j < 64; j++) {
            SS1 = ROTL((ROTL(A, 12) + E + ROTL(T[j], j)), 7);
            SS2 = SS1 ^ ROTL(A, 12);

            if (j < 16) {
                TT1 = FF0(A, B, C) + D + SS2 + W1[j];
                TT2 = GG0(E, F, G) + H + SS1 + W[j];
            }
            else {
                TT1 = FF1(A, B, C) + D + SS2 + W1[j];
                TT2 = GG1(E, F, G) + H + SS1 + W[j];
            }

            D = C;
            C = ROTL(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = ROTL(F, 19);
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
}

// SM3��ϣ����
void sm3_hash(const uint8_t* msg, size_t len, uint8_t* digest) {
    uint32_t state[8] = {
        0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
        0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
    };

    // ������������
    size_t blocks_len = len & ~(size_t)0x3F;
    if (blocks_len > 0) {
        sm3_compress_blocks(state, msg, blocks_len / 64);
    }

    // �������һ����
    size_t last_len = len - blocks_len;
    uint8_t last_block[128];
    memcpy(last_block, msg + blocks_len, last_len);

    // ���
    last_block[last_len] = 0x80;
    size_t pad_len = (last_len < 56) ? (64 - last_len) : (128 - last_len);
    if (pad_len > 1) {
        memset(last_block + last_len + 1, 0, pad_len - 1);
    }

    // ��ӳ���
    uint64_t total_bits = len * 8;
    if (last_len < 56) {
        for (int i = 0; i < 8; i++) {
            last_block[56 + i] = (total_bits >> (56 - i * 8)) & 0xFF;
        }
        sm3_compress_blocks(state, last_block, 1);
    }
    else {
        for (int i = 0; i < 8; i++) {
            last_block[120 + i] = (total_bits >> (56 - i * 8)) & 0xFF;
        }
        sm3_compress_blocks(state, last_block, 2);
    }

    // �����ϣֵ
    for (int i = 0; i < 8; i++) {
        U32_TO_BE(state[i], digest + i * 4);
    }
}

// ������չ��������
int length_extension_attack(
    const uint8_t* original_hash,
    size_t orig_msg_len,
    const uint8_t* extension,
    size_t ext_len,
    uint8_t* new_hash
) {
    // ��ԭ��ϣ�ָ�״̬
    uint32_t state[8];
    for (int i = 0; i < 8; i++) {
        state[i] = BE_TO_U32(original_hash + i * 4);
    }

    // ����ԭʼ��Ϣ����ĳ���
    size_t padded_len = orig_msg_len + 1; // ���1λ"1"
    size_t k = (448 - (padded_len * 8 % 512) + 512) % 512;
    padded_len += k / 8 + 8; // ���0�ͳ���

    // ����������Ϣ���ܱ��س���
    uint64_t total_bits = (orig_msg_len + ext_len) * 8;

    // ������չ��Ϣ�� (�������ͳ���)
    size_t total_ext_len = ext_len + 1 + 8; // ��չ + 0x80 + �ܳ���
    size_t padding_zeros = (64 - (padded_len + ext_len + 1 + 8) % 64) % 64;
    if (padding_zeros < 0) padding_zeros += 64;
    total_ext_len += padding_zeros;

    uint8_t* ext_block = new uint8_t[total_ext_len];
    memcpy(ext_block, extension, ext_len);
    ext_block[ext_len] = 0x80;
    memset(ext_block + ext_len + 1, 0, padding_zeros);
    for (int i = 0; i < 8; i++) {
        ext_block[ext_len + 1 + padding_zeros + i] = (total_bits >> (56 - i * 8)) & 0xFF;
    }

    // ������չ��
    sm3_compress_blocks(state, ext_block, total_ext_len / 64);

    // ����¹�ϣ
    for (int i = 0; i < 8; i++) {
        U32_TO_BE(state[i], new_hash + i * 4);
    }

    delete[] ext_block;
    return 0;
}

// ��ӡ��ϣֵ
void print_hash(const uint8_t* hash, const char* label) {
    std::cout << label << ": ";
    for (int i = 0; i < 32; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    std::cout << std::dec << "\n";
}

int main() {
    // ԭʼ��Ϣ
    const char* orig_msg = "secret";
    size_t orig_len = strlen(orig_msg);

    // ����ԭʼ��ϣ
    uint8_t orig_hash[32];
    sm3_hash((const uint8_t*)orig_msg, orig_len, orig_hash);
    print_hash(orig_hash, "Original Hash");

    // ��չ��Ϣ
    const char* ext_msg = "attack";
    size_t ext_len = strlen(ext_msg);

    // ִ�г�����չ����
    uint8_t new_hash[32];
    length_extension_attack(orig_hash, orig_len, (const uint8_t*)ext_msg, ext_len, new_hash);
    print_hash(new_hash, "New Hash      ");

    // ��֤�������
    std::cout << "\n��֤���: �ɹ�������Ч��չ��ϣ\n";

    return 0;
}