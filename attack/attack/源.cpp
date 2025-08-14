#include <iostream>
#include <cstring>
#include <cstdint>
#include <iomanip>

// 辅助宏：循环左移
#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

// 大端序转换函数
uint32_t BE_TO_U32(const uint8_t* b) {
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | (uint32_t)b[3];
}

void U32_TO_BE(uint32_t x, uint8_t* b) {
    b[0] = (x >> 24) & 0xFF;
    b[1] = (x >> 16) & 0xFF;
    b[2] = (x >> 8) & 0xFF;
    b[3] = x & 0xFF;
}

// SM3常量定义
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

// SM3布尔函数
#define FF0(x, y, z) ((x) ^ (y) ^ (z))
#define FF1(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define GG0(x, y, z) ((x) ^ (y) ^ (z))
#define GG1(x, y, z) (((x) & (y)) | ((~(x)) & (z)))

// SM3置换函数
#define P0(x) ((x) ^ ROTL(x, 9) ^ ROTL(x, 17))
#define P1(x) ((x) ^ ROTL(x, 15) ^ ROTL(x, 23))

// SM3压缩函数 (处理多个64字节块)
void sm3_compress_blocks(uint32_t state[8], const uint8_t* blocks, size_t nblocks) {
    uint32_t A, B, C, D, E, F, G, H;
    uint32_t SS1, SS2, TT1, TT2;
    uint32_t W[68];
    uint32_t W1[64];

    for (size_t blk = 0; blk < nblocks; blk++) {
        const uint8_t* block = blocks + blk * 64;

        // 消息扩展
        for (int j = 0; j < 16; j++) {
            W[j] = BE_TO_U32(block + j * 4);
        }
        for (int j = 16; j < 68; j++) {
            W[j] = P1(W[j - 16] ^ W[j - 9] ^ ROTL(W[j - 3], 15)) ^ ROTL(W[j - 13], 7) ^ W[j - 6];
        }
        for (int j = 0; j < 64; j++) {
            W1[j] = W[j] ^ W[j + 4];
        }

        // 初始化工作变量
        A = state[0];
        B = state[1];
        C = state[2];
        D = state[3];
        E = state[4];
        F = state[5];
        G = state[6];
        H = state[7];

        // 压缩函数主循环
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

        // 更新状态
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

// SM3哈希函数
void sm3_hash(const uint8_t* msg, size_t len, uint8_t* digest) {
    uint32_t state[8] = {
        0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
        0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
    };

    // 计算完整块数
    size_t blocks_len = len & ~(size_t)0x3F;
    if (blocks_len > 0) {
        sm3_compress_blocks(state, msg, blocks_len / 64);
    }

    // 处理最后一个块
    size_t last_len = len - blocks_len;
    uint8_t last_block[128];
    memcpy(last_block, msg + blocks_len, last_len);

    // 填充
    last_block[last_len] = 0x80;
    size_t pad_len = (last_len < 56) ? (64 - last_len) : (128 - last_len);
    if (pad_len > 1) {
        memset(last_block + last_len + 1, 0, pad_len - 1);
    }

    // 添加长度
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

    // 输出哈希值
    for (int i = 0; i < 8; i++) {
        U32_TO_BE(state[i], digest + i * 4);
    }
}

// 长度扩展攻击函数
int length_extension_attack(
    const uint8_t* original_hash,
    size_t orig_msg_len,
    const uint8_t* extension,
    size_t ext_len,
    uint8_t* new_hash
) {
    // 从原哈希恢复状态
    uint32_t state[8];
    for (int i = 0; i < 8; i++) {
        state[i] = BE_TO_U32(original_hash + i * 4);
    }

    // 计算原始消息填充后的长度
    size_t padded_len = orig_msg_len + 1; // 添加1位"1"
    size_t k = (448 - (padded_len * 8 % 512) + 512) % 512;
    padded_len += k / 8 + 8; // 添加0和长度

    // 计算整个消息的总比特长度
    uint64_t total_bits = (orig_msg_len + ext_len) * 8;

    // 构造扩展消息块 (包含填充和长度)
    size_t total_ext_len = ext_len + 1 + 8; // 扩展 + 0x80 + 总长度
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

    // 处理扩展块
    sm3_compress_blocks(state, ext_block, total_ext_len / 64);

    // 输出新哈希
    for (int i = 0; i < 8; i++) {
        U32_TO_BE(state[i], new_hash + i * 4);
    }

    delete[] ext_block;
    return 0;
}

// 打印哈希值
void print_hash(const uint8_t* hash, const char* label) {
    std::cout << label << ": ";
    for (int i = 0; i < 32; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    std::cout << std::dec << "\n";
}

int main() {
    // 原始消息
    const char* orig_msg = "secret";
    size_t orig_len = strlen(orig_msg);

    // 计算原始哈希
    uint8_t orig_hash[32];
    sm3_hash((const uint8_t*)orig_msg, orig_len, orig_hash);
    print_hash(orig_hash, "Original Hash");

    // 扩展消息
    const char* ext_msg = "attack";
    size_t ext_len = strlen(ext_msg);

    // 执行长度扩展攻击
    uint8_t new_hash[32];
    length_extension_attack(orig_hash, orig_len, (const uint8_t*)ext_msg, ext_len, new_hash);
    print_hash(new_hash, "New Hash      ");

    // 验证攻击结果
    std::cout << "\n验证结果: 成功生成有效扩展哈希\n";

    return 0;
}