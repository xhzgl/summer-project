#include <iostream>
#include <vector>
#include <queue>
#include <algorithm>
#include <cstring>
#include <array>
#include <chrono>
#include <memory>
#include <iomanip>

// 模拟SM3哈希函数 (实际使用时替换为真实实现)
void sm3(const uint8_t* data, size_t len, uint8_t hash[32]) {
    // 简化实现: 使用伪随机数据填充
    for (int i = 0; i < 32; i++) {
        hash[i] = static_cast<uint8_t>(i + len);
    }
    // 实际应用中应替换为:
    // SM3(data, len, hash);
}

struct MerkleNode {
    std::array<uint8_t, 32> hash;
    MerkleNode* left;
    MerkleNode* right;
    MerkleNode* parent;

    MerkleNode(const uint8_t h[32])
        : left(nullptr), right(nullptr), parent(nullptr) {
        std::memcpy(hash.data(), h, 32);
    }

    MerkleNode(MerkleNode* l, MerkleNode* r)
        : left(l), right(r), parent(nullptr) {

        // 计算内部节点哈希: 0x01 || left_hash || right_hash
        std::vector<uint8_t> data(65);
        data[0] = 0x01;
        std::memcpy(data.data() + 1, l->hash.data(), 32);
        if (r) {
            std::memcpy(data.data() + 33, r->hash.data(), 32);
        }
        else {
            // 如果没有右节点，复制左节点（RFC6962规范）
            std::memcpy(data.data() + 33, l->hash.data(), 32);
        }

        sm3(data.data(), data.size(), hash.data());

        l->parent = this;
        if (r) r->parent = this;
    }
};

class MerkleTree {
private:
    MerkleNode* root;
    std::vector<MerkleNode*> leaves;
    bool sorted;

    void freeTree(MerkleNode* node) {
        if (node) {
            freeTree(node->left);
            freeTree(node->right);
            delete node;
        }
    }

public:
    MerkleTree(const std::vector<std::vector<uint8_t>>& data, bool sorted = false)
        : root(nullptr), sorted(sorted) {

        // 创建叶子节点
        for (const auto& d : data) {
            std::vector<uint8_t> leafData;
            leafData.reserve(d.size() + 1);
            leafData.push_back(0x00);  // 叶子节点前缀
            leafData.insert(leafData.end(), d.begin(), d.end());

            uint8_t h[32];
            sm3(leafData.data(), leafData.size(), h);
            leaves.push_back(new MerkleNode(h));
        }

        // 排序叶子节点 (用于不存在性证明)
        if (sorted) {
            std::sort(leaves.begin(), leaves.end(), [](MerkleNode* a, MerkleNode* b) {
                return memcmp(a->hash.data(), b->hash.data(), 32) < 0;
            });
        }

        // 构建Merkle树
        if (leaves.empty()) return;

        std::vector<MerkleNode*> nodes;
        for (auto leaf : leaves) nodes.push_back(leaf);

        while (nodes.size() > 1) {
            std::vector<MerkleNode*> nextLevel;

            for (size_t i = 0; i < nodes.size(); i += 2) {
                if (i + 1 < nodes.size()) {
                    nextLevel.push_back(new MerkleNode(nodes[i], nodes[i + 1]));
                }
                else {
                    // 奇数节点处理：复制最后一个节点
                    nextLevel.push_back(new MerkleNode(nodes[i], nullptr));
                }
            }

            nodes = nextLevel;
        }

        root = nodes[0];
    }

    ~MerkleTree() {
        freeTree(root);
    }

    // 存在性证明
    std::vector<std::pair<std::array<uint8_t, 32>, bool>> inclusionProof(size_t index) {
        std::vector<std::pair<std::array<uint8_t, 32>, bool>> proof;
        if (index >= leaves.size()) return proof;

        MerkleNode* current = leaves[index];
        while (current != root) {
            MerkleNode* parent = current->parent;
            bool isLeft = (parent->left == current);
            MerkleNode* sibling = isLeft ? parent->right : parent->left;

            if (sibling) {
                proof.emplace_back(
                    sibling->hash,
                    isLeft  // true: 兄弟节点在右边, false: 兄弟节点在左边
                );
            }
            current = parent;
        }
        return proof;
    }

    // 比较两个哈希值
    static bool hashLess(const std::array<uint8_t, 32>& a, const std::array<uint8_t, 32>& b) {
        return memcmp(a.data(), b.data(), 32) < 0;
    }

    // 不存在性证明
    struct NonInclusionProof {
        std::vector<std::pair<std::array<uint8_t, 32>, bool>> left_proof;
        std::vector<std::pair<std::array<uint8_t, 32>, bool>> right_proof;
        std::array<uint8_t, 32> left_hash;
        std::array<uint8_t, 32> right_hash;
        bool has_left;
        bool has_right;
    };

    NonInclusionProof nonInclusionProof(const std::array<uint8_t, 32>& target) {
        NonInclusionProof proof;
        proof.has_left = false;
        proof.has_right = false;

        if (!sorted || leaves.empty()) {
            return proof;
        }

        // 二分查找定位目标位置
        auto it = std::upper_bound(leaves.begin(), leaves.end(), target,
            [](const auto& t, MerkleNode* node) {
            return hashLess(t, node->hash);
        });

        // 寻找前驱和后继
        size_t succ_idx = it - leaves.begin();
        size_t pred_idx = (succ_idx > 0) ? succ_idx - 1 : 0;

        if (succ_idx > 0) {
            proof.has_left = true;
            proof.left_hash = leaves[pred_idx]->hash;
            proof.left_proof = inclusionProof(pred_idx);
        }

        if (succ_idx < leaves.size()) {
            proof.has_right = true;
            proof.right_hash = leaves[succ_idx]->hash;
            proof.right_proof = inclusionProof(succ_idx);
        }

        return proof;
    }

    const std::array<uint8_t, 32>& rootHash() const {
        return root->hash;
    }

    size_t leafCount() const {
        return leaves.size();
    }

    // 辅助函数：打印哈希值
    static void printHash(const std::array<uint8_t, 32>& hash) {
        for (int i = 0; i < 32; i++) {
            std::cout << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<int>(hash[i]);
        }
        std::cout << std::dec;
    }
};

// 性能测试函数
void performanceTest() {
    const size_t NUM_LEAVES = 100000;
    std::vector<std::vector<uint8_t>> data;
    data.reserve(NUM_LEAVES);

    // 生成随机测试数据
    for (size_t i = 0; i < NUM_LEAVES; ++i) {
        std::vector<uint8_t> d(32);
        for (int j = 0; j < 32; j++) {
            d[j] = static_cast<uint8_t>((i + j) % 256);
        }
        data.push_back(d);
    }

    // 树构建性能测试
    auto start = std::chrono::high_resolution_clock::now();
    MerkleTree tree(data, true);
    auto end = std::chrono::high_resolution_clock::now();
    auto build_time = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    // 存在性证明性能测试
    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 100; i++) {
        tree.inclusionProof(i * 1000);
    }
    end = std::chrono::high_resolution_clock::now();
    auto inclusion_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / 100.0;

    // 不存在性证明性能测试
    std::array<uint8_t, 32> target{};
    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 100; i++) {
        target[0] = static_cast<uint8_t>(i);
        tree.nonInclusionProof(target);
    }
    end = std::chrono::high_resolution_clock::now();
    auto exclusion_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / 100.0;

    // 输出性能结果
    std::cout << "\n性能测试结果 (10w节点):\n";
    std::cout << "树构建时间: " << build_time << " ms\n";
    std::cout << "存在性证明平均时间: " << inclusion_time << " μs\n";
    std::cout << "不存在性证明平均时间: " << exclusion_time << " μs\n";
}

int main() {
    // 基本功能测试
    std::vector<std::vector<uint8_t>> testData = {
        {0x61, 0x62, 0x63},  // "abc"
        {0x64, 0x65, 0x66},  // "def"
        {0x67, 0x68, 0x69},  // "ghi"
        {0x6a, 0x6b, 0x6c}   // "jkl"
    };

    MerkleTree tree(testData, true);
    std::cout << "Merkle树构建成功，叶子节点数: " << tree.leafCount() << "\n";

    // 打印根哈希
    std::cout << "根哈希: ";
    MerkleTree::printHash(tree.rootHash());
    std::cout << "\n";

    // 存在性证明测试
    auto proof = tree.inclusionProof(1);
    std::cout << "\n存在性证明路径长度: " << proof.size() << "\n";
    for (size_t i = 0; i < proof.size(); i++) {
        std::cout << "步骤" << i + 1 << ": "
            << (proof[i].second ? "右兄弟 " : "左兄弟 ");
        MerkleTree::printHash(proof[i].first);
        std::cout << "\n";
    }

    // 不存在性证明测试
    std::array<uint8_t, 32> target;
    target.fill(0x70);
    auto nonIncProof = tree.nonInclusionProof(target);
    std::cout << "\n不存在性证明: "
        << (nonIncProof.has_left ? "找到前驱" : "无前驱") << ", "
        << (nonIncProof.has_right ? "找到后继" : "无后继") << "\n";

    if (nonIncProof.has_left) {
        std::cout << "前驱哈希: ";
        MerkleTree::printHash(nonIncProof.left_hash);
        std::cout << "\n";
    }
    if (nonIncProof.has_right) {
        std::cout << "后继哈希: ";
        MerkleTree::printHash(nonIncProof.right_hash);
        std::cout << "\n";
    }

    // 性能测试
    performanceTest();

    return 0;
}