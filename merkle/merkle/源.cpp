#include <iostream>
#include <vector>
#include <queue>
#include <algorithm>
#include <cstring>
#include <array>
#include <chrono>
#include <memory>
#include <iomanip>

// ģ��SM3��ϣ���� (ʵ��ʹ��ʱ�滻Ϊ��ʵʵ��)
void sm3(const uint8_t* data, size_t len, uint8_t hash[32]) {
    // ��ʵ��: ʹ��α����������
    for (int i = 0; i < 32; i++) {
        hash[i] = static_cast<uint8_t>(i + len);
    }
    // ʵ��Ӧ����Ӧ�滻Ϊ:
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

        // �����ڲ��ڵ��ϣ: 0x01 || left_hash || right_hash
        std::vector<uint8_t> data(65);
        data[0] = 0x01;
        std::memcpy(data.data() + 1, l->hash.data(), 32);
        if (r) {
            std::memcpy(data.data() + 33, r->hash.data(), 32);
        }
        else {
            // ���û���ҽڵ㣬������ڵ㣨RFC6962�淶��
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

        // ����Ҷ�ӽڵ�
        for (const auto& d : data) {
            std::vector<uint8_t> leafData;
            leafData.reserve(d.size() + 1);
            leafData.push_back(0x00);  // Ҷ�ӽڵ�ǰ׺
            leafData.insert(leafData.end(), d.begin(), d.end());

            uint8_t h[32];
            sm3(leafData.data(), leafData.size(), h);
            leaves.push_back(new MerkleNode(h));
        }

        // ����Ҷ�ӽڵ� (���ڲ�������֤��)
        if (sorted) {
            std::sort(leaves.begin(), leaves.end(), [](MerkleNode* a, MerkleNode* b) {
                return memcmp(a->hash.data(), b->hash.data(), 32) < 0;
            });
        }

        // ����Merkle��
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
                    // �����ڵ㴦���������һ���ڵ�
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

    // ������֤��
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
                    isLeft  // true: �ֵܽڵ����ұ�, false: �ֵܽڵ������
                );
            }
            current = parent;
        }
        return proof;
    }

    // �Ƚ�������ϣֵ
    static bool hashLess(const std::array<uint8_t, 32>& a, const std::array<uint8_t, 32>& b) {
        return memcmp(a.data(), b.data(), 32) < 0;
    }

    // ��������֤��
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

        // ���ֲ��Ҷ�λĿ��λ��
        auto it = std::upper_bound(leaves.begin(), leaves.end(), target,
            [](const auto& t, MerkleNode* node) {
            return hashLess(t, node->hash);
        });

        // Ѱ��ǰ���ͺ��
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

    // ������������ӡ��ϣֵ
    static void printHash(const std::array<uint8_t, 32>& hash) {
        for (int i = 0; i < 32; i++) {
            std::cout << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<int>(hash[i]);
        }
        std::cout << std::dec;
    }
};

// ���ܲ��Ժ���
void performanceTest() {
    const size_t NUM_LEAVES = 100000;
    std::vector<std::vector<uint8_t>> data;
    data.reserve(NUM_LEAVES);

    // ���������������
    for (size_t i = 0; i < NUM_LEAVES; ++i) {
        std::vector<uint8_t> d(32);
        for (int j = 0; j < 32; j++) {
            d[j] = static_cast<uint8_t>((i + j) % 256);
        }
        data.push_back(d);
    }

    // ���������ܲ���
    auto start = std::chrono::high_resolution_clock::now();
    MerkleTree tree(data, true);
    auto end = std::chrono::high_resolution_clock::now();
    auto build_time = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    // ������֤�����ܲ���
    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 100; i++) {
        tree.inclusionProof(i * 1000);
    }
    end = std::chrono::high_resolution_clock::now();
    auto inclusion_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / 100.0;

    // ��������֤�����ܲ���
    std::array<uint8_t, 32> target{};
    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 100; i++) {
        target[0] = static_cast<uint8_t>(i);
        tree.nonInclusionProof(target);
    }
    end = std::chrono::high_resolution_clock::now();
    auto exclusion_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / 100.0;

    // ������ܽ��
    std::cout << "\n���ܲ��Խ�� (10w�ڵ�):\n";
    std::cout << "������ʱ��: " << build_time << " ms\n";
    std::cout << "������֤��ƽ��ʱ��: " << inclusion_time << " ��s\n";
    std::cout << "��������֤��ƽ��ʱ��: " << exclusion_time << " ��s\n";
}

int main() {
    // �������ܲ���
    std::vector<std::vector<uint8_t>> testData = {
        {0x61, 0x62, 0x63},  // "abc"
        {0x64, 0x65, 0x66},  // "def"
        {0x67, 0x68, 0x69},  // "ghi"
        {0x6a, 0x6b, 0x6c}   // "jkl"
    };

    MerkleTree tree(testData, true);
    std::cout << "Merkle�������ɹ���Ҷ�ӽڵ���: " << tree.leafCount() << "\n";

    // ��ӡ����ϣ
    std::cout << "����ϣ: ";
    MerkleTree::printHash(tree.rootHash());
    std::cout << "\n";

    // ������֤������
    auto proof = tree.inclusionProof(1);
    std::cout << "\n������֤��·������: " << proof.size() << "\n";
    for (size_t i = 0; i < proof.size(); i++) {
        std::cout << "����" << i + 1 << ": "
            << (proof[i].second ? "���ֵ� " : "���ֵ� ");
        MerkleTree::printHash(proof[i].first);
        std::cout << "\n";
    }

    // ��������֤������
    std::array<uint8_t, 32> target;
    target.fill(0x70);
    auto nonIncProof = tree.nonInclusionProof(target);
    std::cout << "\n��������֤��: "
        << (nonIncProof.has_left ? "�ҵ�ǰ��" : "��ǰ��") << ", "
        << (nonIncProof.has_right ? "�ҵ����" : "�޺��") << "\n";

    if (nonIncProof.has_left) {
        std::cout << "ǰ����ϣ: ";
        MerkleTree::printHash(nonIncProof.left_hash);
        std::cout << "\n";
    }
    if (nonIncProof.has_right) {
        std::cout << "��̹�ϣ: ";
        MerkleTree::printHash(nonIncProof.right_hash);
        std::cout << "\n";
    }

    // ���ܲ���
    performanceTest();

    return 0;
}