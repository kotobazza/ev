#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <algorithm>
#include <array>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

class MerkleTree {
   private:
    struct Node {
        std::string hashHex;
        std::shared_ptr<Node> left;
        std::shared_ptr<Node> right;

        Node(const std::string& h, std::shared_ptr<Node> l = nullptr, std::shared_ptr<Node> r = nullptr)
            : hashHex(h), left(l), right(r) {}
    };

    std::vector<std::shared_ptr<Node>> leaves;
    std::shared_ptr<Node> root;
    EVP_MD* md;
    static constexpr size_t HASH_LEN = 64;  // Для SHA-512

    std::string hashDeprec(const std::string& data) {
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        std::array<unsigned char, HASH_LEN> digest;

        EVP_DigestInit_ex2(ctx, md, nullptr);
        EVP_DigestUpdate(ctx, data.c_str(), data.size());
        EVP_DigestFinal_ex(ctx, digest.data(), nullptr);
        EVP_MD_CTX_free(ctx);

        return std::string(reinterpret_cast<char*>(digest.data()), HASH_LEN);
    }

    std::string hash(const std::string& data) {
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        std::array<unsigned char, HASH_LEN> digest;

        EVP_DigestInit_ex2(ctx, md, nullptr);
        EVP_DigestUpdate(ctx, data.c_str(), data.size());
        EVP_DigestFinal_ex(ctx, digest.data(), nullptr);
        EVP_MD_CTX_free(ctx);

        // Преобразование бинарного хеша в hex
        std::string hex;
        hex.reserve(HASH_LEN * 2);
        static const char hexDigits[] = "0123456789abcdef";
        for (unsigned char byte : digest) {
            hex.push_back(hexDigits[byte >> 4]);
            hex.push_back(hexDigits[byte & 0x0F]);
        }
        return hex;
    }

    std::shared_ptr<Node> buildTree(const std::vector<std::shared_ptr<Node>>& nodes) {
        if (nodes.empty())
            return nullptr;
        if (nodes.size() == 1)
            return nodes[0];

        std::vector<std::shared_ptr<Node>> nextLevel;
        for (size_t i = 0; i < nodes.size(); i += 2) {
            std::string combined = nodes[i]->hashHex;
            if (i + 1 < nodes.size()) {
                combined += nodes[i + 1]->hashHex;
                nextLevel.push_back(std::make_shared<Node>(hash(combined), nodes[i], nodes[i + 1]));
            } else {
                nextLevel.push_back(std::make_shared<Node>(hash(combined + nodes[i]->hashHex), nodes[i], nullptr));
            }
        }
        return buildTree(nextLevel);
    }

   public:
    MerkleTree() {
        md = EVP_MD_fetch(nullptr, "SHA512", nullptr);
        if (!md) {
            throw std::runtime_error("SHA512 not available");
        }
    }

    ~MerkleTree() { EVP_MD_free(md); }

    void addLeaf(const std::string& leaf) {
        leaves.push_back(std::make_shared<Node>(hash(leaf)));
        root = buildTree(leaves);
    }

    void removeLeaf(const std::string& leafHash) {
        auto it = std::find_if(leaves.begin(), leaves.end(),
                               [&leafHash](const std::shared_ptr<Node>& node) { return node->hashHex == leafHash; });

        if (it != leaves.end()) {
            leaves.erase(it);
            root = buildTree(leaves);
        }
    }

    std::string getRoot() const { return root ? root->hashHex : ""; }

    std::vector<std::pair<std::string, bool>> getProof(const std::string& leafHash) const {
        std::vector<std::pair<std::string, bool>> proof;

        auto it = std::find_if(leaves.begin(), leaves.end(),
                               [&leafHash](const auto& node) { return node->hashHex == leafHash; });

        if (it == leaves.end())
            return proof;

        std::shared_ptr<Node> current = *it;

        while (current != root) {
            auto parent = findParent(current);
            if (!parent)
                break;

            if (parent->left.get() == current.get() && parent->right) {
                // Текущий узел — левый, его "брат" — правый (добавляем с флагом true)
                proof.emplace_back(parent->right->hashHex, true);
            } else if (parent->right.get() == current.get()) {
                // Текущий узел — правый, его "брат" — левый (добавляем с флагом false)
                proof.emplace_back(parent->left->hashHex, false);
            }

            current = parent;
        }

        return proof;
    }

    // void serialize(std::ostream& out) const {
    //     if (!root)
    //         return;

    //     std::vector<std::shared_ptr<Node>> currentLevel = {root};
    //     while (!currentLevel.empty()) {
    //         std::vector<std::shared_ptr<Node>> nextLevel;

    //         for (const auto& node : currentLevel) {
    //             out << node->hashHex << " ";
    //             if (node->left)
    //                 nextLevel.push_back(node->left);
    //             if (node->right)
    //                 nextLevel.push_back(node->right);
    //         }
    //         out << "\n";
    //         currentLevel = nextLevel;
    //     }
    // }

    void serializeNode(std::ostream& out, const std::shared_ptr<Node>& node) const {
        if (!node) {
            out << "null";
            return;
        }
        out << "{ \"hash\": \"" << node->hashHex << "\", ";
        out << "\"left\": ";
        serializeNode(out, node->left);
        out << ", \"right\": ";
        serializeNode(out, node->right);
        out << " }";
    }

    void serialize(std::ostream& out) const {
        serializeNode(out, root);
        out << "\n";
    }

   private:
    std::shared_ptr<Node> findParent(const std::shared_ptr<Node>& child) const {
        if (!root)
            return nullptr;

        std::vector<std::shared_ptr<Node>> currentLevel = {root};
        while (!currentLevel.empty()) {
            std::vector<std::shared_ptr<Node>> nextLevel;

            for (const auto& node : currentLevel) {
                if (node->left.get() == child.get() || node->right.get() == child.get()) {
                    return node;
                }
                if (node->left)
                    nextLevel.push_back(node->left);
                if (node->right)
                    nextLevel.push_back(node->right);
            }

            currentLevel = nextLevel;
        }

        return nullptr;
    }
};