from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import random
import math


class SimulatedGroup:#素数阶群
    def __init__(self, order):
        self.order = order
    def hash_to_group(self, identifier):
        #哈希到群实现
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(identifier.encode())
        h = int.from_bytes(digest.finalize(), byteorder='big')
        return pow(h, 1, self.order)
    def exponentiate(self, element, exponent):
        return pow(element, exponent, self.order)

class AdditiveHomomorphicEncryption:
    def __init__(self, key_size=2048):
        #生成RSA密钥对
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
    def encrypt(self, plaintext):
        #转换为字节并加密
        plaintext_bytes = plaintext.to_bytes((plaintext.bit_length() + 7) // 8, byteorder='big')
        return self.public_key.encrypt(
            plaintext_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    def decrypt(self, ciphertext):
        try:
            decrypted = self.private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return int.from_bytes(decrypted, byteorder='big')
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")
    def add(self, ciphertext1, ciphertext2):
        #模拟同态加法
        pt1 = self.decrypt(ciphertext1)
        pt2 = self.decrypt(ciphertext2)
        return self.encrypt(pt1 + pt2)

class Party1:
    def __init__(self, group, identifiers):
        self.group = group
        self.V = [group.hash_to_group(v) for v in identifiers]
        self.k1 = random.randint(1, group.order - 1)

    def round1(self):
        return [self.group.exponentiate(v, self.k1) for v in self.V]#计算H(v_i)^k1

    def round3(self, Z, encrypted_pairs, ahe):
        Z_set = set(Z)
        sum_cipher = ahe.encrypt(0)  #初始化为加密的0

        for (w_k2, enc_t) in encrypted_pairs:
            w_k1k2 = self.group.exponentiate(w_k2, self.k1)#计算H(w_j)^k1k2
            if w_k1k2 in Z_set: #判断是否在交集中
                sum_cipher = ahe.add(sum_cipher, enc_t)#同态加

        return sum_cipher

class Party2:
    def __init__(self, group, pairs):
        self.group = group
        self.W = [(group.hash_to_group(w), t) for (w, t) in pairs]
        self.k2 = random.randint(1, group.order - 1)
        self.ahe = AdditiveHomomorphicEncryption()

    def round2(self, received_from_p1):
        Z = [self.group.exponentiate(item, self.k2) for item in received_from_p1]
        #计算H(v_i)^k1k2
        encrypted_pairs = [
            (self.group.exponentiate(w, self.k2), self.ahe.encrypt(t))
            #(H(w_j)^k2, Enc(t_j))
            for (w, t) in self.W
        ]
        return Z, encrypted_pairs

    def output(self, encrypted_sum):
        return self.ahe.decrypt(encrypted_sum)

def run_protocol():
    #大素数阶
    group_order = 115792089237316195423570985008687907853269984665640564039457584007913129639747  # 示例大素数
    group = SimulatedGroup(group_order)
    #P1的输入
    p1_identifiers = ["user1@example.com", "user2@example.com", "user3@example.com"]
    p1 = Party1(group, p1_identifiers)
    #P2的输入
    p2_pairs = [("user2@example.com", 5), ("user4@example.com", 3), ("user3@example.com", 7)]
    p2 = Party2(group, p2_pairs)
    #协议
    p1_to_p2 = p1.round1()
    Z, p2_to_p1 = p2.round2(p1_to_p2)
    encrypted_sum = p1.round3(Z, p2_to_p1, p2.ahe)
    result = p2.output(encrypted_sum)
    print(f"Intersection sum: {result}")

if __name__ == "__main__":
    run_protocol()