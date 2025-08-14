import hashlib
import random
from typing import Tuple


class SM2:
    # SM2椭圆曲线参数（256位素数域）
    P = 0x8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3
    A = 0x787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498
    B = 0x63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A
    N = 0x8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7
    Gx = 0x421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D
    Gy = 0x0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2
    G = (Gx, Gy)
    H = 1  # 余因子

    def __init__(self, ida: bytes = b"ALICE123@YAHOO.COM", entla: int = 128):
        self.ida = ida
        self.entla = entla.to_bytes(2, 'big')

    def _add_points(self, P: Tuple[int, int], Q: Tuple[int, int]) -> Tuple[int, int]:
        """椭圆曲线点加"""
        if P == (0, 0):
            return Q
        if Q == (0, 0):
            return P
        x1, y1 = P
        x2, y2 = Q

        if x1 == x2 and (y1 != y2 or y1 == 0):
            return (0, 0)  # 无穷远点

        if P == Q:
            lam = (3 * x1 * x1 + self.A) * pow(2 * y1, self.P - 2, self.P) % self.P
        else:
            lam = (y2 - y1) * pow(x2 - x1, self.P - 2, self.P) % self.P

        x3 = (lam * lam - x1 - x2) % self.P
        y3 = (lam * (x1 - x3) - y1) % self.P
        return (x3, y3)

    def _mul_point(self, k: int, P: Tuple[int, int]) -> Tuple[int, int]:
        """椭圆曲线标量乘法（二进制法）"""
        R = (0, 0)  # 无穷远点
        while k:
            if k & 1:
                R = self._add_points(R, P)
            P = self._add_points(P, P)
            k >>= 1
        return R

    def _kdf(self, z: bytes, klen: int) -> bytes:
        """密钥派生函数"""
        ctr = 1
        t = b''
        while len(t) < klen:
            t += hashlib.sha256(z + ctr.to_bytes(4, 'big')).digest()
            ctr += 1
        return t[:klen]

    def _precompute_za(self, pub_key: Tuple[int, int]) -> bytes:
        """计算ZA (用户A的杂凑值)"""
        data = b''.join([
            self.entla,
            self.ida,
            self.A.to_bytes(32, 'big'),
            self.B.to_bytes(32, 'big'),
            self.Gx.to_bytes(32, 'big'),
            self.Gy.to_bytes(32, 'big'),
            pub_key[0].to_bytes(32, 'big'),
            pub_key[1].to_bytes(32, 'big')
        ])
        return hashlib.sha256(data).digest()

    def generate_keypair(self) -> Tuple[int, Tuple[int, int]]:
        """生成密钥对"""
        d = random.randint(1, self.N - 1)
        pub = self._mul_point(d, self.G)
        return d, pub

    def sign(self, d: int, msg: bytes) -> Tuple[int, int]:
        """SM2签名"""
        pub = self._mul_point(d, self.G)
        za = self._precompute_za(pub)
        e = int.from_bytes(hashlib.sha256(za + msg).digest(), 'big') % self.N

        while True:
            k = random.randint(1, self.N - 1)
            x1, _ = self._mul_point(k, self.G)
            r = (e + x1) % self.N
            if r == 0 or r + k == self.N:
                continue

            s = (pow(1 + d, self.N - 2, self.N) * (k - r * d)) % self.N
            if s != 0:
                return r, s

    def sign_with_k(self, d: int, msg: bytes, k: int) -> Tuple[int, int]:
        """使用指定k值进行SM2签名"""
        pub = self._mul_point(d, self.G)
        za = self._precompute_za(pub)
        e = int.from_bytes(hashlib.sha256(za + msg).digest(), 'big') % self.N

        x1, _ = self._mul_point(k, self.G)
        r = (e + x1) % self.N
        if r == 0 or r + k == self.N:
            raise ValueError("Invalid k value")

        s = (pow(1 + d, self.N - 2, self.N) * (k - r * d)) % self.N
        if s == 0:
            raise ValueError("Invalid k value")

        return r, s

    def verify(self, pub: Tuple[int, int], msg: bytes, sig: Tuple[int, int]) -> bool:
        """SM2验签"""
        r, s = sig
        if not (1 <= r < self.N and 1 <= s < self.N):
            return False

        za = self._precompute_za(pub)
        e = int.from_bytes(hashlib.sha256(za + msg).digest(), 'big') % self.N
        t = (r + s) % self.N

        x1, y1 = self._add_points(
            self._mul_point(s, self.G),
            self._mul_point(t, pub)
        )
        R = (e + x1) % self.N
        return R == r


# ECDSA签名函数
def ecdsa_sign(d: int, msg: bytes, k: int, curve: dict) -> Tuple[int, int]:
    """ECDSA签名"""
    n = curve["n"]
    G = curve["G"]

    # 计算 R = k * G
    R = curve_point_mul(k, G, curve)
    x1, y1 = R

    # r = R.x mod n
    r = x1 % n
    if r == 0:
        raise ValueError("r is zero")

    # 计算消息哈希 e = H(msg)
    e = int.from_bytes(hashlib.sha256(msg).digest(), 'big') % n

    # 计算 s = k⁻¹(e + r*d) mod n
    s = pow(k, n - 2, n) * (e + r * d) % n
    if s == 0:
        raise ValueError("s is zero")

    return r, s


# 椭圆曲线点加运算（通用）
def curve_point_add(P: Tuple[int, int], Q: Tuple[int, int], curve: dict) -> Tuple[int, int]:
    p, a = curve["p"], curve["a"]

    if P == (0, 0):
        return Q
    if Q == (0, 0):
        return P

    x1, y1 = P
    x2, y2 = Q

    if x1 == x2 and (y1 != y2 or y1 == 0):
        return (0, 0)  # 无穷远点

    if P == Q:
        lam = (3 * x1 * x1 + a) * pow(2 * y1, p - 2, p) % p
    else:
        lam = (y2 - y1) * pow(x2 - x1, p - 2, p) % p

    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)


# 椭圆曲线标量乘法（通用）
def curve_point_mul(k: int, P: Tuple[int, int], curve: dict) -> Tuple[int, int]:
    R = (0, 0)  # 无穷远点
    while k:
        if k & 1:
            R = curve_point_add(R, P, curve)
        P = curve_point_add(P, P, curve)
        k >>= 1
    return R


# POC 1: 相同k值导致私钥泄露 (修复版)
def poc_same_k_leak():
    print("\n=== POC 1: 相同k值导致私钥泄露 (修复版) ===")
    sm2 = SM2()
    d, pub = sm2.generate_keypair()
    msg1 = b"Message 1"
    msg2 = b"Message 2"

    # 故意使用相同k
    k = random.randint(1, sm2.N - 1)
    print(f"使用的k值: {k}")

    try:
        r1, s1 = sm2.sign_with_k(d, msg1, k)
        r2, s2 = sm2.sign_with_k(d, msg2, k)
    except ValueError as e:
        print(f"签名失败: {e}")
        return

    print(f"消息1签名: (r={r1}, s={s1})")
    print(f"消息2签名: (r={r2}, s={s2})")

    # 验证签名
    valid1 = sm2.verify(pub, msg1, (r1, s1))
    valid2 = sm2.verify(pub, msg2, (r2, s2))
    print(f"签名1验证: {valid1}")
    print(f"签名2验证: {valid2}")

    if not (valid1 and valid2):
        print("签名无效，无法继续")
        return

    # 正确的私钥恢复公式
    numerator = (s1 - s2) % sm2.N
    denominator = (s2 - s1 + r2 - r1) % sm2.N

    if denominator == 0:
        print("错误: 分母为0，无法恢复私钥")
        return

    d_recovered = numerator * pow(denominator, sm2.N - 2, sm2.N) % sm2.N

    print(f"原始私钥: {d}")
    print(f"恢复私钥: {d_recovered}")
    print(f"恢复结果: {d == d_recovered}")


# POC 2: 不同用户相同k导致私钥泄露
def poc_cross_user_k_leak():
    print("\n=== POC 2: 不同用户相同k导致私钥泄露 ===")
    sm2 = SM2()

    # 用户A
    dA, pubA = sm2.generate_keypair()
    msgA = b"Alice's message"

    # 用户B
    dB, pubB = sm2.generate_keypair()
    msgB = b"Bob's message"

    # 使用相同的k值
    k = random.randint(1, sm2.N - 1)
    print(f"使用的相同k值: {k}")

    # 用户A签名
    try:
        rA, sA = sm2.sign_with_k(dA, msgA, k)
    except ValueError as e:
        print(f"用户A签名失败: {e}")
        return

    # 用户B签名
    try:
        rB, sB = sm2.sign_with_k(dB, msgB, k)
    except ValueError as e:
        print(f"用户B签名失败: {e}")
        return

    print(f"用户A签名: (r={rA}, s={sA})")
    print(f"用户B签名: (r={rB}, s={sB})")

    # 验证签名
    validA = sm2.verify(pubA, msgA, (rA, sA))
    validB = sm2.verify(pubB, msgB, (rB, sB))
    print(f"用户A签名验证: {validA}")
    print(f"用户B签名验证: {validB}")

    if not (validA and validB):
        print("签名无效，无法继续")
        return

    # 恢复用户A的私钥
    # dA = (k - sA) / (sA + rA) mod n
    numerator_dA = (k - sA) % sm2.N
    denominator_dA = (sA + rA) % sm2.N

    if denominator_dA == 0:
        print("错误: 分母为0，无法恢复用户A私钥")
        return

    dA_recovered = numerator_dA * pow(denominator_dA, sm2.N - 2, sm2.N) % sm2.N

    # 恢复用户B的私钥
    # dB = (k - sB) / (sB + rB) mod n
    numerator_dB = (k - sB) % sm2.N
    denominator_dB = (sB + rB) % sm2.N

    if denominator_dB == 0:
        print("错误: 分母为0，无法恢复用户B私钥")
        return

    dB_recovered = numerator_dB * pow(denominator_dB, sm2.N - 2, sm2.N) % sm2.N

    print(f"用户A原始私钥: {dA}")
    print(f"用户A恢复私钥: {dA_recovered}")
    print(f"用户A私钥匹配: {dA == dA_recovered}")

    print(f"用户B原始私钥: {dB}")
    print(f"用户B恢复私钥: {dB_recovered}")
    print(f"用户B私钥匹配: {dB == dB_recovered}")


# POC 3: SM2和ECDSA使用相同d和k导致私钥泄露
def poc_ecdsa_sm2_collision():
    print("\n=== POC 3: SM2和ECDSA使用相同d和k导致私钥泄露 ===")
    # ECDSA参数（使用与SM2相同的曲线）
    curve = {
        "p": SM2.P,
        "a": SM2.A,
        "b": SM2.B,
        "n": SM2.N,
        "G": (SM2.Gx, SM2.Gy)
    }

    d = random.randint(1, curve["n"] - 1)
    k = random.randint(1, curve["n"] - 1)
    print(f"使用的私钥d: {d}")
    print(f"使用的k值: {k}")

    msg_sm2 = b"SM2 message"
    msg_ecdsa = b"ECDSA message"

    # SM2签名
    try:
        sm2_sig = SM2().sign_with_k(d, msg_sm2, k)
    except ValueError as e:
        print(f"SM2签名失败: {e}")
        return

    # ECDSA签名
    try:
        ecdsa_sig = ecdsa_sign(d, msg_ecdsa, k, curve)
    except ValueError as e:
        print(f"ECDSA签名失败: {e}")
        return

    r_sm2, s_sm2 = sm2_sig
    r_ecdsa, s_ecdsa = ecdsa_sig

    print(f"SM2签名: (r={r_sm2}, s={s_sm2})")
    print(f"ECDSA签名: (r={r_ecdsa}, s={s_ecdsa})")

    # 计算消息哈希
    sm2 = SM2()
    pub = sm2._mul_point(d, sm2.G)
    za = sm2._precompute_za(pub)
    e_sm2 = int.from_bytes(hashlib.sha256(za + msg_sm2).digest(), 'big') % curve["n"]
    e_ecdsa = int.from_bytes(hashlib.sha256(msg_ecdsa).digest(), 'big') % curve["n"]

    print(f"SM2消息哈希: {e_sm2}")
    print(f"ECDSA消息哈希: {e_ecdsa}")

    # 推导公式
    numerator = (s_ecdsa * s_sm2 - e_ecdsa) % curve["n"]
    denominator = (r_ecdsa - s_ecdsa * s_sm2 - s_ecdsa * r_sm2) % curve["n"]

    if denominator == 0:
        print("错误: 分母为0，无法恢复私钥")
        return

    d_recovered = numerator * pow(denominator, curve["n"] - 2, curve["n"]) % curve["n"]

    print(f"原始私钥: {d}")
    print(f"恢复私钥: {d_recovered}")
    print(f"私钥匹配: {d == d_recovered}")


# 运行所有POC演示
if __name__ == "__main__":
    print("=" * 50)
    print("SM2安全漏洞演示")
    print("=" * 50)

    # 运行POC 1
    poc_same_k_leak()

    print("\n" + "=" * 50)

    # 运行POC 2
    poc_cross_user_k_leak()

    print("\n" + "=" * 50)

    # 运行POC 3
    poc_ecdsa_sm2_collision()

    print("\n" + "=" * 50)
    print("所有POC演示完成！")
    print("=" * 50)