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


# 示例用法
if __name__ == "__main__":
    sm2 = SM2()
    d, pub = sm2.generate_keypair()
    print("私钥:", d)
    print("公钥:", pub)

    msg = b"Hello, SM2!"
    sig = sm2.sign(d, msg)
    print("签名:", sig)
    print("验签结果:", sm2.verify(pub, msg, sig))