import hashlib
import random
import time
from typing import Tuple, List, Optional


class OptimizedSM2:
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

    def _affine_to_jacobian(self, P: Tuple[int, int]) -> Tuple[int, int, int]:
        """仿射坐标转Jacobian坐标"""
        if P == (0, 0):
            return (0, 0, 0)  # 无穷远点
        return (P[0], P[1], 1)

    def _jacobian_to_affine(self, P: Tuple[int, int, int]) -> Tuple[int, int]:
        """Jacobian坐标转仿射坐标"""
        if P[2] == 0:
            return (0, 0)  # 无穷远点

        z_inv = pow(P[2], self.P - 2, self.P)
        z_inv_sq = (z_inv * z_inv) % self.P
        x = (P[0] * z_inv_sq) % self.P
        y = (P[1] * z_inv_sq * z_inv) % self.P
        return (x, y)

    def _jacobian_double(self, P: Tuple[int, int, int]) -> Tuple[int, int, int]:
        """Jacobian坐标下的点加倍"""
        if P[2] == 0:
            return (0, 0, 0)

        # 提取坐标
        X1, Y1, Z1 = P

        # 计算中间量
        XX = (X1 * X1) % self.P
        YY = (Y1 * Y1) % self.P
        YYYY = (YY * YY) % self.P
        ZZ = (Z1 * Z1) % self.P
        S = (4 * X1 * YY) % self.P
        M = (3 * XX + self.A * pow(ZZ, 4, self.P)) % self.P

        # 计算新坐标
        X3 = (M * M - 2 * S) % self.P
        Y3 = (M * (S - X3) - 8 * YYYY) % self.P
        Z3 = (2 * Y1 * Z1) % self.P

        return (X3, Y3, Z3)

    def _jacobian_add(self, P: Tuple[int, int, int], Q: Tuple[int, int, int]) -> Tuple[int, int, int]:
        """Jacobian坐标下的点加"""
        if P[2] == 0:
            return Q
        if Q[2] == 0:
            return P

        # 提取坐标
        X1, Y1, Z1 = P
        X2, Y2, Z2 = Q

        # 计算中间量
        Z1Z1 = (Z1 * Z1) % self.P
        Z2Z2 = (Z2 * Z2) % self.P
        U1 = (X1 * Z2Z2) % self.P
        U2 = (X2 * Z1Z1) % self.P
        S1 = (Y1 * Z2 * Z2Z2) % self.P
        S2 = (Y2 * Z1 * Z1Z1) % self.P

        # 检查是否相同点
        if U1 == U2:
            if S1 != S2:
                return (0, 0, 0)  # 无穷远点
            return self._jacobian_double(P)

        H = (U2 - U1) % self.P
        I = (4 * H * H) % self.P
        J = (H * I) % self.P
        r = (2 * (S2 - S1)) % self.P
        V = (U1 * I) % self.P

        # 计算新坐标
        X3 = (r * r - J - 2 * V) % self.P
        Y3 = (r * (V - X3) - 2 * S1 * J) % self.P
        Z3 = (2 * H * Z1 * Z2) % self.P

        return (X3, Y3, Z3)

    def _neg_point(self, P: Tuple[int, int]) -> Tuple[int, int]:
        """点的负元素"""
        if P == (0, 0):
            return (0, 0)
        return (P[0], (-P[1]) % self.P)

    def _naf(self, k: int) -> List[int]:
        """计算k的NAF（非相邻形式）表示"""
        naf = []
        while k > 0:
            if k & 1:
                ki = 2 - (k % 4)
                k = k - ki
            else:
                ki = 0
            naf.append(ki)
            k //= 2
        return naf

    def _w_naf_point_mul(self, k: int, P: Tuple[int, int], w: int = 4) -> Tuple[int, int]:
        """w-NAF点乘优化"""
        # 预计算点表 [1P, 3P, 5P, ..., (2^{w-1}-1)P]
        precomputed = []
        P_jac = self._affine_to_jacobian(P)

        # 计算奇数倍点
        current = P_jac
        for i in range(1, 1 << (w - 1), 2):
            precomputed.append(self._jacobian_to_affine(current))
            current = self._jacobian_add(current, P_jac)
            current = self._jacobian_add(current, P_jac)

        # 计算NAF表示
        naf = self._naf(k)
        if not naf:
            return (0, 0)

        # 点乘计算
        Q_jac = (0, 0, 0)  # 无穷远点
        for i in range(len(naf) - 1, -1, -1):
            Q_jac = self._jacobian_double(Q_jac)
            if naf[i] > 0:
                idx = (naf[i] - 1) // 2
                P_point = precomputed[idx]
                P_jac = self._affine_to_jacobian(P_point)
                Q_jac = self._jacobian_add(Q_jac, P_jac)
            elif naf[i] < 0:
                idx = (-naf[i] - 1) // 2
                P_point = precomputed[idx]
                P_neg = self._neg_point(P_point)
                P_jac = self._affine_to_jacobian(P_neg)
                Q_jac = self._jacobian_add(Q_jac, P_jac)

        return self._jacobian_to_affine(Q_jac)

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
        pub = self._w_naf_point_mul(d, self.G)  # 使用优化点乘
        return d, pub

    def sign(self, d: int, msg: bytes, use_optimized: bool = True) -> Tuple[int, int]:
        """SM2签名（可选择是否使用优化）"""
        pub = self._w_naf_point_mul(d, self.G) if use_optimized else self._basic_point_mul(d, self.G)
        za = self._precompute_za(pub)
        e = int.from_bytes(hashlib.sha256(za + msg).digest(), 'big') % self.N

        while True:
            k = random.randint(1, self.N - 1)
            if use_optimized:
                x1, _ = self._w_naf_point_mul(k, self.G)
            else:
                x1, _ = self._basic_point_mul(k, self.G)

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

        # 使用优化点乘计算 s*G + t*pub
        sG = self._w_naf_point_mul(s, self.G)
        tPub = self._w_naf_point_mul(t, pub)
        x1, y1 = self._add_points(sG, tPub)

        R = (e + x1) % self.N
        return R == r

    # 以下为基本实现，用于性能对比
    def _basic_point_mul(self, k: int, P: Tuple[int, int]) -> Tuple[int, int]:
        """基本点乘（二进制法）"""
        R = (0, 0)  # 无穷远点
        while k:
            if k & 1:
                R = self._add_points(R, P)
            P = self._add_points(P, P)
            k >>= 1
        return R

    def _add_points(self, P: Tuple[int, int], Q: Tuple[int, int]) -> Tuple[int, int]:
        """仿射坐标点加"""
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


# 性能测试
def performance_test():
    sm2 = OptimizedSM2()
    d, pub = sm2.generate_keypair()
    msg = b"Performance test message"

    # 测试基本点乘性能
    start = time.time()
    for _ in range(100):
        sm2._basic_point_mul(d, sm2.G)
    basic_time = time.time() - start

    # 测试优化点乘性能
    start = time.time()
    for _ in range(100):
        sm2._w_naf_point_mul(d, sm2.G)
    optimized_time = time.time() - start

    # 测试签名性能
    start = time.time()
    for _ in range(100):
        sm2.sign(d, msg, use_optimized=False)
    basic_sign_time = time.time() - start

    start = time.time()
    for _ in range(100):
        sm2.sign(d, msg, use_optimized=True)
    optimized_sign_time = time.time() - start

    # 打印结果
    print("=" * 50)
    print("SM2 性能测试结果")
    print("=" * 50)
    print(f"基本点乘平均时间: {basic_time / 100:.6f} 秒")
    print(f"优化点乘平均时间: {optimized_time / 100:.6f} 秒")
    print(f"速度提升: {basic_time / optimized_time:.2f}x")
    print("-" * 50)
    print(f"基本签名平均时间: {basic_sign_time / 100:.6f} 秒")
    print(f"优化签名平均时间: {optimized_sign_time / 100:.6f} 秒")
    print(f"速度提升: {basic_sign_time / optimized_sign_time:.2f}x")
    print("=" * 50)


# 功能验证
def functionality_test():
    sm2 = OptimizedSM2()
    d, pub = sm2.generate_keypair()
    msg = b"Hello, optimized SM2!"

    # 签名
    sig = sm2.sign(d, msg)
    print(f"签名: (r={sig[0]}, s={sig[1]})")

    # 验证
    valid = sm2.verify(pub, msg, sig)
    print(f"验证结果: {valid}")

    # 篡改消息测试
    invalid = sm2.verify(pub, b"Tampered message", sig)
    print(f"篡改消息验证: {invalid} (应为False)")

    # 篡改签名测试
    tampered_sig = (sig[0], (sig[1] + 1) % sm2.N)
    invalid = sm2.verify(pub, msg, tampered_sig)
    print(f"篡改签名验证: {invalid} (应为False)")


# 主程序
if __name__ == "__main__":
    print("=" * 50)
    print("优化版SM2实现")
    print("=" * 50)

    print("\n[功能验证]")
    functionality_test()

    print("\n[性能测试]")
    performance_test()