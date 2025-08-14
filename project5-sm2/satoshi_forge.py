import hashlib
import random
from typing import Tuple


# 椭圆曲线点加运算
def curve_point_add(P: Tuple[int, int], Q: Tuple[int, int], curve: dict) -> Tuple[int, int]:
    p, a = curve["p"], curve["a"]

    # 处理无穷远点
    if P == (0, 0):
        return Q
    if Q == (0, 0):
        return P

    x1, y1 = P
    x2, y2 = Q

    # 处理相同x坐标但y坐标不同的情况（垂直切线）
    if x1 == x2 and (y1 != y2 or y1 == 0):
        return (0, 0)  # 无穷远点

    # 点加倍运算（P == Q）
    if P == Q:
        # 斜率 λ = (3x₁² + a) / (2y₁) mod p
        lam = (3 * x1 * x1 + a) * pow(2 * y1, p - 2, p) % p
    else:
        # 点加运算（P ≠ Q）
        # 斜率 λ = (y₂ - y₁) / (x₂ - x₁) mod p
        lam = (y2 - y1) * pow(x2 - x1, p - 2, p) % p

    # 计算新点坐标
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)


# 椭圆曲线标量乘法
def curve_point_mul(k: int, P: Tuple[int, int], curve: dict) -> Tuple[int, int]:
    # 初始化结果为无穷远点
    R = (0, 0)

    # 二进制展开法
    while k:
        # 如果最低位为1，则加上当前点
        if k & 1:
            R = curve_point_add(R, P, curve)

        # 点加倍
        P = curve_point_add(P, P, curve)

        # 右移一位
        k >>= 1

    return R


# ECDSA签名（接受k作为参数）
def ecdsa_sign_with_k(d: int, msg: bytes, k: int, curve: dict) -> Tuple[int, int]:
    n = curve["n"]
    G = (curve["Gx"], curve["Gy"])

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


# ECDSA验证
def ecdsa_verify(pub: Tuple[int, int], msg: bytes, sig: Tuple[int, int], curve: dict) -> bool:
    r, s = sig
    n = curve["n"]
    G = (curve["Gx"], curve["Gy"])

    # 检查签名范围
    if not (1 <= r < n and 1 <= s < n):
        return False

    # 计算消息哈希 e = H(msg)
    e = int.from_bytes(hashlib.sha256(msg).digest(), 'big') % n

    # 计算 w = s⁻¹ mod n
    w = pow(s, n - 2, n)

    # 计算 u1 = e*w mod n, u2 = r*w mod n
    u1 = e * w % n
    u2 = r * w % n

    # 计算 R' = u1*G + u2*pub
    R_prime = curve_point_add(
        curve_point_mul(u1, G, curve),
        curve_point_mul(u2, pub, curve),
        curve
    )
    x1, y1 = R_prime

    # 验证 r' == r
    return x1 % n == r


# 伪造中本聪签名（修复版）
def forge_satoshi_signature():
    # 比特币使用的secp256k1曲线参数
    curve = {
        "p": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
        "a": 0,  # a = 0
        "b": 7,  # b = 7
        "n": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
        "Gx": 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        "Gy": 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
    }

    # 中本聪的私钥（随机生成）
    d_satoshi = random.randint(1, curve["n"] - 1)
    print(f"中本聪的原始私钥: {d_satoshi}")

    # 计算中本聪的公钥
    satoshi_pub = curve_point_mul(d_satoshi, (curve["Gx"], curve["Gy"]), curve)

    # 中本聪签署的两个区块奖励消息
    msg1 = b"Block 1 reward"
    msg2 = b"Block 2 reward"

    # 中本聪错误地使用了相同的k值签名
    k = random.randint(1, curve["n"] - 1)
    print(f"使用的相同k值: {k}")

    # 生成第一个签名
    sig1 = ecdsa_sign_with_k(d_satoshi, msg1, k, curve)
    r1, s1 = sig1

    # 生成第二个签名（使用相同的k）
    sig2 = ecdsa_sign_with_k(d_satoshi, msg2, k, curve)
    r2, s2 = sig2

    print(f"签名1: (r={r1}, s={s1})")
    print(f"签名2: (r={r2}, s={s2})")

    # 由于k相同，r值必须相同
    if r1 != r2:
        print(f"错误：r值不同！r1={r1}, r2={r2}")
        return

    r = r1  # 因为r1和r2相同

    # 验证两个签名是否有效
    valid1 = ecdsa_verify(satoshi_pub, msg1, sig1, curve)
    valid2 = ecdsa_verify(satoshi_pub, msg2, sig2, curve)
    print(f"签名1验证: {valid1}")
    print(f"签名2验证: {valid2}")

    if not (valid1 and valid2):
        print("签名无效，无法继续")
        return

    # 计算消息哈希
    e1 = int.from_bytes(hashlib.sha256(msg1).digest(), 'big') % curve["n"]
    e2 = int.from_bytes(hashlib.sha256(msg2).digest(), 'big') % curve["n"]

    print(f"消息1哈希: {e1}")
    print(f"消息2哈希: {e2}")

    # 从签名中恢复k值
    # k = (e1 - e2) * (s1 - s2)^(-1) mod n
    numerator_k = (e1 - e2) % curve["n"]
    denominator_k = (s1 - s2) % curve["n"]

    if denominator_k == 0:
        print("错误: s1 - s2 = 0, 无法恢复k值")
        return

    k_recovered = numerator_k * pow(denominator_k, curve["n"] - 2, curve["n"]) % curve["n"]
    print(f"恢复的k值: {k_recovered} (原始: {k})")

    # 恢复私钥
    # d = (s1 * k - e1) / r mod n
    numerator_d = (s1 * k_recovered - e1) % curve["n"]
    if r == 0:
        print("错误: r = 0, 无法恢复私钥")
        return

    d_recovered = numerator_d * pow(r, curve["n"] - 2, curve["n"]) % curve["n"]
    print(f"恢复的私钥: {d_recovered}")

    # 验证恢复的私钥是否正确
    print(f"私钥匹配: {d_satoshi == d_recovered}")

    if d_satoshi != d_recovered:
        print("私钥恢复失败，无法伪造签名")
        return

    # 使用恢复的私钥伪造新交易签名
    forged_msg = b"Transfer all bitcoins to Attacker"
    forged_sig = ecdsa_sign_with_k(d_recovered, forged_msg, random.randint(1, curve["n"] - 1), curve)

    # 验证伪造的签名
    verification_result = ecdsa_verify(satoshi_pub, forged_msg, forged_sig, curve)
    print(f"伪造签名验证: {verification_result}")


if __name__ == "__main__":
    # 多次尝试以确保成功案例
    for i in range(5):
        print(f"\n尝试 #{i + 1}")
        try:
            forge_satoshi_signature()
            if i < 4:  # 如果成功，询问是否继续
                cont = input("成功！是否继续测试？(y/n): ")
                if cont.lower() != 'y':
                    break
        except Exception as e:
            print(f"错误: {e}")
            continue