#!/bin/bash
set -eo pipefail

# 强制使用Plonk（不检查版本）
echo "⚡ 强制使用Plonk证明系统..."

mkdir -p artifacts

# 编译电路
circom circuits/poseidon2.circom \
    --r1cs --wasm --sym \
    -o artifacts \
    -l node_modules

# 生成Plonk密钥
snarkjs plonk setup \
    artifacts/poseidon2.r1cs \
    artifacts/poseidon2_plonk.zkey

# 导出验证密钥
snarkjs zkey export verificationkey \
    artifacts/poseidon2_plonk.zkey \
    artifacts/verification_key.json

echo "✅ 编译完成！Plonk验证密钥已生成"
