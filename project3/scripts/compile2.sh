#!/bin/bash
set -eo pipefail

# 确保目录存在且有写入权限
mkdir -p artifacts
chmod 755 artifacts

# 1. 检查 snarkjs 版本
echo "ℹ️ 检查 snarkjs 版本..."
if ! snarkjs --version | grep -q "plonk"; then
    echo "❌ 当前 snarkjs 版本不支持 Plonk，请升级："
    echo "npm install -g snarkjs@latest"
    exit 1
fi

# 2. 编译电路
echo "🔄 编译电路中..."
circom circuits/poseidon2.circom \
    --r1cs --wasm --sym \
    -o artifacts \
    -l $(pwd)/node_modules

# 3. 生成 Plonk 验证密钥（使用新语法）
echo "🔑 生成 Plonk 验证密钥..."
if ! snarkjs plonk setup artifacts/poseidon2.r1cs artifacts/poseidon2_plonk.zkey; then
    echo "⚠️ 标准 Plonk 失败，尝试替代方案..."
    # 备用方法：使用 universal setup
    snarkjs powersoftau new bn128 12 artifacts/pot12.ptau -v
    snarkjs plonk setup artifacts/poseidon2.r1cs artifacts/pot12.ptau artifacts/poseidon2_plonk.zkey
fi

# 4. 导出验证密钥
echo "📝 导出验证密钥..."
snarkjs zkey export verificationkey \
    artifacts/poseidon2_plonk.zkey \
    artifacts/plonk_verification_key.json

# 5. 验证流程
echo "🧪 测试完整流程..."
# 生成测试输入
echo '{"preimage":"123456789"}' > artifacts/input.json
# 计算 witness
node artifacts/poseidon2_js/generate_witness.js \
    artifacts/poseidon2_js/poseidon2.wasm \
    artifacts/input.json \
    artifacts/witness.wtns
# 生成证明
snarkjs plonk prove \
    artifacts/poseidon2_plonk.zkey \
    artifacts/witness.wtns \
    artifacts/proof.json \
    artifacts/public.json
# 验证证明
snarkjs plonk verify \
    artifacts/plonk_verification_key.json \
    artifacts/public.json \
    artifacts/proof.json

echo "✅ Plonk 流程成功完成！"
