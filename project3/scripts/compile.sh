#!/bin/bash
set -eo pipefail
mkdir -p artifacts

# 1. 编译电路
echo "编译电路..."
circom circuits/poseidon2.circom \
    --r1cs --wasm --sym \
    -o artifacts

# 2. 下载PTAU文件
if [ ! -f artifacts/pot12_final.ptau ]; then
    echo "下载PTAU文件..."
    for i in {1..5}; do
        if wget -q https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_12.ptau -O artifacts/pot12_final.ptau; then
            break
        elif [ $i -eq 5 ]; then
            echo "PTAU文件下载失败"
            exit 1
        else
            sleep 5
        fi
    done
fi

# 3. 生成Groth16密钥
snarkjs groth16 setup \
    artifacts/poseidon2.r1cs \
    artifacts/pot12_final.ptau \
    artifacts/poseidon2.zkey

# 4. 导出验证密钥
snarkjs zkey export verificationkey \
    artifacts/poseidon2.zkey \
    artifacts/verification_key.json

echo "编译流程完成"
