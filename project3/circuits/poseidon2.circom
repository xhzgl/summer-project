pragma circom 2.1.7;
include "/home/seed/poseidon-circuit/node_modules/circomlib/circuits/poseidon.circom";

template Poseidon2() {
    signal input in[2];
    signal output out;
    
    component hasher = Poseidon(2);
    hasher.inputs[0] <== in[0];
    hasher.inputs[1] <== in[1];
    
    out <== hasher.out;
}

component main = Poseidon2();
