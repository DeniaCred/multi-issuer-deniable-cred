#include "nizk_proof.h"

namespace {

void addStringToHash(PFC* pfc, const string& value) {
    pfc->add_to_hash((char*)value.c_str());
}

Big vAuthChallenge(const string& ctx, const G2& pk_V, const G2& A, PFC* pfc) {
    pfc->start_hash();
    addStringToHash(pfc, "domain_VAuth");
    addStringToHash(pfc, "prototype_ppHash");
    addStringToHash(pfc, ctx);
    pfc->add_to_hash(pk_V);
    pfc->add_to_hash(A);
    return pfc->finish_hash_to_group() % pfc->order();
}

} // namespace

// --- 生成验证者密钥对 ---
VerifierKeyPair generateVerifierKeyPair(PFC* pfc, const G2& G2_gen) {
    VerifierKeyPair kp;
    pfc->random(kp.sk_V);
    kp.pk_V = pfc->mult(G2_gen, kp.sk_V);
    return kp;
}

// --- 验证者生成NIZK证明 ---
NIZKProof generateNIZKProof(const string& ctx, const VerifierKeyPair& kp, PFC* pfc, const G2& G2_gen) {
    NIZKProof proof;
    
    // 第一步：承诺 (Commitment)
    Big a;
    pfc->random(a);
    proof.A = pfc->mult(G2_gen, a);
    
    // 第二步：挑战 (Challenge - Fiat-Shamir 转换)
    Big c = vAuthChallenge(ctx, kp.pk_V, proof.A, pfc);
    
    // 第三步：响应 (Response)
    // z = a + c * sk_V mod p
    Big term = modmult(c, kp.sk_V, pfc->order());
    proof.z = (a + term) % pfc->order();
    
    return proof;
}

// --- 用户校验NIZK证明 ---
bool verifyNIZKProof(const string& ctx, const G2& pk_V, const NIZKProof& proof, PFC* pfc, const G2& G2_gen) {
    Big c = vAuthChallenge(ctx, pk_V, proof.A, pfc);

    G2 lhs = pfc->mult(G2_gen, proof.z);
    G2 rhs = proof.A + pfc->mult(pk_V, c);

    return lhs == rhs;
}
