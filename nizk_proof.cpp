#include "nizk_proof.h"

namespace {

void addStringToHash(PFC* pfc, const string& value) {
    pfc->add_to_hash((char*)value.c_str());
}

Big vAuthChallenge(const string& ctx, const string& ppHash, const G2& pk_V, const G2& A, PFC* pfc) {
    pfc->start_hash();
    addStringToHash(pfc, "domain_VAuth");
    addStringToHash(pfc, ppHash);
    addStringToHash(pfc, ctx);
    pfc->add_to_hash(pk_V);
    pfc->add_to_hash(A);
    return pfc->finish_hash_to_group() % pfc->order();
}

} // namespace

// --- Generate verifier key pair ---
VerifierKeyPair generateVerifierKeyPair(PFC* pfc, const G2& G2_gen) {
    VerifierKeyPair kp;
    pfc->random(kp.sk_V);
    kp.pk_V = pfc->mult(G2_gen, kp.sk_V);
    return kp;
}

// --- Verifier generates a NIZK proof ---
NIZKProof generateNIZKProof(const string& ctx, const string& ppHash, const VerifierKeyPair& kp, PFC* pfc, const G2& G2_gen) {
    NIZKProof proof;
    
    // Step 1: commitment
    Big a;
    pfc->random(a);
    proof.A = pfc->mult(G2_gen, a);
    
    // Step 2: challenge via Fiat-Shamir
    Big c = vAuthChallenge(ctx, ppHash, kp.pk_V, proof.A, pfc);
    
    // Step 3: response
    // z = a + c * sk_V mod p
    Big term = modmult(c, kp.sk_V, pfc->order());
    proof.z = (a + term) % pfc->order();
    
    return proof;
}

// --- User verifies the NIZK proof ---
bool verifyNIZKProof(const string& ctx, const string& ppHash, const G2& pk_V, const NIZKProof& proof, PFC* pfc, const G2& G2_gen) {
    Big c = vAuthChallenge(ctx, ppHash, pk_V, proof.A, pfc);

    G2 lhs = pfc->mult(G2_gen, proof.z);
    G2 rhs = proof.A + pfc->mult(pk_V, c);

    return lhs == rhs;
}
