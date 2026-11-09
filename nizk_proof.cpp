#include "nizk_proof.h"

namespace {

void addStringToHash(PFC* pfc, const string& value) {
    pfc->add_to_hash((char*)value.c_str());
}

Big vAuthChallenge(const string& ctx, const G2& pk_V, const G2& A, PFC* pfc, const ProtocolParameters& pp) {
    std::string input = protocolFrame("domain_VAuth") + protocolFrame(pp.binding) +
        protocolFrame(ctx) + protocolEncodeG2(pk_V, pfc) + protocolEncodeG2(A, pfc);
    return protocolHashScalar(input, pfc);
}

} // namespace

VerifierKeyPair generateVerifierKeyPair(PFC* pfc, const G2& G2_gen) {
    VerifierKeyPair kp;
    kp.sk_V = protocolRandomScalar(pfc, true);
    kp.pk_V = pfc->mult(G2_gen, kp.sk_V);
    return kp;
}

NIZKProof generateNIZKProof(const string& ctx, const VerifierKeyPair& kp, PFC* pfc, const G2& G2_gen, const ProtocolParameters& pp) {
    NIZKProof proof;
    
    Big a;
    a = protocolRandomScalar(pfc, false);
    proof.A = pfc->mult(G2_gen, a);
    
    Big c = vAuthChallenge(ctx, kp.pk_V, proof.A, pfc, pp);
    
    // z = a + c * sk_V mod p
    Big term = modmult(c, kp.sk_V, pfc->order());
    proof.z = (a + term) % pfc->order();
    
    return proof;
}

bool verifyNIZKProof(const string& ctx, const G2& pk_V, const NIZKProof& proof, PFC* pfc, const G2& G2_gen, const ProtocolParameters& pp) {
    if (!protocolValidG2(pk_V, pfc, true) || !protocolValidG2(proof.A, pfc, false) ||
        !protocolScalarValid(proof.z, pfc, false)) return false;
    Big c = vAuthChallenge(ctx, pk_V, proof.A, pfc, pp);

    G2 lhs = pfc->mult(G2_gen, proof.z);
    G2 rhs = proof.A + pfc->mult(pk_V, c);

    return lhs == rhs;
}
