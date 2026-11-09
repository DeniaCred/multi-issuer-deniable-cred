#ifndef NIZK_PROOF_H
#define NIZK_PROOF_H

#include <string>
#include "Algorithm/pairing_3.h"
#include "protocol_parameters.h"

using namespace std;

struct VerifierKeyPair {
    Big sk_V;
    G2 pk_V;   // pk_V = G2_gen * sk_V
};

struct NIZKProof {
    G2 A;
    Big z;
};

VerifierKeyPair generateVerifierKeyPair(PFC* pfc, const G2& G2_gen);
NIZKProof generateNIZKProof(const string& ctx, const VerifierKeyPair& kp, PFC* pfc, const G2& G2_gen, const ProtocolParameters& pp);
bool verifyNIZKProof(const string& ctx, const G2& pk_V, const NIZKProof& proof, PFC* pfc, const G2& G2_gen, const ProtocolParameters& pp);

#endif // NIZK_PROOF_H
