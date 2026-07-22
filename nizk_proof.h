#ifndef NIZK_PROOF_H
#define NIZK_PROOF_H

#include <string>
#include "Algorithm/pairing_3.h"

using namespace std;

// 1. Verifier key pair
struct VerifierKeyPair {
    Big sk_V;
    G2 pk_V;   // pk_V = G2_gen * sk_V
};

// 2. NIZK proof structure
struct NIZKProof {
    G2 A;  // Commitment A = g_2^a
    Big z; // Response z = a + c * sk_V
};

// Function declarations
VerifierKeyPair generateVerifierKeyPair(PFC* pfc, const G2& G2_gen);
NIZKProof generateNIZKProof(const string& ctx, const string& ppHash, const VerifierKeyPair& kp, PFC* pfc, const G2& G2_gen);
bool verifyNIZKProof(const string& ctx, const string& ppHash, const G2& pk_V, const NIZKProof& proof, PFC* pfc, const G2& G2_gen);

#endif // NIZK_PROOF_H
