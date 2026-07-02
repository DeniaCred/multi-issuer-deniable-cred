#ifndef OR_PROOF_H
#define OR_PROOF_H

#include <string>
#include <vector>
#include "Algorithm/pairing_3.h"
#include "multi_issuer.h"
#include "nizk_proof.h"
#include "trusted_authority.h"

using namespace std;

struct HolderSecret {
    Big u_U;
    G2 P_U;
};

struct BlindedCredential {
    G2 user_apk_prime;
    G1 h_prime;
    G1 s_prime;
    G2 P_prime;
    G2 N_V;
};

struct BlindingResult {
    BlindedCredential credential;
    Big w_U;
};

struct ORProof {
    Big c_left;
    G2 A1;
    G2 A2;
    Big z_left;

    Big c_right;
    G2 T_right;
    Big z_right;
};

struct PresentationPayload {
    string ctx;
    ORProof proof;
    G2 pk_V;
    BlindedCredential cred;
    RandomizedTACredential ta_cred;
};

HolderSecret generateHolderSecret(PFC* pfc, const G2& g_tilde);
G2 computeUserApk(const AggregatedPK& apk, const vector<Big>& m, PFC* pfc);
BlindingResult blindCredential(const G2& user_apk, const HolderSecret& holder, const SigShare& sig, Big r_1, Big r_2, PFC* pfc, const G2& g_tilde, const string& ctx);

PresentationPayload generatePresentationPayload(
    const BlindedCredential& blinded_cred,
    const RandomizedTACredential& ta_cred,
    const G2& pk_V,
    const Big& w_U,
    const string& ctx,
    PFC* pfc,
    const G2& g_tilde
);

bool verifyORProof(
    const PresentationPayload& payload,
    PFC* pfc,
    const G1& g,
    const G2& g_tilde,
    const std::string& timing_context = ""
);
bool verifyBlindedAggregateCredential(
    const BlindedCredential& cred,
    PFC* pfc,
    const G2& g_tilde,
    const std::string& timing_context = ""
);
bool verifyPresentationPayload(
    const TAPublicKey& ta_pk,
    const PresentationPayload& payload,
    PFC* pfc,
    const G1& g,
    const G2& g_tilde,
    const G2& expected_pk_V,
    const string& expected_ctx,
    const std::string& timing_context = ""
);

PresentationPayload simulatePresentationPayloadByVerifier(
    const VerifierKeyPair& kp_V,
    const BlindedCredential& blinded_cred,
    const RandomizedTACredential& ta_cred,
    const string& ctx,
    PFC* pfc,
    const G2& g_tilde
);

#endif // OR_PROOF_H
