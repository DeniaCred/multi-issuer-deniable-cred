#ifndef OR_PROOF_H
#define OR_PROOF_H

#include <string>
#include <vector>
#include "Algorithm/pairing_3.h"
#include "multi_issuer.h"
#include "nizk_proof.h"
#include "coordinator_certification.h"
#include "protocol_parameters.h"

using namespace std;

struct HolderKeyPair {
    Big sk_U;
    G2 pk_U;
};

struct BlindedCredential {
    G2 vk_U_prime;
    G1 h_prime;
    G1 s_prime;
    G2 pk_U_prime;
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
    RandomizedCertificate cert;
};

HolderKeyPair generateHolderKeyPair(PFC* pfc, const G2& g_tilde);
G2 deriveVerificationKey(const AggregatedPK& apk_agg, const vector<Big>& m, PFC* pfc);
BlindingResult blindCredential(const G2& vk_U, const HolderKeyPair& holder, const SigShare& sig, Big r_1, Big r_2, PFC* pfc, const G2& g_tilde, const string& ctx, const ProtocolParameters& pp);

PresentationPayload generatePresentationPayload(
    const BlindedCredential& blinded_cred,
    const RandomizedCertificate& cert,
    const G2& pk_V,
    const Big& w_U,
    const string& ctx,
    PFC* pfc,
    const G2& g_tilde, const ProtocolParameters& pp, const std::string& mu = ""
);

bool verifyORProof(
    const PresentationPayload& payload,
    PFC* pfc,
    const G1& g,
    const G2& g_tilde, const ProtocolParameters& pp, const std::string& mu = "", const std::string& timing_context = ""
);
bool verifyBlindedAggregateCredential(
    const BlindedCredential& cred,
    PFC* pfc,
    const G2& g_tilde, const ProtocolParameters& pp, const std::string& timing_context = ""
);
bool verifyPresentationPayload(
    const CertPublicKey& cert_pk,
    const PresentationPayload& payload,
    PFC* pfc,
    const G1& g,
    const G2& g_tilde,
    const G2& expected_pk_V,
    const string& expected_ctx, const ProtocolParameters& pp, const std::string& mu = "", const std::string& timing_context = ""
);

PresentationPayload simulatePresentationPayloadByVerifier(
    const VerifierKeyPair& kp_V,
    const BlindedCredential& blinded_cred,
    const RandomizedCertificate& cert,
    const string& ctx,
    PFC* pfc,
    const G2& g_tilde, const ProtocolParameters& pp, const std::string& mu = ""
);

#endif // OR_PROOF_H
