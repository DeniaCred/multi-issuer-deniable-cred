#include "or_proof.h"
#include <chrono>
#include <iostream>
#include "utils.h"

namespace {

Big mod_add(const Big& a, const Big& b, PFC* pfc) {
    return (a + b) % pfc->order();
}

Big mod_sub(const Big& a, const Big& b, PFC* pfc) {
    return (a + pfc->order() - b) % pfc->order();
}

G2 hashToG2(PFC* pfc, const G2& g_tilde, const string& ctx, const ProtocolParameters& pp) {
    (void)g_tilde;
    return protocolHashToG2(pp, ctx, pfc);
}

Big hash_or_challenge(const PresentationPayload& payload, const ORProof& proof, PFC* pfc, const ProtocolParameters& pp, const std::string& mu) {
    std::string input = protocolFrame("domain_OR") + protocolFrame(pp.binding) + protocolFrame(payload.ctx) + protocolFrame(mu);
    input += protocolEncodeG2(payload.pk_V,pfc) + protocolEncodeG2(payload.cred.vk_U_prime,pfc);
    input += protocolEncodeG1(payload.cred.h_prime,pfc) + protocolEncodeG1(payload.cred.s_prime,pfc);
    input += protocolEncodeG2(payload.cert.R_c_prime,pfc) + protocolEncodeG2(payload.cert.S_c_prime,pfc);
    input += protocolEncodeG2(payload.cred.pk_U_prime,pfc) + protocolEncodeG2(payload.cred.N_V,pfc);
    input += protocolEncodeG2(proof.A1,pfc) + protocolEncodeG2(proof.A2,pfc) + protocolEncodeG2(proof.T_right,pfc);
    return protocolHashScalar(input,pfc);
}

bool same_g2(const G2& left, const G2& right) {
    G2 left_copy = left;
    G2 right_copy = right;
    return left_copy == right_copy;
}

} // namespace

HolderKeyPair generateHolderKeyPair(PFC* pfc, const G2& g_tilde) {
    HolderKeyPair holder;
    holder.sk_U = protocolRandomScalar(pfc, true);
    holder.pk_U = pfc->mult(g_tilde, holder.sk_U);
    return holder;
}

G2 deriveVerificationKey(const AggregatedPK& apk, const vector<Big>& m, PFC* pfc) {
    if (!pfc || m.empty() || apk.Y_agg.size() != m.size() || !protocolValidG2(apk.X_agg, pfc, false)) throw std::invalid_argument("invalid aggregate public-key vector");
    for (size_t i = 0; i < m.size(); ++i)
        if (!protocolScalarValid(m[i], pfc, false) || !protocolValidG2(apk.Y_agg[i], pfc, false)) throw std::invalid_argument("invalid aggregate public-key entry");
    G2 res = apk.X_agg;
    for (size_t i = 0; i < m.size(); i++) {
        G2 term = pfc->mult(apk.Y_agg[i], m[i]);
        res = res + term;
    }
    return res;
}

BlindingResult blindCredential(
    const G2& vk_U,
    const HolderKeyPair& holder,
    const SigShare& sig,
    Big r_1,
    Big r_2,
    PFC* pfc,
    const G2& g_tilde,
    const string& ctx, const ProtocolParameters& pp
) {
    if (!protocolScalarValid(r_1,pfc,true) || !protocolScalarValid(r_2,pfc,true) || !protocolScalarValid(holder.sk_U,pfc,true)) throw std::invalid_argument("invalid blinding scalar");
    BlindingResult result;

    result.credential.vk_U_prime = pfc->mult(vk_U, r_2);
    result.credential.h_prime = pfc->mult(sig.h, r_1);

    Big r_product = modmult(r_1, r_2, pfc->order());
    result.credential.s_prime = pfc->mult(sig.S, r_product);
    result.credential.pk_U_prime = pfc->mult(holder.pk_U, r_2);
    result.w_U = modmult(holder.sk_U, r_2, pfc->order());

    G2 Q_V = hashToG2(pfc, g_tilde, ctx, pp);
    result.credential.N_V = pfc->mult(Q_V, result.w_U);
    return result;
}

PresentationPayload generatePresentationPayload(
    const BlindedCredential& blinded_cred,
    const RandomizedCertificate& cert,
    const G2& pk_V,
    const Big& w_U,
    const string& ctx,
    PFC* pfc,
    const G2& g_tilde, const ProtocolParameters& pp, const std::string& mu
) {
    auto start_time = std::chrono::steady_clock::now();

    PresentationPayload payload;
    payload.ctx = ctx;
    payload.pk_V = pk_V;
    payload.cred = blinded_cred;
    payload.cert = cert;

    ORProof proof;
    proof.c_right = protocolRandomScalar(pfc, false);
    proof.z_right = protocolRandomScalar(pfc, false);

    Big neg_c_right = mod_sub(Big(0), proof.c_right, pfc);
    proof.T_right = pfc->mult(g_tilde, proof.z_right) + pfc->mult(pk_V, neg_c_right);

    Big a_left;
    a_left = protocolRandomScalar(pfc, false);

    G2 Q_V = hashToG2(pfc, g_tilde, ctx, pp);
    proof.A1 = pfc->mult(g_tilde, a_left);
    proof.A2 = pfc->mult(Q_V, a_left);

    Big c_total = hash_or_challenge(payload, proof, pfc, pp, mu);
    proof.c_left = mod_sub(c_total, proof.c_right, pfc);

    Big term = modmult(proof.c_left, w_U, pfc->order());
    proof.z_left = (a_left + term) % pfc->order();

    payload.proof = proof;

    auto end_time = std::chrono::steady_clock::now();
    double duration = std::chrono::duration<double, std::milli>(end_time - start_time).count();
    emitTimingRecord("presentProof", duration);

    return payload;
}

bool verifyORProof(
    const PresentationPayload& payload,
    PFC* pfc,
    const G1&,
    const G2& g_tilde,
    const ProtocolParameters& pp, const std::string& mu, const std::string& timing_context
) {
    auto start_time = std::chrono::steady_clock::now();
    std::string label = timingLabel("verifyORProof", timing_context);

    const ORProof& proof = payload.proof;
    if (!protocolValidG2(payload.pk_V,pfc,true) || !protocolValidG2(payload.cred.pk_U_prime,pfc,true) ||
        !protocolValidG2(payload.cred.N_V,pfc,true) || !protocolValidG2(proof.A1,pfc,false) ||
        !protocolValidG2(proof.A2,pfc,false) || !protocolValidG2(proof.T_right,pfc,false) ||
        !protocolScalarValid(proof.c_left,pfc,false) || !protocolScalarValid(proof.c_right,pfc,false) ||
        !protocolScalarValid(proof.z_left,pfc,false) || !protocolScalarValid(proof.z_right,pfc,false)) return false;
    Big c_total = hash_or_challenge(payload, proof, pfc, pp, mu);
    Big split_sum = mod_add(proof.c_left, proof.c_right, pfc);

    if (split_sum != c_total) {
        if (!protocolBenchmarkMode()) cout << "  -> [Debug] Challenge split check passed: " << (split_sum == c_total) << endl;
        auto end_time = std::chrono::steady_clock::now();
        double duration = std::chrono::duration<double, std::milli>(end_time - start_time).count();
        emitTimingRecord(label, duration);
        return false;
    }

    G2 right_lhs = pfc->mult(g_tilde, proof.z_right);
    G2 right_rhs = proof.T_right + pfc->mult(payload.pk_V, proof.c_right);
    if (!(right_lhs == right_rhs)) {
        if (!protocolBenchmarkMode()) cout << "  -> [Debug] Right side check passed: " << (right_lhs == right_rhs) << endl;
        auto end_time = std::chrono::steady_clock::now();
        double duration = std::chrono::duration<double, std::milli>(end_time - start_time).count();
        emitTimingRecord(label, duration);
        return false;
    }

    G2 Q_V = hashToG2(pfc, g_tilde, payload.ctx, pp);

    G2 left1_lhs = pfc->mult(g_tilde, proof.z_left);
    G2 left1_rhs = proof.A1 + pfc->mult(payload.cred.pk_U_prime, proof.c_left);
    if (!(left1_lhs == left1_rhs)) {
        if (!protocolBenchmarkMode()) cout << "  -> [Debug] Holder P' branch check passed: " << (left1_lhs == left1_rhs) << endl;
        auto end_time = std::chrono::steady_clock::now();
        double duration = std::chrono::duration<double, std::milli>(end_time - start_time).count();
        emitTimingRecord(label, duration);
        return false;
    }

    G2 left2_lhs = pfc->mult(Q_V, proof.z_left);
    G2 left2_rhs = proof.A2 + pfc->mult(payload.cred.N_V, proof.c_left);
    if (!(left2_lhs == left2_rhs)) {
        if (!protocolBenchmarkMode()) cout << "  -> [Debug] Holder N_V branch check passed: " << (left2_lhs == left2_rhs) << endl;
        auto end_time = std::chrono::steady_clock::now();
        double duration = std::chrono::duration<double, std::milli>(end_time - start_time).count();
        emitTimingRecord(label, duration);
        return false;
    }

    auto end_time = std::chrono::steady_clock::now();
    double duration = std::chrono::duration<double, std::milli>(end_time - start_time).count();
    emitTimingRecord(label, duration);

    return true;
}

bool verifyBlindedAggregateCredential(
    const BlindedCredential& cred,
    PFC* pfc,
    const G2& g_tilde,
    const ProtocolParameters& pp, const std::string& timing_context
) {
    auto start_time = std::chrono::steady_clock::now();

    if (!protocolValidG1(cred.h_prime, pfc, true) || !protocolValidG1(cred.s_prime, pfc, true) ||
        !protocolValidG2(cred.vk_U_prime, pfc, true)) return false;

    GT lhs = pfc->pairing(g_tilde, cred.s_prime);
    GT rhs = pfc->pairing(cred.vk_U_prime, cred.h_prime);
    auto end_time = std::chrono::steady_clock::now();
    double duration = std::chrono::duration<double, std::milli>(end_time - start_time).count();
    std::string label = timingLabel("verifyBlindedAggregateCredential", timing_context);
    emitTimingRecord(label, duration);

    return lhs == rhs;
}

bool verifyPresentationPayload(
    const CertPublicKey& cert_pk,
    const PresentationPayload& payload,
    PFC* pfc,
    const G1& g,
    const G2& g_tilde,
    const G2& expected_pk_V,
    const string& expected_ctx, const ProtocolParameters& pp, const std::string& mu, const std::string& timing_context
) {
    auto start_time = std::chrono::steady_clock::now();
    bool valid = false;

    if (payload.ctx != expected_ctx) {
        if (!protocolBenchmarkMode()) cout << "  -> [Debug] Presentation context mismatch." << endl;
    } else if (!same_g2(payload.pk_V, expected_pk_V)) {
        if (!protocolBenchmarkMode()) cout << "  -> [Debug] Presentation verifier public key mismatch." << endl;
    } else if (!same_g2(payload.cert.vk_U_prime, payload.cred.vk_U_prime)) {
        if (!protocolBenchmarkMode()) cout << "  -> [Debug] Certificate vk_U' does not match presentation vk_U'." << endl;
    } else if (!same_g2(payload.cert.pk_U_prime, payload.cred.pk_U_prime)) {
        if (!protocolBenchmarkMode()) cout << "  -> [Debug] Certificate pk_U' does not match presentation pk_U'." << endl;
    } else if (!verifyRandomizedCertificate(cert_pk, payload.cert, pfc, g, timing_context)) {
        valid = false;
    } else if (!verifyBlindedAggregateCredential(payload.cred, pfc, g_tilde, pp, timing_context)) {
        if (!protocolBenchmarkMode()) cout << "  -> [Debug] Blinded aggregate credential equation failed." << endl;
        valid = false;
    } else {
        valid = verifyORProof(payload, pfc, g, g_tilde, pp, mu, timing_context);
    }

    auto end_time = std::chrono::steady_clock::now();
    double duration = std::chrono::duration<double, std::milli>(end_time - start_time).count();
    std::string label = timingLabel("verifyPresentationPayload_total", timing_context);
    emitTimingRecord(label, duration);
    return valid;
}

PresentationPayload simulatePresentationPayloadByVerifier(
    const VerifierKeyPair& kp_V,
    const BlindedCredential& blinded_cred,
    const RandomizedCertificate& cert,
    const string& ctx,
    PFC* pfc,
    const G2& g_tilde, const ProtocolParameters& pp, const std::string& mu
) {
    auto start_time = std::chrono::steady_clock::now();

    PresentationPayload payload;
    payload.ctx = ctx;
    payload.pk_V = kp_V.pk_V;
    payload.cred = blinded_cred;
    payload.cert = cert;

    ORProof proof;
    proof.c_left = protocolRandomScalar(pfc, false);
    proof.z_left = protocolRandomScalar(pfc, false);

    Big neg_c_left = mod_sub(Big(0), proof.c_left, pfc);
    G2 Q_V = hashToG2(pfc, g_tilde, ctx, pp);
    proof.A1 = pfc->mult(g_tilde, proof.z_left) + pfc->mult(payload.cred.pk_U_prime, neg_c_left);
    proof.A2 = pfc->mult(Q_V, proof.z_left) + pfc->mult(payload.cred.N_V, neg_c_left);

    Big k_right;
    k_right = protocolRandomScalar(pfc, false);
    proof.T_right = pfc->mult(g_tilde, k_right);

    Big c_total = hash_or_challenge(payload, proof, pfc, pp, mu);
    proof.c_right = mod_sub(c_total, proof.c_left, pfc);

    Big term = modmult(proof.c_right, kp_V.sk_V, pfc->order());
    proof.z_right = (k_right + term) % pfc->order();

    payload.proof = proof;

    auto end_time = std::chrono::steady_clock::now();
    double duration = std::chrono::duration<double, std::milli>(end_time - start_time).count();
    emitTimingRecord("simulatePresentationPayloadByVerifier", duration);

    return payload;
}
