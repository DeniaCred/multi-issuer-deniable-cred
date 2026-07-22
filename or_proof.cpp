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

Big randomNonZero(PFC* pfc) {
    Big value;
    do {
        pfc->random(value);
        value = value % pfc->order();
    } while (value == Big(0));
    return value;
}

void addStringToHash(PFC* pfc, const string& value) {
    pfc->add_to_hash((char*)value.c_str());
}

Big hashToScalar(PFC* pfc, const string& domain, const string& ppHash, const string& ctx) {
    pfc->start_hash();
    addStringToHash(pfc, domain);
    addStringToHash(pfc, ppHash);
    addStringToHash(pfc, ctx);
    Big scalar = pfc->finish_hash_to_group() % pfc->order();
    if (scalar == Big(0)) {
        scalar = Big(1);
    }
    return scalar;
}

G2 hashToG2(PFC* pfc, const G2& g_tilde, const string& ppHash, const string& ctx) {
    return pfc->mult(g_tilde, hashToScalar(pfc, "domain_nym", ppHash, ctx));
}

Big hash_or_challenge(const PresentationPayload& payload, const ORProof& proof, PFC* pfc) {
    pfc->start_hash();
    addStringToHash(pfc, "domain_OR");
    addStringToHash(pfc, payload.ppHash);
    addStringToHash(pfc, payload.ctx);
    pfc->add_to_hash(payload.pk_V);
    pfc->add_to_hash(payload.cred.user_apk_prime);
    pfc->add_to_hash(payload.cred.h_prime);
    pfc->add_to_hash(payload.cred.s_prime);
    pfc->add_to_hash(payload.ta_cred.R_prime);
    pfc->add_to_hash(payload.ta_cred.S_prime);
    pfc->add_to_hash(payload.cred.P_prime);
    pfc->add_to_hash(payload.cred.N_V);
    pfc->add_to_hash(proof.A1);
    pfc->add_to_hash(proof.A2);
    pfc->add_to_hash(proof.T_right);
    return pfc->finish_hash_to_group() % pfc->order();
}

bool same_g2(const G2& left, const G2& right) {
    G2 left_copy = left;
    G2 right_copy = right;
    return left_copy == right_copy;
}

} // namespace

HolderSecret generateHolderSecret(PFC* pfc, const G2& g_tilde) {
    HolderSecret holder;
    holder.u_U = randomNonZero(pfc);
    holder.P_U = pfc->mult(g_tilde, holder.u_U);
    return holder;
}

G2 computeUserApk(const AggregatedPK& apk, const vector<Big>& m, PFC* pfc) {
    G2 res = apk.X_agg;
    for (size_t i = 0; i < m.size(); i++) {
        G2 term = pfc->mult(apk.Y_agg[i], m[i]);
        res = res + term;
    }
    return res;
}

BlindingResult blindCredential(
    const G2& user_apk,
    const HolderSecret& holder,
    const SigShare& sig,
    Big r_1,
    Big r_2,
    PFC* pfc,
    const G2& g_tilde,
    const string& ctx,
    const string& ppHash
) {
    BlindingResult result;

    result.credential.user_apk_prime = pfc->mult(user_apk, r_2);
    result.credential.h_prime = pfc->mult(sig.h, r_1);

    Big r_product = modmult(r_1, r_2, pfc->order());
    result.credential.s_prime = pfc->mult(sig.S, r_product);
    result.credential.P_prime = pfc->mult(holder.P_U, r_2);
    result.w_U = modmult(holder.u_U, r_2, pfc->order());

    G2 Q_V = hashToG2(pfc, g_tilde, ppHash, ctx);
    result.credential.N_V = pfc->mult(Q_V, result.w_U);
    return result;
}

PresentationPayload generatePresentationPayload(
    const BlindedCredential& blinded_cred,
    const RandomizedTACredential& ta_cred,
    const G2& pk_V,
    const Big& w_U,
    const string& ctx,
    const string& ppHash,
    PFC* pfc,
    const G2& g_tilde
) {
    auto start_time = std::chrono::high_resolution_clock::now();

    PresentationPayload payload;
    payload.ctx = ctx;
    payload.ppHash = ppHash;
    payload.pk_V = pk_V;
    payload.cred = blinded_cred;
    payload.ta_cred = ta_cred;

    ORProof proof;
    pfc->random(proof.c_right);
    proof.c_right = proof.c_right % pfc->order();
    pfc->random(proof.z_right);
    proof.z_right = proof.z_right % pfc->order();

    Big neg_c_right = mod_sub(Big(0), proof.c_right, pfc);
    proof.T_right = pfc->mult(g_tilde, proof.z_right) + pfc->mult(pk_V, neg_c_right);

    Big a_left;
    pfc->random(a_left);
    a_left = a_left % pfc->order();

    G2 Q_V = hashToG2(pfc, g_tilde, ppHash, ctx);
    proof.A1 = pfc->mult(g_tilde, a_left);
    proof.A2 = pfc->mult(Q_V, a_left);

    Big c_total = hash_or_challenge(payload, proof, pfc);
    proof.c_left = mod_sub(c_total, proof.c_right, pfc);

    Big term = modmult(proof.c_left, w_U, pfc->order());
    proof.z_left = (a_left + term) % pfc->order();

    payload.proof = proof;

    auto end_time = std::chrono::high_resolution_clock::now();
    double duration = std::chrono::duration<double, std::milli>(end_time - start_time).count();
    std::cout << ANSI_CYAN << "[Time] generatePresentationPayload execution time: " << duration << " ms" << ANSI_RESET << std::endl;
    g_execution_times.push_back({"generatePresentationPayload", duration});

    return payload;
}

bool verifyORProof(
    const PresentationPayload& payload,
    PFC* pfc,
    const G1&,
    const G2& g_tilde,
    const std::string& timing_context
) {
    auto start_time = std::chrono::high_resolution_clock::now();
    std::string label = timingLabel("verifyORProof", timing_context);

    const ORProof& proof = payload.proof;
    Big c_total = hash_or_challenge(payload, proof, pfc);
    Big split_sum = mod_add(proof.c_left, proof.c_right, pfc);

    if (split_sum != c_total) {
        cout << "  -> [Debug] Challenge split check passed: " << (split_sum == c_total) << endl;
        auto end_time = std::chrono::high_resolution_clock::now();
        double duration = std::chrono::duration<double, std::milli>(end_time - start_time).count();
        std::cout << ANSI_CYAN << "[Time] " << label << " execution time: " << duration << " ms" << ANSI_RESET << std::endl;
        g_execution_times.push_back({label, duration});
        return false;
    }

    G2 right_lhs = pfc->mult(g_tilde, proof.z_right);
    G2 right_rhs = proof.T_right + pfc->mult(payload.pk_V, proof.c_right);
    if (!(right_lhs == right_rhs)) {
        cout << "  -> [Debug] Right side check passed: " << (right_lhs == right_rhs) << endl;
        auto end_time = std::chrono::high_resolution_clock::now();
        double duration = std::chrono::duration<double, std::milli>(end_time - start_time).count();
        std::cout << ANSI_CYAN << "[Time] " << label << " execution time: " << duration << " ms" << ANSI_RESET << std::endl;
        g_execution_times.push_back({label, duration});
        return false;
    }

    G2 Q_V = hashToG2(pfc, g_tilde, payload.ppHash, payload.ctx);

    G2 left1_lhs = pfc->mult(g_tilde, proof.z_left);
    G2 left1_rhs = proof.A1 + pfc->mult(payload.cred.P_prime, proof.c_left);
    if (!(left1_lhs == left1_rhs)) {
        cout << "  -> [Debug] Holder P' branch check passed: " << (left1_lhs == left1_rhs) << endl;
        auto end_time = std::chrono::high_resolution_clock::now();
        double duration = std::chrono::duration<double, std::milli>(end_time - start_time).count();
        std::cout << ANSI_CYAN << "[Time] " << label << " execution time: " << duration << " ms" << ANSI_RESET << std::endl;
        g_execution_times.push_back({label, duration});
        return false;
    }

    G2 left2_lhs = pfc->mult(Q_V, proof.z_left);
    G2 left2_rhs = proof.A2 + pfc->mult(payload.cred.N_V, proof.c_left);
    if (!(left2_lhs == left2_rhs)) {
        cout << "  -> [Debug] Holder N_V branch check passed: " << (left2_lhs == left2_rhs) << endl;
        auto end_time = std::chrono::high_resolution_clock::now();
        double duration = std::chrono::duration<double, std::milli>(end_time - start_time).count();
        std::cout << ANSI_CYAN << "[Time] " << label << " execution time: " << duration << " ms" << ANSI_RESET << std::endl;
        g_execution_times.push_back({label, duration});
        return false;
    }

    auto end_time = std::chrono::high_resolution_clock::now();
    double duration = std::chrono::duration<double, std::milli>(end_time - start_time).count();
    std::cout << ANSI_CYAN << "[Time] " << label << " execution time: " << duration << " ms" << ANSI_RESET << std::endl;
    g_execution_times.push_back({label, duration});

    return true;
}

bool verifyBlindedAggregateCredential(
    const BlindedCredential& cred,
    PFC* pfc,
    const G2& g_tilde,
    const std::string& timing_context
) {
    auto start_time = std::chrono::high_resolution_clock::now();

    GT lhs = pfc->pairing(g_tilde, cred.s_prime);
    GT rhs = pfc->pairing(cred.user_apk_prime, cred.h_prime);
    auto end_time = std::chrono::high_resolution_clock::now();
    double duration = std::chrono::duration<double, std::milli>(end_time - start_time).count();
    std::string label = timingLabel("verifyBlindedAggregateCredential", timing_context);
    std::cout << ANSI_CYAN << "[Time] " << label << " execution time: " << duration << " ms" << ANSI_RESET << std::endl;
    g_execution_times.push_back({label, duration});

    return lhs == rhs;
}

bool verifyPresentationPayload(
    const TAPublicKey& ta_pk,
    const PresentationPayload& payload,
    PFC* pfc,
    const G1& g,
    const G2& g_tilde,
    const G2& expected_pk_V,
    const string& expected_ctx,
    const string& expected_ppHash,
    const std::string& timing_context
) {
    auto start_time = std::chrono::high_resolution_clock::now();
    bool valid = false;

    if (!expected_ctx.empty() && payload.ctx != expected_ctx) {
        cout << "  -> [Debug] Presentation context mismatch." << endl;
    } else if (payload.ppHash != expected_ppHash) {
        cout << "  -> [Debug] Presentation parameter digest mismatch." << endl;
    } else if (!same_g2(payload.pk_V, expected_pk_V)) {
        cout << "  -> [Debug] Presentation verifier public key mismatch." << endl;
    } else if (!same_g2(payload.ta_cred.user_apk_prime, payload.cred.user_apk_prime)) {
        cout << "  -> [Debug] TA credential apk' does not match presentation apk'." << endl;
    } else if (!same_g2(payload.ta_cred.P_prime, payload.cred.P_prime)) {
        cout << "  -> [Debug] TA credential P' does not match presentation P'." << endl;
    } else if (!verifyRandomizedTACredential(ta_pk, payload.ta_cred, pfc, g, timing_context)) {
        valid = false;
    } else if (!verifyBlindedAggregateCredential(payload.cred, pfc, g_tilde, timing_context)) {
        cout << "  -> [Debug] Blinded aggregate credential equation failed." << endl;
        valid = false;
    } else {
        valid = verifyORProof(payload, pfc, g, g_tilde, timing_context);
    }

    auto end_time = std::chrono::high_resolution_clock::now();
    double duration = std::chrono::duration<double, std::milli>(end_time - start_time).count();
    std::string label = timingLabel("verifyPresentationPayload_total", timing_context);
    std::cout << ANSI_CYAN << "[Time] " << label << " execution time: " << duration << " ms" << ANSI_RESET << std::endl;
    g_execution_times.push_back({label, duration});
    return valid;
}

bool simulatePresentationPayloadByVerifier(
    const VerifierKeyPair& kp_V,
    const NIZKProof& vauth_proof,
    const BlindedCredential& blinded_cred,
    const RandomizedTACredential& ta_cred,
    const string& ctx,
    const string& ppHash,
    PFC* pfc,
    const G2& g_tilde,
    PresentationPayload& simulated_payload
) {
    auto start_time = std::chrono::high_resolution_clock::now();

    if (!verifyNIZKProof(ctx, ppHash, kp_V.pk_V, vauth_proof, pfc, g_tilde)) {
        return false;
    }

    PresentationPayload payload;
    payload.ctx = ctx;
    payload.ppHash = ppHash;
    payload.pk_V = kp_V.pk_V;
    payload.cred = blinded_cred;
    payload.ta_cred = ta_cred;

    ORProof proof;
    pfc->random(proof.c_left);
    proof.c_left = proof.c_left % pfc->order();
    pfc->random(proof.z_left);
    proof.z_left = proof.z_left % pfc->order();

    Big neg_c_left = mod_sub(Big(0), proof.c_left, pfc);
    G2 Q_V = hashToG2(pfc, g_tilde, ppHash, ctx);
    proof.A1 = pfc->mult(g_tilde, proof.z_left) + pfc->mult(payload.cred.P_prime, neg_c_left);
    proof.A2 = pfc->mult(Q_V, proof.z_left) + pfc->mult(payload.cred.N_V, neg_c_left);

    Big k_right;
    pfc->random(k_right);
    k_right = k_right % pfc->order();
    proof.T_right = pfc->mult(g_tilde, k_right);

    Big c_total = hash_or_challenge(payload, proof, pfc);
    proof.c_right = mod_sub(c_total, proof.c_left, pfc);

    Big term = modmult(proof.c_right, kp_V.sk_V, pfc->order());
    proof.z_right = (k_right + term) % pfc->order();

    payload.proof = proof;

    auto end_time = std::chrono::high_resolution_clock::now();
    double duration = std::chrono::duration<double, std::milli>(end_time - start_time).count();
    std::cout << ANSI_CYAN << "[Time] simulatePresentationPayloadByVerifier execution time: " << duration << " ms" << ANSI_RESET << std::endl;
    g_execution_times.push_back({"simulatePresentationPayloadByVerifier", duration});

    simulated_payload = payload;
    return true;
}
