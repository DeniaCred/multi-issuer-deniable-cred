#include <iostream>
#include <vector>
#include <sstream>
#include "Algorithm/pairing_3.h"
#include "multi_issuer.h"
#include "coordinator_certification.h"
#include "nizk_proof.h"
#include "or_proof.h"
#include "utils.h"
#include "protocol_rng.h"
#include <iomanip>
#include <fstream>
#include <chrono>
#include <cstdlib>
#include <algorithm>

std::vector<std::pair<std::string, double>> g_execution_times;

void printSummaryTable() {
    std::cout << "\n" << ANSI_BOLD << ANSI_CYAN << "+--------------------------------------------------------+" << ANSI_RESET << std::endl;
    std::cout << ANSI_BOLD << ANSI_CYAN << "| Timing summary (ms)                                    |" << ANSI_RESET << std::endl;
    std::cout << ANSI_BOLD << ANSI_CYAN << "+--------------------------------------------------------+" << ANSI_RESET << std::endl;

    std::cout << ANSI_BOLD << "| " << std::left << std::setw(39) << "Function" << " | " << std::setw(11) << "Time" << " |" << ANSI_RESET << std::endl;
    std::cout << "+--------------------------------------------------------+" << std::endl;

    for(const auto& entry : g_execution_times) {
        std::cout << "| " << ANSI_YELLOW << std::left << std::setw(39) << entry.first << ANSI_RESET
                  << " | " << ANSI_GREEN << std::right << std::setw(8) << std::fixed << std::setprecision(4) << entry.second << " ms" << ANSI_RESET << " |" << std::endl;
    }
    std::cout << "+--------------------------------------------------------+\n" << std::endl;
}

using namespace std;

void recordExecutionTime(const std::string& label, double duration) {
    emitTimingRecord(label, duration);
}

int main() {
    const bool benchmark_mode = protocolBenchmarkMode();
    g_execution_times.reserve(128);
    ProtocolRng protocol_rng;
    PFC pfc(128, protocol_rng.get()); // BN254 pairing parameter selection
    {
        G2 G2_gen;
        pfc.random(G2_gen);

        G1 G1_gen;
        pfc.random(G1_gen);

        int num_messages;
        if (!benchmark_mode) cout << "Number of attributes (num_messages): ";
        cin >> num_messages;
        ProtocolParameters pp = makeProtocolParameters(&pfc, G1_gen, G2_gen, num_messages);
        vector<Big> messages;
        for (int i = 0; i < num_messages; i++) {
            messages.push_back(Big(12345 + i));
        }

        if (!benchmark_mode) cout << "=== Multi-issuer credential prototype ===" << endl;
        HolderKeyPair holder = generateHolderKeyPair(&pfc, G2_gen);

        G1 h;
        pfc.random(h);
        if (!benchmark_mode) cout << "-> Sampled the common issuance base h in G1." << endl;

        if (!benchmark_mode) cout << "\n[1] Generate issuer keys..." << endl;

        if (!benchmark_mode) cout << "  -> Generate the coordinating issuer key." << endl;
        KeyPair kp_initiator = generateKeyPair(num_messages, &pfc, G2_gen);

        if (!benchmark_mode) cout << "  -> Generate a fresh key for DM." << endl;
        KeyPair kp_dm = generateKeyPair(num_messages, &pfc, G2_gen);

        int num_other_issuers;
        if (!benchmark_mode) cout << "Number of other real issuers (num_other_issuers): ";
        cin >> num_other_issuers;
        if (!benchmark_mode) cout << "  -> " << num_other_issuers << " other real issuers generate keys." << endl;

        vector<KeyPair> other_issuers_kps;
        for (int i = 0; i < num_other_issuers; i++) {
            other_issuers_kps.push_back(generateKeyPair(num_messages, &pfc, G2_gen));
        }

        if (!benchmark_mode) cout << "\n[2] Generate signature shares..." << endl;
        if (!benchmark_mode) cout << "    Share: (h, h^{x_i + sum_j y_{i,j} * m_j})" << endl;

        auto issue_start_time = std::chrono::steady_clock::now();
        vector<SigShare> all_shares;

        SigShare share_initiator = signShare(kp_initiator, messages, h, &pfc);
        all_shares.push_back(share_initiator);

        SigShare share_dm = signShare(kp_dm, messages, h, &pfc);
        all_shares.push_back(share_dm);

        for (int i = 0; i < num_other_issuers; i++) {
            all_shares.push_back(signShare(other_issuers_kps[i], messages, h, &pfc));
        }

        if (!benchmark_mode) cout << "\n[3] Aggregate the signature shares..." << endl;
        SigShare aggregated_sig = aggregateSignatures(all_shares);
        auto issue_end_time = std::chrono::steady_clock::now();
        double issue_duration = std::chrono::duration<double, std::milli>(issue_end_time - issue_start_time).count();
        emitTimingRecord("issueCredential", issue_duration);
        if (!benchmark_mode) cout << "  -> Aggregate credential generated." << endl;

        if (!benchmark_mode) cout << "\n[4] Aggregate issuer public keys..." << endl;
        vector<KeyPair> all_kps;
        all_kps.push_back(kp_initiator);
        all_kps.push_back(kp_dm);
        for (int i = 0; i < num_other_issuers; i++) {
            all_kps.push_back(other_issuers_kps[i]);
        }
        auto aggregate_pk_start_time = std::chrono::steady_clock::now();
        AggregatedPK apk = aggregatePublicKeys(all_kps, num_messages);
        auto aggregate_pk_end_time = std::chrono::steady_clock::now();
        recordExecutionTime(
            "aggregatePublicKeys",
            std::chrono::duration<double, std::milli>(aggregate_pk_end_time - aggregate_pk_start_time).count()
        );
        if (!benchmark_mode) cout << "  -> Aggregate public-key vector generated." << endl;

        if (!benchmark_mode) cout << "\n[5] The coordinating issuer completes aggregation." << endl;

        if (!benchmark_mode) cout << "\n[6] Check the aggregate credential before TA certification..." << endl;
        bool is_valid = verifySignature(apk, aggregated_sig, messages, G2_gen, &pfc, "coordinator");
        if (!is_valid) return -1;

        if (is_valid) {
            if (!benchmark_mode) cout << ANSI_GREEN << "  -> Aggregate credential verified." << ANSI_RESET << endl;
        } else {
            if (!benchmark_mode) cout << ANSI_RED << "  -> Aggregate credential verification failed." << ANSI_RESET << endl;
        }

        if (!benchmark_mode) cout << "\n=== TA certification and randomization demo ===" << endl;

        if (!benchmark_mode) cout << "\n[7] Generate the TA key pair..." << endl;
        CertKeyPair cert_kp = generateCertKeyPair(&pfc, G1_gen);
        if (!benchmark_mode) cout << "  -> TA public keys are in G1 and secret scalars are in Z_p." << endl;

        if (!benchmark_mode) cout << "\n[8] Derive the verification key and request TA certification..." << endl;
        auto derive_vk_coordinator_start_time = std::chrono::steady_clock::now();
        G2 vk_U = deriveVerificationKey(apk, messages, &pfc);
        auto derive_vk_coordinator_end_time = std::chrono::steady_clock::now();
        recordExecutionTime(
            "deriveVkCoordinator",
            std::chrono::duration<double, std::milli>(derive_vk_coordinator_end_time - derive_vk_coordinator_start_time).count()
        );

        if (!benchmark_mode) cout << "  -> The TA certifies (vk_U, pk_U)." << endl;
        auto certify_start_time = std::chrono::steady_clock::now();
        CertSignature cert_sig = certifyCredentialBinding(cert_kp, vk_U, holder.pk_U, &pfc, G2_gen);
        auto certify_end_time = std::chrono::steady_clock::now();
        recordExecutionTime(
            "Certify",
            std::chrono::duration<double, std::milli>(certify_end_time - certify_start_time).count()
        );
        IssuedCredential issued{aggregated_sig, apk, cert_sig};
        if (!benchmark_mode) cout << "  -> Deliver the aggregate credential, public-key vector, and TA certificate." << endl;
        if (!benchmark_mode) cout << "  -> The TA certificate is randomizable." << endl;

        auto derive_vk_user_start_time = std::chrono::steady_clock::now();
        G2 vk_U_user = deriveVerificationKey(issued.aggregate_public_key, messages, &pfc);
        auto derive_vk_user_end_time = std::chrono::steady_clock::now();
        recordExecutionTime(
            "deriveVkUser",
            std::chrono::duration<double, std::milli>(derive_vk_user_end_time - derive_vk_user_start_time).count()
        );
        if (!verifySignature(issued.aggregate_public_key, issued.credential, messages, G2_gen, &pfc, "user") ||
            !verifyCertificate(cert_kp.pk, vk_U_user, holder.pk_U, issued.certificate, &pfc, G1_gen)) return 1;

        Big r_1;
        Big r_2;
        RandomizedCertificate randomized_cert;
        BlindingResult blinding_result;

        if (!benchmark_mode) cout << "\n=== Verifier authentication ===" << endl;

        if (!benchmark_mode) cout << "\n[10] Generate the verifier key pair..." << endl;
        VerifierKeyPair verifier_kp = generateVerifierKeyPair(&pfc, G2_gen);
        string verifier_id = "Verifier-001";
        string verifier_ctx = verifier_id + "|pk-bound-demo|nonce-001|policy-all-attributes|expiry-demo";
        if (!benchmark_mode) cout << "  -> Verifier " << verifier_id << " generated a G2 key pair." << endl;

        if (!benchmark_mode) cout << "\n[11] Generate the verifier proof of knowledge..." << endl;
        auto verifier_auth_gen_start_time = std::chrono::steady_clock::now();
        NIZKProof nizk_proof = generateNIZKProof(verifier_ctx, verifier_kp, &pfc, G2_gen, pp);
        auto verifier_auth_gen_end_time = std::chrono::steady_clock::now();
        recordExecutionTime(
            "verifierAuthNIZKGen",
            std::chrono::duration<double, std::milli>(verifier_auth_gen_end_time - verifier_auth_gen_start_time).count()
        );
        if (!benchmark_mode) cout << "  -> Send the context-bound proof (A, z) to the holder." << endl;

        if (!benchmark_mode) cout << "\n[12] Verify the verifier proof..." << endl;
        auto verifier_auth_verify_start_time = std::chrono::steady_clock::now();
        bool nizk_valid = verifyNIZKProof(verifier_ctx, verifier_kp.pk_V, nizk_proof, &pfc, G2_gen, pp);
        auto verifier_auth_verify_end_time = std::chrono::steady_clock::now();
        recordExecutionTime(
            "verifierAuthNIZKVerify",
            std::chrono::duration<double, std::milli>(verifier_auth_verify_end_time - verifier_auth_verify_start_time).count()
        );
        if (nizk_valid) {
            if (!benchmark_mode) cout << ANSI_GREEN << "  -> Proof of knowledge accepted for " << verifier_id << "." << ANSI_RESET << endl;
            if (!benchmark_mode) cout << "  -> The holder proceeds to blinding." << endl;
        } else {
            if (!benchmark_mode) cout << ANSI_RED << "  -> Verifier authentication failed." << ANSI_RESET << endl;
            return -1;
        }

        auto blind_total_start_time = std::chrono::steady_clock::now();
        r_1 = protocolRandomScalar(&pfc, true);
        r_2 = protocolRandomScalar(&pfc, true);
        auto randomize_certificate_start_time = std::chrono::steady_clock::now();
        randomized_cert = randomizeCertificate(vk_U_user, holder.pk_U, issued.certificate, r_2, &pfc);
        auto randomize_certificate_end_time = std::chrono::steady_clock::now();

        auto blind_credential_start_time = std::chrono::steady_clock::now();
        blinding_result = blindCredential(vk_U_user, holder, issued.credential, r_1, r_2, &pfc, G2_gen, verifier_ctx, pp);
        auto blind_credential_end_time = std::chrono::steady_clock::now();
        auto blind_total_end_time = std::chrono::steady_clock::now();
        recordExecutionTime("blindTotal", std::chrono::duration<double, std::milli>(blind_total_end_time - blind_total_start_time).count());
        recordExecutionTime("randomizeCertificate", std::chrono::duration<double, std::milli>(randomize_certificate_end_time - randomize_certificate_start_time).count());
        recordExecutionTime(
            "blindCredential",
            std::chrono::duration<double, std::milli>(blind_credential_end_time - blind_credential_start_time).count()
        );
        if (!benchmark_mode) cout << "\n[9] Blind the credential and certificate..." << endl;
        if (!benchmark_mode) cout << "  -> Computed the blinded credential, P'_U, and N_V using r_1 and r_2." << endl;

        if (!benchmark_mode) cout << "\n[13] Check the randomized TA certificate..." << endl;
        bool cert_verify_valid = verifyRandomizedCertificate(cert_kp.pk, randomized_cert, &pfc, G1_gen, "standalone");
        if (cert_verify_valid) {
            if (!benchmark_mode) cout << ANSI_GREEN << "  -> Randomized TA certificate verified." << ANSI_RESET << endl;
        } else {
            if (!benchmark_mode) cout << ANSI_RED << "  -> Randomized TA certificate verification failed." << ANSI_RESET << endl;
            return -1;
        }

        if (!benchmark_mode) cout << "\n=== Anonymous presentation ===" << endl;

        if (!benchmark_mode) cout << "\n[14] Generate the presentation OR proof..." << endl;
        PresentationPayload or_payload = generatePresentationPayload(
            blinding_result.credential,
            randomized_cert,
            verifier_kp.pk_V,
            blinding_result.w_U,
            verifier_ctx,
            &pfc,
            G2_gen, pp, ""
        );
        if (!benchmark_mode) cout << "  -> The holder sends the presentation payload." << endl;

        if (!benchmark_mode) cout << "\n[15] Verify the presentation..." << endl;
        bool or_proof_valid = verifyPresentationPayload(cert_kp.pk, or_payload, &pfc, G1_gen, G2_gen, verifier_kp.pk_V, verifier_ctx, pp, "", "real");
        if (!or_proof_valid) return 1;
        if (or_proof_valid) {
            if (!benchmark_mode) cout << ANSI_GREEN << "  -> Presentation accepted." << ANSI_RESET << endl;
            if (!benchmark_mode) cout << ANSI_GREEN << "  -> Protocol run completed." << ANSI_RESET << endl;
        } else {
            if (!benchmark_mode) cout << ANSI_RED << "  -> Presentation verification failed." << ANSI_RESET << endl;
        }

        if (!benchmark_mode) cout << "\n=== Verifier simulation ===" << endl;

        if (!benchmark_mode) cout << "\n[16] Generate a proof for the same blinded material using the verifier secret key..." << endl;
        PresentationPayload faked_payload = simulatePresentationPayloadByVerifier(
            verifier_kp,
            blinding_result.credential,
            randomized_cert,
            verifier_ctx,
            &pfc,
            G2_gen, pp, ""
        );
        if (!benchmark_mode) cout << "  -> The verifier simulates the holder branch and proves the verifier branch." << endl;

        if (!benchmark_mode) cout << "\n[17] Check the simulated presentation..." << endl;
        bool fake_proof_valid = verifyPresentationPayload(cert_kp.pk, faked_payload, &pfc, G1_gen, G2_gen, verifier_kp.pk_V, verifier_ctx, pp, "", "simulated");
        if (!fake_proof_valid) return 1;
        if (fake_proof_valid) {
            if (!benchmark_mode) cout << ANSI_GREEN << "  -> Simulated presentation accepted." << endl;
            if (!benchmark_mode) cout << "     The verifier can also generate an accepted proof for this material." << endl;
            if (!benchmark_mode) cout << "     Simulation uses fixed publicly valid blinded material." << ANSI_RESET << endl;
        } else {
            if (!benchmark_mode) cout << ANSI_RED << "  -> Simulated presentation verification failed." << ANSI_RESET << endl;
            return -1;
        }
        if (!benchmark_mode) printSummaryTable();

        if (!benchmark_mode) {
        std::ofstream outfile("execution_records.txt", std::ios::app);
        if (outfile.is_open()) {
            outfile << "========== Run record ==========\n";
            outfile << "Number of attributes (num_messages): " << num_messages << "\n";
            outfile << "Number of other real issuers (num_other_issuers): " << num_other_issuers << "\n";
            outfile << "Internal contribution count (q_internal): " << (2 + num_other_issuers) << "\n";
            outfile << "+-----------------------------------------+-------------+\n";
            outfile << "| Function                                | Time         |\n";
            outfile << "+-----------------------------------------+-------------+\n";
            for(const auto& entry : g_execution_times) {
                outfile << "| " << std::left << std::setw(39) << entry.first
                        << " | " << std::right << std::setw(8) << std::fixed << std::setprecision(4) << entry.second << " ms |\n";
            }
            outfile << "+-----------------------------------------+-------------+\n";
            outfile << "==================================\n\n";
            outfile.close();
            if (!benchmark_mode) std::cout << ANSI_GREEN << "  -> Appended timing records to execution_records.txt." << ANSI_RESET << std::endl;
        } else {
            std::cerr << ANSI_RED << "  -> Could not open execution_records.txt." << ANSI_RESET << std::endl;
        }
        }
    }

    if (benchmark_mode) {
        for (const auto& entry : g_execution_times) {
            std::cout << ANSI_CYAN << "[Time] " << entry.first << " execution time: "
                      << entry.second << " ms" << ANSI_RESET << std::endl;
        }
    }

    return 0;
}
