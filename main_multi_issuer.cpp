#include <iostream>
#include <vector>
#include <sstream>
#include "Algorithm/pairing_3.h"
#include "multi_issuer.h"
#include "trusted_authority.h"
#include "nizk_proof.h"
#include "or_proof.h"
#include "utils.h"
#include <iomanip>
#include <fstream>
#include <chrono>

std::vector<std::pair<std::string, double>> g_execution_times;

void printSummaryTable() {
    std::cout << "\n" << ANSI_BOLD << ANSI_CYAN << "+--------------------------------------------------------+" << ANSI_RESET << std::endl;
    std::cout << ANSI_BOLD << ANSI_CYAN << "|                   Performance Summary (ms)                  |" << ANSI_RESET << std::endl;
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

Big randomNonZeroScalar(PFC& pfc) {
    Big value;
    do {
        pfc.random(value);
        value = value % pfc.order();
    } while (value == Big(0));
    return value;
}

void recordExecutionTime(const std::string& label, double duration) {
    std::cout << ANSI_CYAN << "[Time] " << label << " execution time: " << duration << " ms" << ANSI_RESET << std::endl;
    g_execution_times.push_back({label, duration});
}

int main() {
    PFC pfc(128); // 128-bit security BN curve environment initialization
    {
        G2 G2_gen;
        pfc.random(G2_gen); // global base point in G2
        
        G1 G1_gen;
        pfc.random(G1_gen); // global base point in G1
        const string ppHash = deriveProtocolParameterDigest(&pfc, G1_gen, G2_gen);
        
        int num_messages;
        cout << "Enter the number of messages/attributes (num_messages): ";
        cin >> num_messages;
        vector<Big> messages;
        for (int i = 0; i < num_messages; i++) {
            messages.push_back(Big(12345 + i)); // synthetic user attributes
        }
        
        cout << "=== PS Multi-Issuer Credential Prototype Demo ===" << endl;
        
        // AggIssue samples the issuance base h.
        G1 h;
        pfc.random(h);
        cout << "-> The coordinating issuer samples issuance base h in G1." << endl;
        
        cout << "\n[1] Parties generate their key pairs..." << endl;
        
        cout << "  -> The coordinating issuer generates its own key pair..." << endl;
        KeyPair kp_initiator = generateKeyPair(num_messages, &pfc, G2_gen);
        
        cout << "  -> The coordinating issuer internally generates the one-time virtual issuer DM key pair..." << endl;
        KeyPair kp_dm = generateKeyPair(num_messages, &pfc, G2_gen); 
        
        int num_other_issuers;
        cout << "Enter the number of other cooperating issuers (num_other_issuers): ";
        cin >> num_other_issuers;
        cout << "  -> " << num_other_issuers << "  other cooperating issuers generate their key pairs..." << endl;
        
        vector<KeyPair> other_issuers_kps;
        for (int i = 0; i < num_other_issuers; i++) {
            other_issuers_kps.push_back(generateKeyPair(num_messages, &pfc, G2_gen));
        }
        
        cout << "\n[2] Each issuer generates a signature share over h..." << endl;
        cout << "    Signature form: (h, h^{x_i + \\Sigma y_{i,j} * m_j})" << endl;
        
        auto issue_start_time = std::chrono::high_resolution_clock::now();
        vector<SigShare> all_shares;
        
        SigShare share_initiator = signShare(kp_initiator, messages, h, &pfc);
        all_shares.push_back(share_initiator);
        
        SigShare share_dm = signShare(kp_dm, messages, h, &pfc);
        all_shares.push_back(share_dm);
        
        for (int i = 0; i < num_other_issuers; i++) {
            all_shares.push_back(signShare(other_issuers_kps[i], messages, h, &pfc));
        }
        
        cout << "\n[3] The coordinating issuer collects and aggregates all signature shares..." << endl;
        SigShare aggregated_sig = aggregateSignatures(all_shares);
        auto issue_end_time = std::chrono::high_resolution_clock::now();
        double issue_duration = std::chrono::duration<double, std::milli>(issue_end_time - issue_start_time).count();
        std::cout << ANSI_CYAN << "[Time] issueCredential execution time: " << issue_duration << " ms" << ANSI_RESET << std::endl;
        g_execution_times.push_back({"issueCredential", issue_duration});
        cout << "  -> Aggregate signature (h, S_agg) generated." << endl;
        
        cout << "\n[4] The coordinating issuer aggregates all participant public keys into APK..." << endl;
        vector<KeyPair> all_kps;
        all_kps.push_back(kp_initiator);     // initiator
        all_kps.push_back(kp_dm);            // DM
        for (int i = 0; i < num_other_issuers; i++) {
            all_kps.push_back(other_issuers_kps[i]); // other issuer
        }
        auto aggregate_pk_start_time = std::chrono::high_resolution_clock::now();
        AggregatedPK apk = aggregatePublicKeys(all_kps, num_messages);
        auto aggregate_pk_end_time = std::chrono::high_resolution_clock::now();
        recordExecutionTime(
            "aggregatePublicKeys",
            std::chrono::duration<double, std::milli>(aggregate_pk_end_time - aggregate_pk_start_time).count()
        );
        cout << "  -> Aggregate public key apk (X_agg, Y_agg) generated." << endl;
        
        cout << "\n[5] Return APK and the aggregate credential to the user..." << endl;
        
        cout << "\n[6] The user/verifier checks the aggregate credential with apk..." << endl;
        bool is_valid = verifySignature(apk, aggregated_sig, messages, G2_gen, &pfc);
        
        if (is_valid) {
            cout << ANSI_GREEN << "  -> [OK] Aggregate credential and opaque aggregate public-key vector are algebraically consistent." << ANSI_RESET << endl;
        } else {
            cout << ANSI_RED << "  -> [FAIL] Verification failed." << ANSI_RESET << endl;
        }
        
        cout << "\n=== TA Certificate and Randomization Demo ===" << endl;
        
        cout << "\n[7] TA generates a key pair..." << endl;
        TAKeyPair ta_kp = generateTAKeyPair(&pfc, G1_gen);
        cout << "  -> TA generated a public key in G1 and a secret key in Z_p." << endl;
        
        cout << "\n[8] TA certifies the user's derived aggregate verification key user_apk and holder public key P_U..." << endl;
        // Compute user_apk = X_agg + \sum m_i * Y_agg[i].
        auto compute_user_apk_start_time = std::chrono::high_resolution_clock::now();
        G2 user_apk = computeUserApk(apk, messages, &pfc);
        auto compute_user_apk_end_time = std::chrono::high_resolution_clock::now();
        recordExecutionTime(
            "computeUserApk",
            std::chrono::duration<double, std::milli>(compute_user_apk_end_time - compute_user_apk_start_time).count()
        );

        HolderSecret holder = generateHolderSecret(&pfc, G2_gen);

        auto ta_cert_start_time = std::chrono::high_resolution_clock::now();
        TASignature ta_sig = signUserApk(ta_kp, user_apk, holder.P_U, &pfc, G2_gen);
        auto ta_cert_end_time = std::chrono::high_resolution_clock::now();
        recordExecutionTime(
            "TACert",
            std::chrono::duration<double, std::milli>(ta_cert_end_time - ta_cert_start_time).count()
        );
        cout << "  -> TA creates a randomizable certificate (R, S) for (user_apk, P_U)." << endl;
        
        Big r_1;
        Big r_2;
        RandomizedTACredential rand_ta_cred;
        BlindingResult blinding_result;
        
        cout << "\n=== Verifier NIZK Authentication Demo ===" << endl;
        
        cout << "\n[10] The verifier creates a key pair for receiving presentations..." << endl;
        VerifierKeyPair verifier_kp = generateVerifierKeyPair(&pfc, G2_gen);
        string verifier_id = "Verifier-001";
        string verifier_ctx = verifier_id + "|pk_V=" + encodeG2ForContext(verifier_kp.pk_V)
            + "|nonce=nonce-001|session=session-ref-001|policy=all-attributes|expiry=expiry-demo";
        cout << "  -> Verifier " << verifier_id << " generated a key pair over G2." << endl;
        
        cout << "\n[11] The verifier sends a NIZK proof of key possession..." << endl;
        auto verifier_auth_gen_start_time = std::chrono::high_resolution_clock::now();
        NIZKProof nizk_proof = generateNIZKProof(verifier_ctx, ppHash, verifier_kp, &pfc, G2_gen);
        auto verifier_auth_gen_end_time = std::chrono::high_resolution_clock::now();
        recordExecutionTime(
            "verifierAuthNIZKGen",
            std::chrono::duration<double, std::milli>(verifier_auth_gen_end_time - verifier_auth_gen_start_time).count()
        );
        cout << "  -> The verifier sends a session-bound NIZK proof (A, z) to the user." << endl;
        
        cout << "\n[12] The user verifies the verifier authentication proof..." << endl;
        auto verifier_auth_verify_start_time = std::chrono::high_resolution_clock::now();
        bool nizk_valid = verifyNIZKProof(verifier_ctx, ppHash, verifier_kp.pk_V, nizk_proof, &pfc, G2_gen);
        auto verifier_auth_verify_end_time = std::chrono::high_resolution_clock::now();
        recordExecutionTime(
            "verifierAuthNIZKVerify",
            std::chrono::duration<double, std::milli>(verifier_auth_verify_end_time - verifier_auth_verify_start_time).count()
        );
        if (nizk_valid) {
            cout << ANSI_GREEN << "  -> [OK] Verifier NIZK accepted; the user confirmed that " << verifier_id << " holds the corresponding secret key." << ANSI_RESET << endl;
            cout << "  -> The user proceeds to present the blinded credential to this verifier..." << endl;
        } else {
            cout << ANSI_RED << "  -> [FAIL] Verifier NIZK rejected; the user refuses to present the credential." << ANSI_RESET << endl;
            return -1; // abort execution
        }

        auto present_total_start_time = std::chrono::high_resolution_clock::now();
        r_1 = randomNonZeroScalar(pfc);
        r_2 = randomNonZeroScalar(pfc);
        auto randomize_ta_start_time = std::chrono::high_resolution_clock::now();
        rand_ta_cred = randomizeTACredential(user_apk, holder.P_U, ta_sig, r_2, &pfc);
        auto randomize_ta_end_time = std::chrono::high_resolution_clock::now();
        recordExecutionTime(
            "randomizeTACredential",
            std::chrono::duration<double, std::milli>(randomize_ta_end_time - randomize_ta_start_time).count()
        );

        auto blind_credential_start_time = std::chrono::high_resolution_clock::now();
        blinding_result = blindCredential(user_apk, holder, aggregated_sig, r_1, r_2, &pfc, G2_gen, verifier_ctx, ppHash);
        auto blind_credential_end_time = std::chrono::high_resolution_clock::now();
        recordExecutionTime(
            "blindCredential",
            std::chrono::duration<double, std::milli>(blind_credential_end_time - blind_credential_start_time).count()
        );
        cout << "\n[9] The user randomizes/blinds the credential for presentation..." << endl;
        cout << "  -> The user samples nonzero r_1,r_2 and derives the blinded credential, P'_U, and N_V." << endl;

        cout << "\n[13] The verifier checks the randomized TA certificate..." << endl;
        bool ta_verify_valid = verifyRandomizedTACredential(ta_kp.pk, rand_ta_cred, &pfc, G1_gen, "standalone");
        if (ta_verify_valid) {
            cout << ANSI_GREEN << "  -> [OK] Randomized TA certificate accepted; user_apk_prime is bound to a valid TA certificate." << ANSI_RESET << endl;
        } else {
            cout << ANSI_RED << "  -> [FAIL] Randomized TA certificate rejected." << ANSI_RESET << endl;
        }
        
        cout << "\n=== Phase 3: Anonymous Presentation and OR Proof ===" << endl;
        
        cout << "\n[14] The user generates an OR proof over the blinded credential..." << endl;
        PresentationPayload or_payload = generatePresentationPayload(
            blinding_result.credential,
            rand_ta_cred,
            verifier_kp.pk_V,
            blinding_result.w_U,
            verifier_ctx,
            ppHash,
            &pfc,
            G2_gen
        );
        auto present_total_end_time = std::chrono::high_resolution_clock::now();
        recordExecutionTime(
            "presentTotal",
            std::chrono::duration<double, std::milli>(present_total_end_time - present_total_start_time).count()
        );
        cout << "  -> The user sends the presentation payload to the verifier without plaintext attributes m." << endl;
        
        cout << "\n[15] The verifier checks the OR proof and blinded credential..." << endl;
        bool or_proof_valid = verifyPresentationPayload(ta_kp.pk, or_payload, &pfc, G1_gen, G2_gen, verifier_kp.pk_V, verifier_ctx, ppHash, "real");
        if (or_proof_valid) {
            cout << ANSI_GREEN << "  -> [OK] OR proof accepted; challenge splitting and both branch equations are consistent." << ANSI_RESET << endl;
            cout << ANSI_GREEN << "  -> The full protocol run completed successfully." << ANSI_RESET << endl;
        } else {
            cout << ANSI_RED << "  -> [FAIL] OR proof rejected; data may be inconsistent or tampered with." << ANSI_RESET << endl;
        }
        
        cout << "\n=== Phase 4: Verifier-Side Deniability Simulation ===" << endl;
        
        cout << "\n[16] The verifier uses its secret key to simulate a presentation over the same public blinded material..." << endl;
        PresentationPayload faked_payload;
        bool simulation_precondition_valid = simulatePresentationPayloadByVerifier(
            verifier_kp,
            nizk_proof,
            blinding_result.credential,
            rand_ta_cred,
            verifier_ctx,
            ppHash,
            &pfc,
            G2_gen,
            faked_payload
        );
        cout << "  -> The simulator swaps the proof roles: simulated left branch, real right branch with the verifier secret key." << endl;
        
        cout << "\n[17] A third party verifies the simulated transcript..." << endl;
        bool fake_proof_valid = simulation_precondition_valid && verifyPresentationPayload(ta_kp.pk, faked_payload, &pfc, G1_gen, G2_gen, verifier_kp.pk_V, verifier_ctx, ppHash, "simulated");
        if (fake_proof_valid) {
            cout << ANSI_GREEN << "  -> [OK] Simulated proof accepted." << endl;
            cout << "     Because the verifier can generate an indistinguishable accepted transcript, a third party cannot tell whether the transcript came from the user or from the verifier." << endl;
            cout << "     This demonstrates deniability for the user." << ANSI_RESET << endl;
        } else {
            cout << ANSI_RED << "  -> [FAIL] Simulated proof rejected; implementation error." << ANSI_RESET << endl;
        }
        printSummaryTable();

        // Append each run's inputs and timing records to a separate file.
        std::ofstream outfile("execution_records.txt", std::ios::app);
        if (outfile.is_open()) {
            outfile << "========== Run Record ==========\n";
            outfile << "Input variable - message count (num_messages): " << num_messages << "\n";
            outfile << "Input variable - other issuer count (num_other_issuers): " << num_other_issuers << "\n";
            outfile << "Internal contribution count (q_internal): " << (2 + num_other_issuers) << "\n";
            outfile << "+-----------------------------------------+-------------+\n";
            outfile << "| Function                     | Time |\n";
            outfile << "+-----------------------------------------+-------------+\n";
            for(const auto& entry : g_execution_times) {
                outfile << "| " << std::left << std::setw(39) << entry.first 
                        << " | " << std::right << std::setw(8) << std::fixed << std::setprecision(4) << entry.second << " ms |\n";
            }
            outfile << "+-----------------------------------------+-------------+\n";
            outfile << "==================================\n\n";
            outfile.close();
            std::cout << ANSI_GREEN << "  -> Run record with inputs and timing values was appended to execution_records.txt." << ANSI_RESET << std::endl;
        } else {
            std::cerr << ANSI_RED << "  -> Could not open execution_records.txt for appending." << ANSI_RESET << std::endl;
        }
    }
    
    return 0;
}
