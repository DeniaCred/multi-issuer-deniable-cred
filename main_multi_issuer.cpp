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
    std::cout << ANSI_BOLD << ANSI_CYAN << "|                   性能统计汇总表格 (ms)                  |" << ANSI_RESET << std::endl;
    std::cout << ANSI_BOLD << ANSI_CYAN << "+--------------------------------------------------------+" << ANSI_RESET << std::endl;
    
    std::cout << ANSI_BOLD << "| " << std::left << std::setw(39) << "函数名称 (Function)" << " | " << std::setw(11) << "耗时 (Time)" << " |" << ANSI_RESET << std::endl;
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
    PFC pfc(128); // 128-bit security BN curve 环境初始化
    {
        G2 G2_gen;
        pfc.random(G2_gen); // G2 上的全局基点
        
        G1 G1_gen;
        pfc.random(G1_gen); // G1 上的全局基点
        
        int num_messages;
        cout << "请输入消息/属性的数量(num_messages): ";
        cin >> num_messages;
        vector<Big> messages;
        for (int i = 0; i < num_messages; i++) {
            messages.push_back(Big(12345 + i)); // 用户的一些属性信息自动模拟生成
        }
        
        cout << "=== PS 多签发方协作签发证书实验演示 ===" << endl;
        
        // AggIssue 随机选择发行基底 h。
        G1 h;
        pfc.random(h);
        cout << "-> 签名发起方随机选择发行基底 h (在群 G1 上)" << endl;
        
        cout << "\n[1] 各方生成各自的密钥对..." << endl;
        
        cout << "  -> 签名发起方生成自己的密钥对..." << endl;
        KeyPair kp_initiator = generateKeyPair(num_messages, &pfc, G2_gen);
        
        cout << "  -> 签名发起方在内部生成一次性虚拟签发方 DM 的密钥对..." << endl;
        KeyPair kp_dm = generateKeyPair(num_messages, &pfc, G2_gen); 
        
        int num_other_issuers;
        cout << "请输入其他合作签发方的数量(num_other_issuers): ";
        cin >> num_other_issuers;
        cout << "  -> " << num_other_issuers << " 个其他合作签发方生成各自的密钥对..." << endl;
        
        vector<KeyPair> other_issuers_kps;
        for (int i = 0; i < num_other_issuers; i++) {
            other_issuers_kps.push_back(generateKeyPair(num_messages, &pfc, G2_gen));
        }
        
        cout << "\n[2] 每个签发方针对哈希值 h 生成签名份额..." << endl;
        cout << "    签名形式：(h, h^{x_i + \\Sigma y_{i,j} * m_j})" << endl;
        
        auto issue_start_time = std::chrono::high_resolution_clock::now();
        vector<SigShare> all_shares;
        
        SigShare share_initiator = signShare(kp_initiator, messages, h, &pfc);
        all_shares.push_back(share_initiator);
        
        SigShare share_dm = signShare(kp_dm, messages, h, &pfc);
        all_shares.push_back(share_dm);
        
        for (int i = 0; i < num_other_issuers; i++) {
            all_shares.push_back(signShare(other_issuers_kps[i], messages, h, &pfc));
        }
        
        cout << "\n[3] 签名发起方收集并聚合所有签名份额..." << endl;
        SigShare aggregated_sig = aggregateSignatures(all_shares);
        auto issue_end_time = std::chrono::high_resolution_clock::now();
        double issue_duration = std::chrono::duration<double, std::milli>(issue_end_time - issue_start_time).count();
        std::cout << ANSI_CYAN << "[Time] issueCredential execution time: " << issue_duration << " ms" << ANSI_RESET << std::endl;
        g_execution_times.push_back({"issueCredential", issue_duration});
        cout << "  -> 聚合签名 (h, 相乘后的结果 S_agg) 生成完成。" << endl;
        
        cout << "\n[4] 签名发起方聚合所有参与者的公钥 apk..." << endl;
        vector<KeyPair> all_kps;
        all_kps.push_back(kp_initiator);     // 发起方
        all_kps.push_back(kp_dm);            // dm用户
        for (int i = 0; i < num_other_issuers; i++) {
            all_kps.push_back(other_issuers_kps[i]); // 其他签发方
        }
        auto aggregate_pk_start_time = std::chrono::high_resolution_clock::now();
        AggregatedPK apk = aggregatePublicKeys(all_kps, num_messages);
        auto aggregate_pk_end_time = std::chrono::high_resolution_clock::now();
        recordExecutionTime(
            "aggregatePublicKeys",
            std::chrono::duration<double, std::milli>(aggregate_pk_end_time - aggregate_pk_start_time).count()
        );
        cout << "  -> 聚合公钥 apk (X_agg, Y_agg) 生成完成。" << endl;
        
        cout << "\n[5] 将聚合公钥 apk 与聚合签名返回给用户..." << endl;
        
        cout << "\n[6] 用户/验证方使用聚合公钥验证多签发方证书的合法性..." << endl;
        bool is_valid = verifySignature(apk, aggregated_sig, messages, G2_gen, &pfc);
        
        if (is_valid) {
            cout << ANSI_GREEN << "  -> 【验证成功！】聚合凭证与不透明聚合公钥向量代数一致。" << ANSI_RESET << endl;
        } else {
            cout << ANSI_RED << "  -> 【验证失败！】" << ANSI_RESET << endl;
        }
        
        cout << "\n=== 可信第三方(TA)签名与随机化实验演示 ===" << endl;
        
        cout << "\n[7] TA生成密钥对..." << endl;
        TAKeyPair ta_kp = generateTAKeyPair(&pfc, G1_gen);
        cout << "  -> TA 生成了公钥 (在G1上) 和私钥 (在Z_p上)" << endl;
        
        cout << "\n[8] TA对用户的属性特定公钥 user_apk 和持有者承诺 P_U 进行担保..." << endl;
        // 计算用户的 user_apk = X_agg + \sum m_i * Y_agg[i]
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
        cout << "  -> TA 计算并对 (user_apk, P_U) 生成随机化担保 (R, S)。" << endl;
        
        Big r_1;
        Big r_2;
        RandomizedTACredential rand_ta_cred;
        BlindingResult blinding_result;
        
        cout << "\n=== 验证者 NIZK 身份自证演示 ===" << endl;
        
        cout << "\n[10] 验证者建立自己的密钥对 (用于接受用户出示凭证)..." << endl;
        VerifierKeyPair verifier_kp = generateVerifierKeyPair(&pfc, G2_gen);
        string verifier_id = "Verifier-001";
        string verifier_ctx = verifier_id + "|pk-bound-demo|nonce-001|policy-all-attributes|expiry-demo";
        cout << "  -> 验证者 " << verifier_id << " 生成了公私钥对 (G2之上)。" << endl;
        
        cout << "\n[11] 验证者向用户发起身份证明 (NIZK PoK)..." << endl;
        auto verifier_auth_gen_start_time = std::chrono::high_resolution_clock::now();
        NIZKProof nizk_proof = generateNIZKProof(verifier_ctx, verifier_kp, &pfc, G2_gen);
        auto verifier_auth_gen_end_time = std::chrono::high_resolution_clock::now();
        recordExecutionTime(
            "verifierAuthNIZKGen",
            std::chrono::duration<double, std::milli>(verifier_auth_gen_end_time - verifier_auth_gen_start_time).count()
        );
        cout << "  -> 验证者生成了绑定会话上下文的非交互式零知识证明 (A, z) 发送给用户。" << endl;
        
        cout << "\n[12] 用户校验验证者的真实身份..." << endl;
        auto verifier_auth_verify_start_time = std::chrono::high_resolution_clock::now();
        bool nizk_valid = verifyNIZKProof(verifier_ctx, verifier_kp.pk_V, nizk_proof, &pfc, G2_gen);
        auto verifier_auth_verify_end_time = std::chrono::high_resolution_clock::now();
        recordExecutionTime(
            "verifierAuthNIZKVerify",
            std::chrono::duration<double, std::milli>(verifier_auth_verify_end_time - verifier_auth_verify_start_time).count()
        );
        if (nizk_valid) {
            cout << ANSI_GREEN << "  -> 【验证者 NIZK 校验成功！】用户确认对方是真实的 " << verifier_id << "，拥有对应的私钥。" << ANSI_RESET << endl;
            cout << "  -> 用户同意将盲化后的证书出示给该验证者..." << endl;
        } else {
            cout << ANSI_RED << "  -> 【验证者 NIZK 校验失败！】用户拒绝出示凭证！" << ANSI_RESET << endl;
            return -1; // 终止执行
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
        blinding_result = blindCredential(user_apk, holder, aggregated_sig, r_1, r_2, &pfc, G2_gen, verifier_ctx);
        auto blind_credential_end_time = std::chrono::high_resolution_clock::now();
        recordExecutionTime(
            "blindCredential",
            std::chrono::duration<double, std::milli>(blind_credential_end_time - blind_credential_start_time).count()
        );
        cout << "\n[9] 用户进行凭证的随机化(盲化)以便于出示..." << endl;
        cout << "  -> 用户使用非零随机数 r_1,r_2 生成了盲化凭证、P'_U 和 N_V。" << endl;

        cout << "\n[13] 第三方验证者验证盲化后的TA凭证..." << endl;
        bool ta_verify_valid = verifyRandomizedTACredential(ta_kp.pk, rand_ta_cred, &pfc, G1_gen, "standalone");
        if (ta_verify_valid) {
            cout << ANSI_GREEN << "  -> 【TA签名盲化验证成功！】验证者仅通过一次验证等式，确定了盲化 user_apk_prime 来自合法的TA担保。" << ANSI_RESET << endl;
        } else {
            cout << ANSI_RED << "  -> 【TA签名盲化验证失败！】" << ANSI_RESET << endl;
        }
        
        cout << "\n=== 第三阶段：匿名出示与 OR-Proof ===" << endl;
        
        cout << "\n[14] 用户基于已盲化的凭证生成 OR-Proof..." << endl;
        PresentationPayload or_payload = generatePresentationPayload(
            blinding_result.credential,
            rand_ta_cred,
            verifier_kp.pk_V,
            blinding_result.w_U,
            verifier_ctx,
            &pfc,
            G2_gen
        );
        auto present_total_end_time = std::chrono::high_resolution_clock::now();
        recordExecutionTime(
            "presentTotal",
            std::chrono::duration<double, std::milli>(present_total_end_time - present_total_start_time).count()
        );
        cout << "  -> 用户生成了数据包发送给验证者 (不再发送明文属性 m)。" << endl;
        
        cout << "\n[15] 验证者验证 OR-Proof 及盲化凭证..." << endl;
        bool or_proof_valid = verifyPresentationPayload(ta_kp.pk, or_payload, &pfc, G1_gen, G2_gen, verifier_kp.pk_V, verifier_ctx, "real");
        if (or_proof_valid) {
            cout << ANSI_GREEN << "  -> 【OR-Proof 验证成功！】验证者确认了哈希分割一致、Right侧合规且Left侧持有者承诺关系无误。" << ANSI_RESET << endl;
            cout << ANSI_GREEN << "  -> 整个协议执行圆满成功！" << ANSI_RESET << endl;
        } else {
            cout << ANSI_RED << "  -> 【OR-Proof 验证失败！】存在数据篡改或对应不符合的情况。" << ANSI_RESET << endl;
        }
        
        cout << "\n=== 第四阶段：验证者展示可否认性 (伪造 OR-Proof) ===" << endl;
        
        cout << "\n[16] 验证者利用自己的私钥在同一份公开盲化材料上生成模拟展示..." << endl;
        PresentationPayload faked_payload = simulatePresentationPayloadByVerifier(
            verifier_kp,
            blinding_result.credential,
            rand_ta_cred,
            verifier_ctx,
            &pfc,
            G2_gen
        );
        cout << "  -> 验证者反转逻辑：Left侧模拟，Right侧使用验证者私钥真实证明。" << endl;
        
        cout << "\n[17] 第三方 (如法官) 验证该伪造的大礼包..." << endl;
        bool fake_proof_valid = verifyPresentationPayload(ta_kp.pk, faked_payload, &pfc, G1_gen, G2_gen, verifier_kp.pk_V, verifier_ctx, "simulated");
        if (fake_proof_valid) {
            cout << ANSI_GREEN << "  -> 【伪造证明验证成功！】" << endl;
            cout << "     因为验证者完全有能力毫无破绽地伪造出合法的展示记录，第三方无法确信该记录究竟是用户出示的，还是验证者自己捏造的。" << endl;
            cout << "     这赋予了用户绝对的【可否认性】！" << ANSI_RESET << endl;
        } else {
            cout << ANSI_RED << "  -> 【伪造证明验证失败！】代码实现有误。" << ANSI_RESET << endl;
        }
        printSummaryTable();

        // 将每次运行的数据（包含输入的变量和所有的耗时）保存到单独的文件中
        std::ofstream outfile("execution_records.txt", std::ios::app);
        if (outfile.is_open()) {
            outfile << "========== 本次运行记录 ==========\n";
            outfile << "输入的变量 - 消息数量 (num_messages): " << num_messages << "\n";
            outfile << "输入的变量 - 其他发起方数量 (num_other_issuers): " << num_other_issuers << "\n";
            outfile << "内部贡献数量(q_internal): " << (2 + num_other_issuers) << "\n";
            outfile << "+-----------------------------------------+-------------+\n";
            outfile << "| 函数名称 (Function)                     | 耗时 (Time) |\n";
            outfile << "+-----------------------------------------+-------------+\n";
            for(const auto& entry : g_execution_times) {
                outfile << "| " << std::left << std::setw(39) << entry.first 
                        << " | " << std::right << std::setw(8) << std::fixed << std::setprecision(4) << entry.second << " ms |\n";
            }
            outfile << "+-----------------------------------------+-------------+\n";
            outfile << "==================================\n\n";
            outfile.close();
            std::cout << ANSI_GREEN << "  -> 运行记录(包含输入变量和耗时)已成功追加保存至文件 execution_records.txt" << ANSI_RESET << std::endl;
        } else {
            std::cerr << ANSI_RED << "  -> 无法打开文件 execution_records.txt 进行记录保存！" << ANSI_RESET << std::endl;
        }
    }
    
    return 0;
}
