#include "trusted_authority.h"
#include <chrono>
#include <iostream>
#include "utils.h"
#include <iostream>

// --- 生成TA密钥对 ---
TAKeyPair generateTAKeyPair(PFC* pfc, const G1& G1_gen) {
    TAKeyPair kp;
    
    // 生成私钥
    pfc->random(kp.sk.x_TA);
    pfc->random(kp.sk.y_TA);
    pfc->random(kp.sk.z_TA);
    
    // 生成公钥
    kp.pk.X = pfc->mult(G1_gen, kp.sk.x_TA);
    kp.pk.Y = pfc->mult(G1_gen, kp.sk.y_TA);
    kp.pk.Z = pfc->mult(G1_gen, kp.sk.z_TA);
    
    return kp;
}

// --- TA生成对 (user_apk, P_U) 的随机化担保 ---
TASignature signUserApk(const TAKeyPair& ta_kp, const G2& user_apk, const G2& P_U, PFC* pfc, const G2& G2_gen) {
    TASignature sig;
    
    // TA选取随机盲化因子 ρ (rho)
    Big rho;
    pfc->random(rho);
    
    // 计算随机化基点 R = ρ * G2_gen
    sig.R = pfc->mult(G2_gen, rho);
    
    // 计算核心签名组件 S = x_{TA} * R + y_{TA} * user_apk + z_{TA} * P_U
    sig.S = pfc->mult(sig.R, ta_kp.sk.x_TA);
    
    G2 term_apk = pfc->mult(user_apk, ta_kp.sk.y_TA);
    G2 term_holder = pfc->mult(P_U, ta_kp.sk.z_TA);
    sig.S = sig.S + term_apk + term_holder;
    
    return sig;
}

// --- 用户的盲化操作 (Randomize) ---
RandomizedTACredential randomizeTACredential(const G2& user_apk, const G2& P_U, const TASignature& sig, Big r_2, PFC* pfc) {
    RandomizedTACredential ta_cred;
    
    // 盲化 user_apk 和持有者承诺 P_U
    ta_cred.user_apk_prime = pfc->mult(user_apk, r_2);
    ta_cred.P_prime = pfc->mult(P_U, r_2);
    
    // 盲化签名: R' = r * R, S' = r * S
    ta_cred.R_prime = pfc->mult(sig.R, r_2);
    ta_cred.S_prime = pfc->mult(sig.S, r_2);
    
    return ta_cred;
}

// --- 第三方验证过程 ---
bool verifyRandomizedTACredential(
    const TAPublicKey& ta_pk,
    const RandomizedTACredential& ta_cred,
    PFC* pfc,
    const G1& G1_gen,
    const std::string& timing_context
) {
    auto start_time = std::chrono::high_resolution_clock::now();

    // 验证者检查双线性配对等式是否成立:
    // e(g, S') = e(X, R') * e(Y, user_apk') * e(Z, P')
    
    // 由于 MIRACL pfc->pairing 约定为 e(G2, G1)，我们需要将顺序调整好：
    // e(S_prime, G1_gen)
    GT lhs = pfc->pairing(ta_cred.S_prime, G1_gen);
    
    // e(R_prime, X)
    GT rhs = pfc->pairing(ta_cred.R_prime, ta_pk.X);
    
    // * e(user_apk', Y)
    rhs = rhs * pfc->pairing(ta_cred.user_apk_prime, ta_pk.Y);

    // * e(P', Z)
    rhs = rhs * pfc->pairing(ta_cred.P_prime, ta_pk.Z);
    
    auto end_time = std::chrono::high_resolution_clock::now();
    double duration = std::chrono::duration<double, std::milli>(end_time - start_time).count();
    std::string label = timingLabel("verifyRandomizedTACredential", timing_context);
    std::cout << ANSI_CYAN << "[Time] " << label << " execution time: " << duration << " ms" << ANSI_RESET << std::endl;
    g_execution_times.push_back({label, duration});

    return lhs == rhs;
}
