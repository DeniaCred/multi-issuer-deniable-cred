#include "multi_issuer.h"
#include <chrono>
#include <iostream>
#include "utils.h"
#include <iostream>

// --- 生成密钥对 ---
KeyPair generateKeyPair(int num_messages, PFC* pfc, const G2& G2_gen) {
    KeyPair kp;
    pfc->random(kp.x);  // 随机生成私钥 x
    kp.X = pfc->mult(G2_gen, kp.x); // X = X^x (对应加法群的 x*G2_gen)

    for (int i = 0; i < num_messages; i++) {
        Big y_j;
        pfc->random(y_j);
        G2 Y_j = pfc->mult(G2_gen, y_j);
        
        kp.y.push_back(y_j);
        kp.Y.push_back(Y_j);
    }
    return kp;
}

// --- 生成签名份额 ---
SigShare signShare(const KeyPair& kp, const vector<Big>& messages, G1 h, PFC* pfc) {
    SigShare share;
    share.h = h;
    
    // 计算指数 expt = x + \sum (y_j * m_j) mod q
    Big exp = kp.x;
    for (size_t i = 0; i < messages.size(); i++) {
        Big term = modmult(kp.y[i], messages[i], pfc->order());
        exp = (exp + term) % pfc->order();
    }
    
    // S = h^exp (对应加法群的 exp * h)
    share.S = pfc->mult(h, exp);
    return share;
}

// --- 聚合签名 ---
SigShare aggregateSignatures(const vector<SigShare>& shares) {
    if (shares.empty()) return SigShare();
    
    SigShare aggregated_sig;
    aggregated_sig.h = shares[0].h;
    aggregated_sig.S = shares[0].S;
    
    for (size_t i = 1; i < shares.size(); i++) {
        aggregated_sig.S = aggregated_sig.S + shares[i].S;
    }
    return aggregated_sig;
}

// --- 聚合公钥 ---
AggregatedPK aggregatePublicKeys(const vector<KeyPair>& kps, int num_messages) {
    AggregatedPK apk;
    if (kps.empty()) return apk;
    
    apk.X_agg = kps[0].X;
    for (int i = 0; i < num_messages; i++) {
        apk.Y_agg.push_back(kps[0].Y[i]);
    }
    
    for (size_t k = 1; k < kps.size(); k++) {
        apk.X_agg = apk.X_agg + kps[k].X;
        for (int i = 0; i < num_messages; i++) {
            apk.Y_agg[i] = apk.Y_agg[i] + kps[k].Y[i];
        }
    }
    return apk;
}

// --- 验证聚合签名 ---
bool verifySignature(const AggregatedPK& apk, const SigShare& aggregated_sig, const vector<Big>& messages, const G2& G2_gen, PFC* pfc) {
    auto start_time = std::chrono::high_resolution_clock::now();

    G2 right_pub = apk.X_agg;
    for (size_t i = 0; i < messages.size(); i++) {
        G2 term = pfc->mult(apk.Y_agg[i], messages[i]);
        right_pub = right_pub + term; // Y_agg_j * m_j 再相乘
    }
    
    GT lhs = pfc->pairing(G2_gen, aggregated_sig.S);  // e(G2, S_agg) <=> e(S_agg, G2_gen)
    GT rhs = pfc->pairing(right_pub, aggregated_sig.h); // e(right_pub, h) <=> e(h, right_pub)
    
    auto end_time = std::chrono::high_resolution_clock::now();
    double duration = std::chrono::duration<double, std::milli>(end_time - start_time).count();
    std::cout << ANSI_CYAN << "[Time] verifySignature execution time: " << duration << " ms" << ANSI_RESET << std::endl;
    g_execution_times.push_back({"verifySignature", duration});

    return lhs == rhs;
}
