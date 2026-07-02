#ifndef MULTI_ISSUER_H
#define MULTI_ISSUER_H

#include <vector>
#include "Algorithm/pairing_3.h"

using namespace std;

// 1. 公钥结构 (全部在 G2 上)
struct KeyPair {
    //私钥
    Big x;
    vector<Big> y;
    
    //公钥
    G2 X;           // X = x * G2_gen
    vector<G2> Y;   // Y_j = y_j * G2_gen
};

// 2. 签名份额结构 (全部在 G1 上)
struct SigShare {
    G1 h;
    G1 S; // S = h^(x + \sum y_j * m_j)
};

// 3. 聚合公钥
struct AggregatedPK {
    G2 X_agg;
    vector<G2> Y_agg;
};

// 函数声明
KeyPair generateKeyPair(int num_messages, PFC* pfc, const G2& G2_gen);
SigShare signShare(const KeyPair& kp, const vector<Big>& messages, G1 h, PFC* pfc);
SigShare aggregateSignatures(const vector<SigShare>& shares);
AggregatedPK aggregatePublicKeys(const vector<KeyPair>& kps, int num_messages);
bool verifySignature(const AggregatedPK& apk, const SigShare& aggregated_sig, const vector<Big>& messages, const G2& G2_gen, PFC* pfc);

#endif // MULTI_ISSUER_H
