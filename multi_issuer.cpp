#include "multi_issuer.h"
#include "protocol_parameters.h"
#include <chrono>
#include <iostream>
#include "utils.h"
#include <iostream>

KeyPair generateKeyPair(int num_messages, PFC* pfc, const G2& G2_gen) {
    KeyPair kp;
    kp.x = protocolRandomScalar(pfc, false);
    kp.X = pfc->mult(G2_gen, kp.x);

    for (int i = 0; i < num_messages; i++) {
        Big y_j;
        y_j = protocolRandomScalar(pfc, false);
        G2 Y_j = pfc->mult(G2_gen, y_j);
        
        kp.y.push_back(y_j);
        kp.Y.push_back(Y_j);
    }
    return kp;
}

SigShare signShare(const KeyPair& kp, const vector<Big>& messages, G1 h, PFC* pfc) {
    SigShare share;
    if (!pfc || kp.y.size() != messages.size() || kp.Y.size() != messages.size() || messages.empty() ||
        !protocolScalarValid(kp.x,pfc,false) || !protocolValidG1(h,pfc,true)) return share;
    for (size_t i = 0; i < messages.size(); ++i)
        if (!protocolScalarValid(messages[i],pfc,false) || !protocolScalarValid(kp.y[i],pfc,false) || !protocolValidG2(kp.Y[i],pfc,false)) return share;
    share.h = h;
    
    Big exp = kp.x;
    for (size_t i = 0; i < messages.size(); i++) {
        Big term = modmult(kp.y[i], messages[i], pfc->order());
        exp = (exp + term) % pfc->order();
    }
    
    share.S = pfc->mult(h, exp);
    return share;
}

SigShare aggregateSignatures(const vector<SigShare>& shares) {
    if (shares.empty()) return SigShare();
    
    SigShare aggregated_sig;
    aggregated_sig.h = shares[0].h;
    aggregated_sig.S = shares[0].S;
    
    for (size_t i = 1; i < shares.size(); i++) {
        if (!(shares[i].h == aggregated_sig.h)) return SigShare();
        aggregated_sig.S = aggregated_sig.S + shares[i].S;
    }
    return aggregated_sig;
}

AggregatedPK aggregatePublicKeys(const vector<KeyPair>& kps, int num_messages) {
    AggregatedPK apk;
    if (kps.empty() || num_messages < 0) return apk;
    for (const auto& kp : kps) if (kp.Y.size() != static_cast<size_t>(num_messages)) return apk;
    
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

bool verifySignature(const AggregatedPK& apk, const SigShare& aggregated_sig, const vector<Big>& messages, const G2& G2_gen, PFC* pfc, const std::string& timing_context) {
    auto start_time = std::chrono::steady_clock::now();

    if (!pfc || apk.Y_agg.size() != messages.size() || messages.empty() || !protocolValidG2(G2_gen,pfc,true) || !protocolValidG1(aggregated_sig.h,pfc,true) || !protocolValidG1(aggregated_sig.S,pfc,true)) return false;
    for(size_t i=0;i<messages.size();++i) if(!protocolScalarValid(messages[i],pfc,false)||!protocolValidG2(apk.Y_agg[i],pfc,false)) return false;
    if (!protocolValidG2(apk.X_agg,pfc,false)) return false;
    G2 right_pub = apk.X_agg;
    for (size_t i = 0; i < messages.size(); i++) {
        G2 term = pfc->mult(apk.Y_agg[i], messages[i]);
        right_pub = right_pub + term;
    }
    
    if(!protocolValidG2(right_pub,pfc,true)) return false;
    GT lhs = pfc->pairing(G2_gen, aggregated_sig.S);  // e(G2, S_agg) <=> e(S_agg, G2_gen)
    GT rhs = pfc->pairing(right_pub, aggregated_sig.h); // e(right_pub, h) <=> e(h, right_pub)
    
    auto end_time = std::chrono::steady_clock::now();
    double duration = std::chrono::duration<double, std::milli>(end_time - start_time).count();
    std::string label = timingLabel("verifySignature", timing_context);
    emitTimingRecord(label, duration);

    return lhs == rhs;
}
