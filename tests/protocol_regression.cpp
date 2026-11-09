#include <iostream>
#include <string>
#include <vector>
#include "../or_proof.h"
#include "../utils.h"
#include "../protocol_rng.h"
#include <cstring>
#include <sstream>

class ScopedCoutSilence {
public:
    ScopedCoutSilence() : old_buffer_(std::cout.rdbuf(sink_.rdbuf())) {}
    ~ScopedCoutSilence() { std::cout.rdbuf(old_buffer_); }

private:
    std::ostringstream sink_;
    std::streambuf* old_buffer_;
};

std::vector<std::pair<std::string, double> > g_execution_times;

int main(int argc, char** argv) {
    if (argc > 1 && std::string(argv[1]) == "--rng-fingerprint") {
        std::string digest;
        {
            ScopedCoutSilence silence;
            ProtocolRng fingerprint_rng; PFC fingerprint_pfc(128, fingerprint_rng.get());
            G2 g2; G1 g1; fingerprint_pfc.random(g2); fingerprint_pfc.random(g1);
            auto holder = generateHolderKeyPair(&fingerprint_pfc, g2);
            std::string material = protocolEncodeG2(holder.pk_U, &fingerprint_pfc) + protocolEncodeG1(g1, &fingerprint_pfc);
            digest = protocolHex(protocolSha256(material));
        }
        std::cout << digest << "\n";
        return 0;
    }
    int checks = 0, failed = 0;
    auto check = [&](bool ok, const char* name) { ++checks; if (!ok) { ++failed; std::cerr << "FAIL: " << name << "\n"; } };
    ProtocolRng protocol_rng; PFC pfc(128, protocol_rng.get()); G1 g1, h; G2 g2; pfc.random(g1); pfc.random(g2); pfc.random(h);
    auto pp = makeProtocolParameters(&pfc, g1, g2, 2);
    auto holder = generateHolderKeyPair(&pfc, g2);
    std::vector<Big> m{Big(7), Big(11)};
    auto issuer = generateKeyPair(2, &pfc, g2); auto dm = generateKeyPair(2, &pfc, g2);
    std::vector<KeyPair> keys{issuer, dm};
    std::vector<SigShare> shares{signShare(issuer, m, h, &pfc), signShare(dm, m, h, &pfc)};
    auto sig = aggregateSignatures(shares); auto apk = aggregatePublicKeys(keys, 2);
    auto vk = deriveVerificationKey(apk, m, &pfc); auto ta = generateCertKeyPair(&pfc, g1);
    auto cert = certifyCredentialBinding(ta, vk, holder.pk_U, &pfc, g2);
    auto verifier = generateVerifierKeyPair(&pfc, g2); auto other = generateVerifierKeyPair(&pfc, g2);
    std::string ctx("ctx\0x", 5), mu("a\0b", 3);
    auto auth = generateNIZKProof(ctx, verifier, &pfc, g2, pp);
    Big r1 = protocolRandomScalar(&pfc, true), r2 = protocolRandomScalar(&pfc, true);
    auto blind = blindCredential(vk, holder, sig, r1, r2, &pfc, g2, ctx, pp);
    auto rc = randomizeCertificate(vk, holder.pk_U, cert, r2, &pfc);
    check(verifySignature(apk, sig, m, g2, &pfc), "credential");
    check(verifyRandomizedCertificate(ta.pk, rc, &pfc, g1), "TA certificate");
    check(verifyNIZKProof(ctx, verifier.pk_V, auth, &pfc, g2, pp), "VAuth");
    auto real = generatePresentationPayload(blind.credential, rc, verifier.pk_V, blind.w_U, ctx, &pfc, g2, pp, mu);
    auto sim = simulatePresentationPayloadByVerifier(verifier, blind.credential, rc, ctx, &pfc, g2, pp, mu);
    auto verify = [&](const PresentationPayload& t, const std::string& message) { return verifyPresentationPayload(ta.pk, t, &pfc, g1, g2, verifier.pk_V, ctx, pp, message); };
    check(verify(real, mu), "real binary mu"); check(verify(sim, mu), "simulated same material");
    check(!verify(real, std::string("a\0c", 3)), "changed bytes after NUL"); check(!verify(real, "a"), "NUL truncation");
    check(!verifyPresentationPayload(ta.pk, real, &pfc, g1, g2, verifier.pk_V, ctx + "x", pp, mu), "wrong ctx");
    check(!verifyPresentationPayload(ta.pk, real, &pfc, g1, g2, other.pk_V, ctx, pp, mu), "wrong verifier");
    auto changedpp = pp; changedpp.binding[0] ^= 1;
    check(!verifyPresentationPayload(ta.pk, real, &pfc, g1, g2, verifier.pk_V, ctx, changedpp, mu), "wrong ppHash");
    auto empty = generatePresentationPayload(blind.credential, rc, verifier.pk_V, blind.w_U, ctx, &pfc, g2, pp);
    check(verify(empty, std::string()), "default empty mu");

    // Reuse system and long-term keys across runs; refresh each DM and holder.
    auto other_real = generateKeyPair(2, &pfc, g2);
    std::string previous_dm;
    for (int run = 0; run < 2; ++run) {
        auto run_holder = generateHolderKeyPair(&pfc, g2);
        auto run_dm = generateKeyPair(2, &pfc, g2);
        auto run_h = G1(); pfc.random(run_h);
        std::vector<KeyPair> run_keys{issuer, other_real, run_dm};
        std::vector<SigShare> run_shares{signShare(issuer, m, run_h, &pfc), signShare(other_real, m, run_h, &pfc), signShare(run_dm, m, run_h, &pfc)};
        auto run_sig = aggregateSignatures(run_shares);
        auto run_apk = aggregatePublicKeys(run_keys, 2);
        auto run_vk = deriveVerificationKey(run_apk, m, &pfc);
        auto run_cert = certifyCredentialBinding(ta, run_vk, run_holder.pk_U, &pfc, g2);
        check(verifySignature(run_apk, run_sig, m, g2, &pfc) && verifyCertificate(ta.pk, run_vk, run_holder.pk_U, run_cert, &pfc, g1), "shared long-term keys accept issuance");
        std::string dm_encoding = protocolEncodeG2(run_dm.X, &pfc);
        if (!previous_dm.empty()) check(dm_encoding != previous_dm, "fresh one-time DM key");
        previous_dm = dm_encoding;
        std::string previous_h_prime;
        for (int show = 0; show < 2; ++show) {
            std::string run_ctx = "shared-" + std::to_string(run) + "-" + std::to_string(show);
            auto run_auth = generateNIZKProof(run_ctx, verifier, &pfc, g2, pp);
            check(verifyNIZKProof(run_ctx, verifier.pk_V, run_auth, &pfc, g2, pp), "shared verifier key authenticates context");
            Big run_r1 = protocolRandomScalar(&pfc, true), run_r2 = protocolRandomScalar(&pfc, true);
            auto run_blind = blindCredential(run_vk, run_holder, run_sig, run_r1, run_r2, &pfc, g2, run_ctx, pp);
            auto run_rc = randomizeCertificate(run_vk, run_holder.pk_U, run_cert, run_r2, &pfc);
            auto run_real = generatePresentationPayload(run_blind.credential, run_rc, verifier.pk_V, run_blind.w_U, run_ctx, &pfc, g2, pp, mu);
            auto run_sim = simulatePresentationPayloadByVerifier(verifier, run_blind.credential, run_rc, run_ctx, &pfc, g2, pp, mu);
            auto run_verify = [&](const PresentationPayload& t) { return verifyPresentationPayload(ta.pk, t, &pfc, g1, g2, verifier.pk_V, run_ctx, pp, mu); };
            check(run_verify(run_real), "shared-key real presentation accepted");
            check(run_verify(run_sim), "shared-key same-material simulation accepted");
            std::string h_prime = protocolEncodeG1(run_blind.credential.h_prime, &pfc);
            if (!previous_h_prime.empty()) check(h_prime != previous_h_prime, "fresh blinding changes material");
            previous_h_prime = h_prime;
        }
    }
    PresentationPayload mutated = real;
    mutated.cred.h_prime = G1(); check(!verify(mutated, mu), "identity h");
    mutated = real; mutated.cred.s_prime = G1(); check(!verify(mutated, mu), "identity s");
    mutated = real; mutated.cred.vk_U_prime = G2(); check(!verify(mutated, mu), "identity vk");
    mutated = real; mutated.cred.pk_U_prime = G2(); check(!verify(mutated, mu), "identity pk");
    mutated = real; mutated.cred.N_V = G2(); check(!verify(mutated, mu), "identity nym");
    mutated = real; mutated.cert.R_c_prime = G2(); check(!verify(mutated, mu), "identity cert R");
    mutated = real; mutated.pk_V = G2(); check(!verify(mutated, mu), "identity verifier key");
    mutated = real; mutated.proof.c_left = Big(-1); check(!verify(mutated, mu), "negative c_left");
    mutated = real; mutated.proof.z_left = -pfc.order(); check(!verify(mutated, mu), "negative z_left");
    mutated = real; mutated.proof.c_right = -pfc.order(); check(!verify(mutated, mu), "negative c_right");
    mutated = real; mutated.proof.z_right = -pfc.order(); check(!verify(mutated, mu), "negative z_right");
    mutated = real; mutated.proof.c_left = pfc.order(); check(!verify(mutated, mu), "order c_left");
    mutated = real; mutated.proof.z_left = pfc.order(); check(!verify(mutated, mu), "order z_left");
    mutated = real; mutated.proof.c_right = pfc.order(); check(!verify(mutated, mu), "order c_right");
    mutated = real; mutated.proof.z_right = pfc.order(); check(!verify(mutated, mu), "order z_right");
    mutated = real; mutated.cert.pk_U_prime = other.pk_V; check(!verify(mutated, mu), "mismatched cert pk");
    mutated = real; mutated.cert.vk_U_prime = other.pk_V; check(!verify(mutated, mu), "mismatched cert vk");
    check(!verifySignature(apk, sig, std::vector<Big>(1, Big(7)), g2, &pfc), "short message");
    AggregatedPK short_apk = apk; short_apk.Y_agg.pop_back(); check(!verifySignature(short_apk, sig, m, g2, &pfc), "short apk");
    SigShare bad_sig = sig; bad_sig.h = G1(); check(!verifySignature(apk, bad_sig, m, g2, &pfc), "identity signature base");
    SigShare both_identity = sig; both_identity.h = G1(); both_identity.S = G1();
    check(!verifySignature(apk, both_identity, m, g2, &pfc), "identity signature pair");
    check(!verifySignature(apk, sig, std::vector<Big>{Big(-1), Big(11)}, g2, &pfc), "negative attribute");
    check(!verifySignature(apk, sig, std::vector<Big>{pfc.order(), Big(11)}, g2, &pfc), "out of range attribute");
    check(signShare(issuer, std::vector<Big>{Big(7)}, h, &pfc).h.g.iszero(), "short sign share rejected");
    csprng* saved = pfc.RNG; pfc.RNG = nullptr;
    bool rng_rejected = false; try { (void)protocolRandomScalar(&pfc, true); } catch (const std::exception&) { rng_rejected = true; }
    pfc.RNG = saved; check(rng_rejected, "missing RNG rejected");
    IssuedCredential bundle{sig, apk, cert};
    auto accept = [&](const IssuedCredential& b) { G2 user_vk = deriveVerificationKey(b.aggregate_public_key, m, &pfc); return verifySignature(b.aggregate_public_key, b.credential, m, g2, &pfc, "user") && verifyCertificate(ta.pk, user_vk, holder.pk_U, b.certificate, &pfc, g1); };
    check(accept(bundle), "complete bundle accepted");
    auto bad_bundle = bundle; bad_bundle.credential.S = bad_bundle.credential.S + h; check(!accept(bad_bundle), "modified credential rejected");
    bad_bundle = bundle; bad_bundle.certificate.S_c = bad_bundle.certificate.S_c + g2; check(!accept(bad_bundle), "modified certificate rejected");
    check(!verifyCertificate(ta.pk, vk, holder.pk_U + g2, cert, &pfc, g1), "wrong holder binding");
    check(!verifyCertificate(ta.pk, vk + g2, holder.pk_U, cert, &pfc, g1), "wrong vk binding");
    check(!verifyCertificate(ta.pk, vk, holder.pk_U, cert, &pfc, G1()), "identity certificate base");
    auto short_key = issuer; short_key.y.pop_back(); check(signShare(short_key, m, h, &pfc).h.g.iszero(), "short secret vector");
    short_key = issuer; short_key.Y.pop_back(); check(signShare(short_key, m, h, &pfc).h.g.iszero(), "short public vector");
    check(signShare(issuer, m, G1(), &pfc).h.g.iszero(), "identity issuance base");
    check(signShare(issuer, m, h, nullptr).h.g.iszero(), "null signing context");
    check(signShare(issuer, std::vector<Big>{Big(-1), Big(11)}, h, &pfc).h.g.iszero(), "negative signing attribute");
    check(signShare(issuer, std::vector<Big>{pfc.order(), Big(11)}, h, &pfc).h.g.iszero(), "order signing attribute");
    auto zero_key = issuer; zero_key.x = Big(0); zero_key.X = G2(); zero_key.y.assign(2, Big(0)); zero_key.Y.assign(2, G2()); auto zero_share = signShare(zero_key, m, h, &pfc); check(zero_share.h == h && zero_share.S.g.iszero(), "zero issuer scalars allowed");
    check(!verifySignature(apk, sig, m, G2(), &pfc), "identity credential generator");
    check(!verifySignature(apk, sig, m, g2, nullptr), "null credential verifier");
    bool caught = false; try { deriveVerificationKey(apk, std::vector<Big>{Big(7)}, &pfc); } catch (const std::invalid_argument&) { caught = true; } check(caught, "derive rejects short attributes");
    caught = false; try { deriveVerificationKey(apk, m, nullptr); } catch (const std::invalid_argument&) { caught = true; } check(caught, "derive rejects null context");
    caught = false; try { deriveVerificationKey(apk, std::vector<Big>{Big(-1), Big(11)}, &pfc); } catch (const std::invalid_argument&) { caught = true; } check(caught, "derive rejects negative attribute");
    check(aggregateSignatures(std::vector<SigShare>()).h.g.iszero(), "empty shares default");
    check(aggregatePublicKeys(std::vector<KeyPair>(), 2).X_agg.g.iszero(), "empty keys default");
    check(protocolValidG2(G2(), &pfc, false), "identity optional subgroup");
    check(!protocolValidG2(G2(), &pfc, true), "identity required subgroup");
    check(protocolFrame("ab") + protocolFrame("c") != protocolFrame("a") + protocolFrame("bc"), "framing boundaries");
    std::cout << "Protocol regression: " << checks << " checks, " << failed << " failed\n";
    return failed ? 1 : 0;
}
