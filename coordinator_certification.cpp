#include "coordinator_certification.h"
#include <chrono>
#include <iostream>
#include "utils.h"
#include <iostream>

// --- Generate TA certification key pair ---
CertKeyPair generateCertKeyPair(PFC* pfc, const G1& G1_gen) {
    CertKeyPair kp;

    kp.sk.x_c = protocolRandomScalar(pfc, true);
    kp.sk.y_c = protocolRandomScalar(pfc, true);
    kp.sk.z_c = protocolRandomScalar(pfc, true);

    kp.pk.X = pfc->mult(G1_gen, kp.sk.x_c);
    kp.pk.Y = pfc->mult(G1_gen, kp.sk.y_c);
    kp.pk.Z = pfc->mult(G1_gen, kp.sk.z_c);

    return kp;
}

// --- Certify the binding between vk_U and pk_U ---
CertSignature certifyCredentialBinding(const CertKeyPair& cert_kp, const G2& vk_U, const G2& pk_U, PFC* pfc, const G2& G2_gen) {
    CertSignature sig;

    // Sample a fresh certificate base scalar.
    Big rho;
    rho = protocolRandomScalar(pfc, true);

    // Compute R_c = rho * G2_gen.
    sig.R_c = pfc->mult(G2_gen, rho);

    // Compute S_c = x_c R_c + y_c vk_U + z_c pk_U.
    sig.S_c = pfc->mult(sig.R_c, cert_kp.sk.x_c);

    G2 term_apk = pfc->mult(vk_U, cert_kp.sk.y_c);
    G2 term_holder = pfc->mult(pk_U, cert_kp.sk.z_c);
    sig.S_c = sig.S_c + term_apk + term_holder;

    return sig;
}

// --- Holder-side certificate randomization ---
RandomizedCertificate randomizeCertificate(const G2& vk_U, const G2& pk_U, const CertSignature& sig, Big r_2, PFC* pfc) {
    if (!protocolScalarValid(r_2,pfc,true)) throw std::invalid_argument("invalid certificate randomization scalar");
    RandomizedCertificate cert;

    // Randomize vk_U and pk_U.
    cert.vk_U_prime = pfc->mult(vk_U, r_2);
    cert.pk_U_prime = pfc->mult(pk_U, r_2);

    // Randomize the certificate components with r_2.
    cert.R_c_prime = pfc->mult(sig.R_c, r_2);
    cert.S_c_prime = pfc->mult(sig.S_c, r_2);

    return cert;
}

bool verifyCertificate(const CertPublicKey& cert_pk, const G2& vk_U, const G2& pk_U, const CertSignature& sig, PFC* pfc, const G1& G1_gen) {
    if (!pfc) return false;
    RandomizedCertificate cert{vk_U, pk_U, sig.R_c, sig.S_c};
    return verifyRandomizedCertificate(cert_pk, cert, pfc, G1_gen, "original");
}

// --- Public certificate verification ---
bool verifyRandomizedCertificate(
    const CertPublicKey& cert_pk,
    const RandomizedCertificate& cert,
    PFC* pfc,
    const G1& G1_gen,
    const std::string& timing_context
) {
    auto start_time = std::chrono::steady_clock::now();

    if (!pfc || !protocolValidG1(G1_gen, pfc, true) || !protocolValidG1(cert_pk.X, pfc, true) || !protocolValidG1(cert_pk.Y, pfc, true) ||
        !protocolValidG1(cert_pk.Z, pfc, true) || !protocolValidG2(cert.R_c_prime, pfc, true) ||
        !protocolValidG2(cert.vk_U_prime, pfc, true) || !protocolValidG2(cert.pk_U_prime, pfc, true) ||
        !protocolValidG2(cert.S_c_prime, pfc, false)) return false;

    // Check e(S_c',g_1)=e(R_c',X_c)e(vk_U',Y_c)e(pk_U',Z_c).

    // e(S_prime, G1_gen)
    GT lhs = pfc->pairing(cert.S_c_prime, G1_gen);

    // e(R_prime, X)
    GT rhs = pfc->pairing(cert.R_c_prime, cert_pk.X);

    // * e(vk_U', Y_c)
    rhs = rhs * pfc->pairing(cert.vk_U_prime, cert_pk.Y);

    // * e(P', Z)
    rhs = rhs * pfc->pairing(cert.pk_U_prime, cert_pk.Z);

    auto end_time = std::chrono::steady_clock::now();
    double duration = std::chrono::duration<double, std::milli>(end_time - start_time).count();
    std::string label = timingLabel("verifyRandomizedCertificate", timing_context);
    emitTimingRecord(label, duration);

    return lhs == rhs;
}
