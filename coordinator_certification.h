#ifndef COORDINATOR_CERTIFICATION_H
#define COORDINATOR_CERTIFICATION_H

#include <string>
#include <vector>
#include "Algorithm/pairing_3.h"
#include "multi_issuer.h"
#include "protocol_parameters.h"

using namespace std;

// 1. Certification public key (in G1)
struct CertPublicKey {
    G1 X;
    G1 Y;
    G1 Z;
};

// 2. Certification private key (in Z_p)
struct CertPrivateKey {
    Big x_c;
    Big y_c;
    Big z_c;
};

struct CertKeyPair {
    CertPublicKey pk;
    CertPrivateKey sk;
};

// 3. Certification signature (in G2)
struct CertSignature {
    G2 R_c;
    G2 S_c;
};

// 4. Randomized certificate material for the verifier
struct RandomizedCertificate {
    G2 vk_U_prime;
    G2 pk_U_prime;
    G2 R_c_prime;
    G2 S_c_prime;
};
struct IssuedCredential { SigShare credential; AggregatedPK aggregate_public_key; CertSignature certificate; };

CertKeyPair generateCertKeyPair(PFC* pfc, const G1& G1_gen);
CertSignature certifyCredentialBinding(const CertKeyPair& cert_kp, const G2& vk_U, const G2& pk_U, PFC* pfc, const G2& G2_gen);
RandomizedCertificate randomizeCertificate(const G2& vk_U, const G2& pk_U, const CertSignature& sig, Big r_2, PFC* pfc);
bool verifyCertificate(const CertPublicKey& cert_pk, const G2& vk_U, const G2& pk_U, const CertSignature& sig, PFC* pfc, const G1& G1_gen);
bool verifyRandomizedCertificate(
    const CertPublicKey& cert_pk,
    const RandomizedCertificate& cert,
    PFC* pfc,
    const G1& G1_gen,
    const std::string& timing_context = ""
);

#endif // COORDINATOR_CERTIFICATION_H
