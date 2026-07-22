#ifndef TRUSTED_AUTHORITY_H
#define TRUSTED_AUTHORITY_H

#include <string>
#include <vector>
#include "Algorithm/pairing_3.h"
#include "multi_issuer.h"

using namespace std;

// 1. TA public-key structure; all elements are in G1
struct TAPublicKey {
    G1 X;           // X = x_{TA} * G1_gen
    G1 Y;           // Y = y_{TA} * G1_gen
    G1 Z;           // Z = z_{TA} * G1_gen
};

// 2. TA secret-key structure over Z_p
struct TAPrivateKey {
    Big x_TA;
    Big y_TA;
    Big z_TA;
};

struct TAKeyPair {
    TAPublicKey pk;
    TAPrivateKey sk;
};

// 3. TA signature structure over G2
struct TASignature {
    G2 R;
    G2 S;
};

// 4. Blinded data bundle sent to the verifier
struct RandomizedTACredential {
    G2 user_apk_prime; // blinded user_apk
    G2 P_prime;        // blinded holder public key P_U
    G2 R_prime;
    G2 S_prime;
};

// Function declarations
TAKeyPair generateTAKeyPair(PFC* pfc, const G1& G1_gen);
TASignature signUserApk(const TAKeyPair& ta_kp, const G2& user_apk, const G2& P_U, PFC* pfc, const G2& G2_gen);
RandomizedTACredential randomizeTACredential(const G2& user_apk, const G2& P_U, const TASignature& sig, Big r_2, PFC* pfc);
bool verifyRandomizedTACredential(
    const TAPublicKey& ta_pk,
    const RandomizedTACredential& ta_cred,
    PFC* pfc,
    const G1& G1_gen,
    const std::string& timing_context = ""
);

#endif // TRUSTED_AUTHORITY_H
