param(
    [string]$Root = $PSScriptRoot
)

$ErrorActionPreference = 'Stop'

function Read-Source([string]$RelativePath) {
    Get-Content -Path (Join-Path $Root $RelativePath) -Raw
}

function Assert-Contains([string]$Text, [string]$Pattern, [string]$Message) {
    if ($Text -notmatch $Pattern) {
        throw $Message
    }
}

function Assert-NotContains([string]$Text, [string]$Pattern, [string]$Message) {
    if ($Text -match $Pattern) {
        throw $Message
    }
}

$orProofCpp = Read-Source 'or_proof.cpp'
$orProofH = Read-Source 'or_proof.h'
$taAuthH = Read-Source 'trusted_authority.h'
$mainCpp = Read-Source 'main_multi_issuer.cpp'

Assert-NotContains $orProofCpp '\blxor\s*\(' 'OR proof challenge splitting must use modular addition/subtraction, not logical XOR.'
Assert-Contains $orProofH 'RandomizedTACredential\s+ta_cred' 'PresentationPayload must carry the randomized TA credential from sigma_TA prime.'
Assert-Contains $orProofH 'HolderSecret' 'The implementation must include HolderKeyGen output u_U/P_U.'
Assert-Contains $orProofH 'P_prime' 'Blinded credential material must carry P_U prime.'
Assert-Contains $orProofH 'N_V' 'Blinded credential material must carry verifier-bound pseudonym N_V.'
Assert-Contains $orProofH 'bool\s+verifyPresentationPayload\s*\(' 'Final Verify must bind TA verification, aggregate credential verification, and OR verification.'
Assert-Contains $orProofH 'const\s+G2&\s+expected_pk_V' 'Final Verify must receive the verifier public key expected by the current session.'
Assert-Contains $orProofCpp 'same_g2\s*\(\s*payload\.pk_V\s*,\s*expected_pk_V\s*\)' 'Final Verify must reject transcripts bound to a different verifier public key.'
Assert-Contains $orProofCpp 'verifyRandomizedTACredential\s*\(' 'Final Verify must check the randomized TA attestation equation.'
Assert-Contains $orProofCpp 'verifyBlindedAggregateCredential\s*\(' 'Final Verify must check the randomized aggregate credential equation.'
Assert-Contains $orProofCpp 'hashToG2' 'The OR proof must derive Q_V from a domain-separated context hash into G2.'
Assert-Contains $orProofCpp 'A1' 'The left OR branch must use Schnorr commitment A1 for P_U prime.'
Assert-Contains $orProofCpp 'A2' 'The left OR branch must use Schnorr commitment A2 for N_V.'
Assert-NotContains $orProofH 'GT\s+T_left' 'The old pairing-based left branch must be removed.'
Assert-NotContains $orProofH 'G1\s+z_h' 'The old pairing-based z_h response must be removed.'
Assert-NotContains $orProofH 'G1\s+z_s' 'The old pairing-based z_s response must be removed.'
Assert-Contains $taAuthH 'Z' 'TA public key must include Z_TA for binding P_U.'
Assert-Contains $orProofH 'blindCredential\([^;]*Big\s+r_1[^;]*Big\s+r_2' 'Blind must expose independent r_1 and r_2 blinding exponents.'
Assert-Contains $orProofCpp 'user_apk_prime\s*=\s*pfc->mult\(user_apk,\s*r_2\)' 'Blind must randomize apk_U with r_2.'
Assert-Contains $orProofCpp 'h_prime\s*=\s*pfc->mult\(sig\.h,\s*r_1\)' 'Blind must randomize h with r_1.'
Assert-Contains $orProofCpp 'modmult\(r_1,\s*r_2,\s*pfc->order\(\)\)' 'Blind must randomize S_agg with r_1*r_2.'
Assert-Contains $orProofCpp 'P_prime\s*=\s*pfc->mult\(holder\.P_U,\s*r_2\)' 'Blind must randomize P_U with r_2.'
Assert-Contains $orProofCpp 'w_U\s*=\s*modmult\(holder\.u_U,\s*r_2,\s*pfc->order\(\)\)' 'Blind must set w_U = u_U*r_2.'
Assert-Contains $taAuthH 'Big\s+r_2' 'TA randomization must use the same r_2 exponent as apk_U and P_U blinding.'
Assert-Contains $mainCpp 'r_1\s*=\s*randomNonZeroScalar\(pfc\)' 'Blind must sample r_1 from Z_p^*.'
Assert-Contains $mainCpp 'r_2\s*=\s*randomNonZeroScalar\(pfc\)' 'Blind must sample r_2 from Z_p^*.'
Assert-Contains $mainCpp 'randomizeTACredential\(user_apk,\s*holder\.P_U,\s*ta_sig,\s*r_2' 'TA attestation randomization must use r_2.'
Assert-Contains $mainCpp 'blindCredential\(user_apk,\s*holder,\s*aggregated_sig,\s*r_1,\s*r_2' 'Credential blinding must pass r_1 and r_2.'
Assert-NotContains $mainCpp 'r_blind' 'Single-exponent r_blind blinding must not remain in the main flow.'
Assert-NotContains $orProofH 'Big\s+r\s*,' 'Blind must not expose a single generic r exponent.'
Assert-NotContains $orProofCpp 'r_sq' 'Blind must not compute S_agg randomization as r^2.'
Assert-Contains $mainCpp 'pfc\.random\(h\)' 'AggIssue must sample a fresh random issuance base h.'
Assert-NotContains $mainCpp 'hash_and_map\(h' 'AggIssue must not derive h by hashing the attribute vector.'

Write-Host 'Protocol consistency checks passed.'
