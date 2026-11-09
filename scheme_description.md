# Prototype Scheme Description

This prototype corresponds to the concrete construction used in the paper. It
is intended for timing experiments and protocol consistency checks, not for
production deployment.

## 1. Aggregate Issuance

The system works over Type-III pairing groups. Each real issuer holds a
PS-style key:

```text
sk_i = (x_i, y_{i,1}, ..., y_{i,k})
pk_i = (X_i, Y_{i,1}, ..., Y_{i,k})
X_i = g_2^{x_i}, Y_{i,j} = g_2^{y_{i,j}}
```

For each issuance run, the coordinating issuer internally creates a one-time
virtual issuer `DM` and aggregates the real issuer shares together with the
virtual share:

```text
S_i = h^{x_i + sum_j y_{i,j} m_j}
S_DM = h^{x_DM + sum_j y_{DM,j} m_j}
S_agg = S_DM * product_i S_i
APK = (X_agg, Y_agg,1, ..., Y_agg,k)
```

After TA certification, the coordinating issuer delivers the aggregate
credential `sigma_agg = (h, S_agg)`, aggregate public-key vector `APK`, and
TA certificate. The holder verifies the credential and the certificate. The user does not receive the real issuer set, the
issuer count, `pk_DM`, or individual issuer public keys.

## 2. TA Certificate and Holder Public Key

The user samples a holder secret `u_U` and holder public key `P_U = g_2^{u_U}`.
The coordinating issuer derives the verification key
`vk_U = X_agg * product_j Y_agg,j^{m_j}` and requests a randomizable TA
certificate on `(vk_U, P_U)`:

```text
R_TA = g_2^rho
S_TA = R_TA^{x_TA} * vk_U^{y_TA} * P_U^{z_TA}
```

The verification equation is:

```text
e(X_TA, R_TA) * e(Y_TA, vk_U) * e(Z_TA, P_U) = e(g_1, S_TA)
```

## 3. Verifier Authentication

Before receiving a presentation, the verifier proves knowledge of its secret
key with a Schnorr-style proof bound to the session context `ctx`:

```text
A = g_2^a
c = H(domain_VAuth, ppHash, ctx, pk_V, A)
z = a + c * sk_V
```

The user checks `g_2^z = A * pk_V^c` before generating the presentation
material.

## 4. Blinding and Presentation

The user samples two independent nonzero values `r_1` and `r_2` to blind the
credential, TA certificate, and holder public key:

```text
vk'_U = vk_U^{r_2}
h' = h^{r_1}
S'_agg = S_agg^{r_1*r_2}
R'_TA = R_TA^{r_2}
S'_TA = S_TA^{r_2}
P'_U = P_U^{r_2}
w_U = u_U * r_2 mod p
Q_V = H_G2(domain_nym, ppHash, ctx)
N_V = Q_V^{w_U}
```

The public presentation material is:

```text
C = (vk'_U, h', sigma'_TA, S'_agg, P'_U, N_V)
```

where `sigma'_TA = (R'_TA, S'_TA)`.

## 5. Designated-Verifier OR Proof

The OR proof shows that at least one of the following statements is true:

```text
left:  P'_U = g_2^{w_U} and N_V = Q_V^{w_U}
right: pk_V = g_2^{sk_V}
```

The real holder proves the left branch and simulates the right branch. The
verifier-side simulator proves the right branch and simulates the left branch.
Verification also checks:

```text
e(S'_agg, g_2) = e(h', vk'_U)
e(X_TA, R'_TA) * e(Y_TA, vk'_U) * e(Z_TA, P'_U) = e(g_1, S'_TA)
```

The simulated presentation must reuse the same public, already verifiable
blinded material `C`; it must not create a new aggregate credential or a new TA
certificate.
