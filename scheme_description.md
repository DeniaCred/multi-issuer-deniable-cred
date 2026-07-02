# 多签发方隐私保护凭证原型说明

本目录中的原型实现对应论文 `Final latex` 中第 4.2 节的具体构造。代码用于实验计时和协议一致性验证，不作为生产级密码库。

## 1. 聚合签发

系统运行在 Type-III 双线性配对群上。每个真实签发方持有 PS 风格密钥：

```text
sk_i = (x_i, y_{i,1}, ..., y_{i,k})
pk_i = (X_i, Y_{i,1}, ..., Y_{i,k})
X_i = g_2^{x_i}, Y_{i,j} = g_2^{y_{i,j}}
```

签名发起方在每次签发运行中内部生成一次性虚拟签发方 `DM`，并将真实签发方份额和虚拟份额聚合：

```text
S_i = h^{x_i + sum_j y_{i,j} m_j}
S_DM = h^{x_DM + sum_j y_{DM,j} m_j}
S_agg = S_DM * product_i S_i
APK = (X_agg, Y_agg,1, ..., Y_agg,k)
```

用户只获得 `sigma_agg = (h, S_agg)` 和不透明聚合公钥向量 `APK`，不获得真实签发方集合、签发方数量、`pk_DM` 或单个签发方公钥。

## 2. TA 担保与持有者承诺

用户生成持有者秘密 `u_U` 和承诺 `P_U = g_2^{u_U}`。TA 对 `(apk_U, P_U)` 出具可随机化担保：

```text
R_TA = g_2^rho
S_TA = R_TA^{x_TA} * apk_U^{y_TA} * P_U^{z_TA}
```

验证等式为：

```text
e(X_TA, R_TA) * e(Y_TA, apk_U) * e(Z_TA, P_U) = e(g_1, S_TA)
```

## 3. 验证者认证

验证者先生成绑定会话上下文 `ctx` 的 Schnorr 型证明：

```text
A = g_2^a
c = H(domain_VAuth, ppHash, ctx, pk_V, A)
z = a + c * sk_V
```

用户验证 `g_2^z = A * pk_V^c` 后才生成展示材料。

## 4. 盲化与展示

用户使用两个独立非零随机数 `r_1,r_2` 盲化凭证、TA 担保和持有者承诺：

```text
apk'_U = apk_U^{r_2}
h' = h^{r_1}
S'_agg = S_agg^{r_1*r_2}
R'_TA = R_TA^{r_2}
S'_TA = S_TA^{r_2}
P'_U = P_U^{r_2}
w_U = u_U * r_2 mod p
Q_V = H_G2(domain_nym, ppHash, ctx)
N_V = Q_V^{w_U}
```

展示公开材料为：

```text
C = (apk'_U, h', sigma'_TA, S'_agg, P'_U, N_V)
```

其中 `sigma'_TA = (R'_TA, S'_TA)`。

## 5. 指定验证者 OR proof

OR proof 证明以下二者之一成立：

```text
left:  P'_U = g_2^{w_U} and N_V = Q_V^{w_U}
right: pk_V = g_2^{sk_V}
```

真实用户证明左分支并模拟右分支；验证者模拟展示时证明右分支并模拟左分支。验证时除 OR proof 外，还必须检查：

```text
e(S'_agg, g_2) = e(h', apk'_U)
e(X_TA, R'_TA) * e(Y_TA, apk'_U) * e(Z_TA, P'_U) = e(g_1, S'_TA)
```

模拟展示必须使用同一份已经公开且可验证的盲化材料 `C`，不能重新生成虚假的凭证或 TA 证书。
