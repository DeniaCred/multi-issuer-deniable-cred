# 多签发方隐私保护凭证原型代码说明

本目录是论文第 4.2 节具体构造的本地实验原型。代码用于验证协议代数一致性、指定验证者可否认展示，以及生成论文实验数据；它不是生产级密码库。

代码主线是：

```text
run_issuer_hiding_measurements.py
  -> 编译 main_multi_issuer.cpp
  -> 批量运行协议原型
  -> benchmark_and_plot.py 解析 [Time] 输出
  -> run_unit_benchmark.py / unit_operation_benchmark.cpp 测底层操作
  -> estimate_issuer_hiding_baselines.py 推算对比方案
  -> render_chapter7_issuer_hiding_figures.py 生成图
  -> build_issuer_hiding_all_tables.py 汇总表格
```

`main_multi_issuer.cpp` 是协议主入口，按顺序调用 `multi_issuer`、`trusted_authority`、`nizk_proof` 和 `or_proof` 中的函数。

## 目录结构

| 路径 | 作用 |
| --- | --- |
| `main_multi_issuer.cpp` | 端到端协议演示和计时输出入口。 |
| `multi_issuer.cpp/.h` | PS 风格多签发方密钥、签名份额、签名聚合、公钥聚合和聚合凭证验证。 |
| `trusted_authority.cpp/.h` | TA 对 `(apk_U, P_U)` 的可随机化担保及验证。 |
| `nizk_proof.cpp/.h` | 验证者预认证，即证明验证者知道 `sk_V`。 |
| `or_proof.cpp/.h` | 持有者秘密、盲化、展示 OR proof、完整展示验证和验证者侧模拟。 |
| `unit_operation_benchmark.cpp` | 底层群运算、配对、哈希等单位耗时测试。 |
| `run_issuer_hiding_measurements.py` | 当前 issuer-hiding 实验主入口。 |
| `benchmark_and_plot.py` | 运行协议、解析计时、统计均值/中位数/截尾均值、估算通信大小。 |
| `run_unit_benchmark.py` | 调用 `unit_operation_benchmark` 并写出单位操作耗时工作簿。 |
| `estimate_issuer_hiding_baselines.py` | 根据文献公式和单位操作耗时推算对比方案数据。 |
| `render_chapter7_issuer_hiding_figures.py` | 根据 CSV 结果生成第七章图。 |
| `build_issuer_hiding_all_tables.py` | 汇总 CSV/XLSX/manifest 为总表格。 |
| `Algorithm/` | MIRACL、BN pairing 和 Type-III pairing 相关依赖。 |
| `results/` | 实验输出和历史结果。 |
| `tests/` | Python 单元测试和结构一致性检查。 |

## 核心协议调用链

`main_multi_issuer.cpp:47` 中的 `main()` 是协议主流程：

1. 初始化 `PFC pfc(128)`，随机生成 `G1_gen` 和 `G2_gen`。
2. 调用 `generateKeyPair` 生成签名发起方、一次性虚拟签发方 `DM` 和其他签发方密钥。
3. 调用 `signShare` 生成各签发方份额。
4. 调用 `aggregateSignatures` 和 `aggregatePublicKeys` 得到 `(h,S_agg)` 与 `APK`。
5. 调用 `verifySignature` 检查聚合凭证和不透明聚合公钥向量是否代数一致。
6. 调用 `generateTAKeyPair`、`computeUserApk`、`generateHolderSecret` 和 `signUserApk` 生成 TA 担保。
7. 调用 `generateVerifierKeyPair`、`generateNIZKProof` 和 `verifyNIZKProof` 完成验证者预认证。
8. 调用 `randomizeTACredential` 和 `blindCredential` 盲化凭证材料。
9. 调用 `generatePresentationPayload` 生成真实用户展示。
10. 调用 `verifyPresentationPayload` 验证真实展示。
11. 调用 `simulatePresentationPayloadByVerifier` 生成验证者侧模拟展示。
12. 再次调用 `verifyPresentationPayload` 验证模拟展示。

## `main_multi_issuer.cpp`

| 函数 | 作用 | 调用位置 |
| --- | --- | --- |
| `printSummaryTable` (`main_multi_issuer.cpp:16`) | 打印本次运行中记录的所有阶段耗时。 | `main_multi_issuer.cpp:283`。 |
| `randomNonZeroScalar` (`main_multi_issuer.cpp:33`) | 从群阶中采样非零随机数，用作 `r_1` 和 `r_2`。 | `main_multi_issuer.cpp:207`--`208`。 |
| `recordExecutionTime` (`main_multi_issuer.cpp:42`) | 统一记录和输出阶段耗时。 | `main_multi_issuer.cpp:123`, `151`, `161`, `183`, `193`, `210`, `218`, `246` 等。 |
| `main` (`main_multi_issuer.cpp:47`) | 协议演示入口，串联聚合签发、TA 担保、验证者认证、盲化展示和模拟展示。 | 被可执行文件入口调用；Python 实验脚本通过运行编译后的程序间接调用。 |

## `multi_issuer.cpp/.h`

该模块对应具体构造中的 `IKg`、`DMGen`、`IssueShare`、`AggIssue` 和 `CredVerify`。代码使用 MIRACL 的加法群表示：`pfc->mult(P,a)` 对应论文中的 `P^a`，点相加对应群乘。

| 函数 | 作用 | 调用位置 |
| --- | --- | --- |
| `generateKeyPair` (`multi_issuer.cpp:8`) | 生成一个签发方密钥对，私钥为 `(x,y_1,...,y_k)`，公钥为 `(X,Y_1,...,Y_k)`。也用于生成一次性虚拟签发方 `DM`。 | `main_multi_issuer.cpp:74`, `77`, `86`。 |
| `signShare` (`multi_issuer.cpp:25`) | 计算签名份额 `S_i = h^{x_i + sum y_{i,j}m_j}`。 | `main_multi_issuer.cpp:95`, `98`, `102`。 |
| `aggregateSignatures` (`multi_issuer.cpp:42`) | 将真实签发方份额和 `DM` 份额聚合为 `S_agg`。 | `main_multi_issuer.cpp:106`。 |
| `aggregatePublicKeys` (`multi_issuer.cpp:56`) | 聚合所有内部贡献者的公钥，得到不透明 `APK=(X_agg,Y_agg,1,...,Y_agg,k)`。 | `main_multi_issuer.cpp:121`。 |
| `verifySignature` (`multi_issuer.cpp:75`) | 检查 `e(S_agg,g_2)=e(h,apk_U)`，确认聚合凭证和 `APK` 代数一致。 | `main_multi_issuer.cpp:132`。 |

## `trusted_authority.cpp/.h`

该模块对应具体构造中的 `TAKeyGen`、`TACert`、`TAVerify`，以及展示阶段对 TA 担保的随机化。

| 函数 | 作用 | 调用位置 |
| --- | --- | --- |
| `generateTAKeyPair` (`trusted_authority.cpp:8`) | 生成 TA 私钥 `(x_TA,y_TA,z_TA)` 和公钥 `(X_TA,Y_TA,Z_TA)`。 | `main_multi_issuer.cpp:143`。 |
| `signUserApk` (`trusted_authority.cpp:25`) | 对 `(apk_U,P_U)` 生成 TA 担保 `sigma_TA=(R_TA,S_TA)`。 | `main_multi_issuer.cpp:159`。 |
| `randomizeTACredential` (`trusted_authority.cpp:46`) | 使用 `r_2` 随机化 `apk_U`、`P_U`、`R_TA` 和 `S_TA`。 | `main_multi_issuer.cpp:210`。 |
| `verifyRandomizedTACredential` (`trusted_authority.cpp:61`) | 检查随机化后的 TA 担保等式。 | `main_multi_issuer.cpp:226`；也被 `verifyPresentationPayload` 在 `or_proof.cpp:268` 调用。 |

## `nizk_proof.cpp/.h`

该模块对应具体构造中的 `VKeyGen`、`VAuth` 和 `VAuthVerify`。

| 函数 | 作用 | 调用位置 |
| --- | --- | --- |
| `addStringToHash` (`nizk_proof.cpp:5`) | 将字符串加入 Fiat-Shamir 哈希输入。 | 内部辅助函数，被 `vAuthChallenge` 调用。 |
| `vAuthChallenge` (`nizk_proof.cpp:9`) | 计算验证者认证证明挑战 `c=H(domain_VAuth, ppHash, ctx, pk_V, A)`。 | `generateNIZKProof` 在 `nizk_proof.cpp:39` 调用；`verifyNIZKProof` 在 `nizk_proof.cpp:51` 调用。 |
| `generateVerifierKeyPair` (`nizk_proof.cpp:22`) | 生成验证者密钥 `sk_V` 和 `pk_V=g_2^{sk_V}`。 | `main_multi_issuer.cpp:174`。 |
| `generateNIZKProof` (`nizk_proof.cpp:30`) | 生成 Schnorr 型 NIZK 证明 `(A,z)`，证明验证者知道 `sk_V`。 | `main_multi_issuer.cpp:181`。 |
| `verifyNIZKProof` (`nizk_proof.cpp:50`) | 检查 `g_2^z=A*pk_V^c`。 | `main_multi_issuer.cpp:191`。 |

## `or_proof.cpp/.h`

该模块对应具体构造中的 `HolderKeyGen`、`Blind`、`Present`、`Verify`、`ORProve`、`ORVerify`、`SimORProve` 和 `SimPresent`。

| 函数 | 作用 | 调用位置 |
| --- | --- | --- |
| `mod_add` (`or_proof.cpp:8`) | 模群阶加法。 | `verifyORProof` 在 `or_proof.cpp:174` 调用。 |
| `mod_sub` (`or_proof.cpp:12`) | 模群阶减法，用于挑战拆分和模拟分支。 | `generatePresentationPayload` 在 `or_proof.cpp:135`, `147` 调用；`simulatePresentationPayloadByVerifier` 在 `or_proof.cpp:304`, `315` 调用。 |
| `randomNonZero` (`or_proof.cpp:16`) | 采样非零标量。 | `generateHolderSecret` 在 `or_proof.cpp:74` 调用。 |
| `addStringToHash` (`or_proof.cpp:25`) | 将字符串加入 OR proof 哈希输入。 | `hashToScalar` 和 `hash_or_challenge` 内部调用。 |
| `hashToScalar` (`or_proof.cpp:29`) | 将域标签和 `ctx` 哈希到标量。 | `hashToG2` 在 `or_proof.cpp:42` 调用。 |
| `hashToG2` (`or_proof.cpp:41`) | 生成上下文绑定基点 `Q_V`。 | `blindCredential` 在 `or_proof.cpp:107` 调用；`generatePresentationPayload` 在 `or_proof.cpp:142` 调用；`verifyORProof` 在 `or_proof.cpp:196` 调用；`simulatePresentationPayloadByVerifier` 在 `or_proof.cpp:305` 调用。 |
| `hash_or_challenge` (`or_proof.cpp:45`) | 计算 OR proof 总挑战，绑定 `ctx`、`pk_V`、盲化凭证、TA 担保和承诺。 | `generatePresentationPayload` 在 `or_proof.cpp:146` 调用；`verifyORProof` 在 `or_proof.cpp:173` 调用；`simulatePresentationPayloadByVerifier` 在 `or_proof.cpp:314` 调用。 |
| `same_g2` (`or_proof.cpp:64`) | 比较两个 `G2` 元素是否一致。 | `verifyPresentationPayload` 在 `or_proof.cpp:262`, `264`, `266` 调用。 |
| `generateHolderSecret` (`or_proof.cpp:72`) | 生成持有者秘密 `u_U` 和承诺 `P_U=g_2^{u_U}`。 | `main_multi_issuer.cpp:156`。 |
| `computeUserApk` (`or_proof.cpp:79`) | 根据 `APK` 和属性向量计算 `apk_U=X_agg+sum m_jY_agg,j`。 | `main_multi_issuer.cpp:149`。 |
| `blindCredential` (`or_proof.cpp:88`) | 使用 `r_1,r_2` 计算 `apk'_U=apk_U^{r_2}`、`h'=h^{r_1}`、`S'_agg=S_agg^{r_1r_2}`、`P'_U`、`w_U` 和 `N_V`。 | `main_multi_issuer.cpp:218`。 |
| `generatePresentationPayload` (`or_proof.cpp:112`) | 生成真实用户展示转录；真实证明左分支，模拟右分支。 | `main_multi_issuer.cpp:236`。 |
| `verifyORProof` (`or_proof.cpp:162`) | 验证挑战拆分、右分支 `pk_V` 关系、左分支 `P'_U/N_V` 关系。 | `verifyPresentationPayload` 在 `or_proof.cpp:274` 调用。 |
| `verifyBlindedAggregateCredential` (`or_proof.cpp:228`) | 检查盲化后的聚合凭证等式 `e(S'_agg,g_2)=e(h',apk'_U)`。 | `verifyPresentationPayload` 在 `or_proof.cpp:270` 调用。 |
| `verifyPresentationPayload` (`or_proof.cpp:247`) | 完整展示验证：检查 `ctx`、期望的验证者 `pk_V`、TA 担保绑定、盲化聚合凭证和 OR proof。 | `main_multi_issuer.cpp:253`, `275`。 |
| `simulatePresentationPayloadByVerifier` (`or_proof.cpp:282`) | 验证者用 `sk_V` 生成模拟展示；模拟左分支，真实证明右分支。 | `main_multi_issuer.cpp:264`。 |

## `unit_operation_benchmark.cpp`

该文件测量底层操作耗时，用于对其他方案做公式推算。

| 函数 | 作用 | 调用位置 |
| --- | --- | --- |
| `median` (`unit_operation_benchmark.cpp:55`) | 计算样本中位数。 | `measure` 在 `unit_operation_benchmark.cpp:113` 调用。 |
| `stddev` (`unit_operation_benchmark.cpp:63`) | 计算样本标准差。 | `measure` 在 `unit_operation_benchmark.cpp:114` 调用。 |
| `measure` (`unit_operation_benchmark.cpp:74`) | 对某个底层操作重复计时并返回统计摘要。 | `main` 在 `unit_operation_benchmark.cpp:199` 到 `289` 多次调用。 |
| `format_double` (`unit_operation_benchmark.cpp:121`) | 格式化浮点数输出。 | `print_tsv` 在 `unit_operation_benchmark.cpp:147` 到 `151` 调用。 |
| `random_nonzero_scalar` (`unit_operation_benchmark.cpp:127`) | 采样非零标量。 | `main` 在 `unit_operation_benchmark.cpp:171` 调用。 |
| `print_tsv` (`unit_operation_benchmark.cpp:135`) | 将单位操作结果输出为 TSV。 | `main` 在 `unit_operation_benchmark.cpp:295` 调用。 |
| `main` (`unit_operation_benchmark.cpp:159`) | 单位操作 benchmark 入口。 | 被 `run_unit_benchmark.py` 运行。 |

## Python 实验脚本调用关系

### `run_issuer_hiding_measurements.py`

这是当前实验主入口。

| 函数 | 作用 | 调用关系 |
| --- | --- | --- |
| `build_binaries` (`run_issuer_hiding_measurements.py:170`) | 编译 `main_multi_issuer.cpp` 和 `unit_operation_benchmark.cpp`。 | `main` 在 `run_issuer_hiding_measurements.py:553` 调用。 |
| `experiment_jobs` (`run_issuer_hiding_measurements.py:209`) | 生成 k 轴、q 轴、最大参数点三组实验任务。 | `main` 通过 `run_protocol_job` 循环使用。 |
| `run_protocol_job` (`run_issuer_hiding_measurements.py:262`) | 对单个实验任务多轮运行协议原型。 | `main` 在 `run_issuer_hiding_measurements.py:560` 调用。 |
| `build_wide_rows` (`run_issuer_hiding_measurements.py:297`) | 将 long summary 转成 wide summary。 | `main` 在 `run_issuer_hiding_measurements.py:566` 调用。 |
| `run_unit_benchmark` (`run_issuer_hiding_measurements.py:364`) | 运行单位操作 benchmark。 | `main` 在 `run_issuer_hiding_measurements.py:554` 调用。 |
| `run_baseline_estimates` (`run_issuer_hiding_measurements.py:381`) | 调用 `estimate_issuer_hiding_baselines.py` 推算对比方案。 | `main` 在 `run_issuer_hiding_measurements.py:569` 调用。 |
| `write_manifest` (`run_issuer_hiding_measurements.py:446`) | 写 `manifest.json` 和 `manifest.md`。 | `main` 在 `run_issuer_hiding_measurements.py:551`, `572` 调用。 |
| `main` (`run_issuer_hiding_measurements.py:524`) | 完整实验入口。 | 命令行执行本脚本时调用。 |

辅助函数如 `iso_now`、`csv_write`、`parse_round_exclusion`、`exclude_rounds` 用于时间戳、CSV 写入和剔除指定异常轮次。

### `benchmark_and_plot.py`

这是通用实验统计工具。

| 函数 | 作用 | 调用关系 |
| --- | --- | --- |
| `parse_timing_records` (`benchmark_and_plot.py:419`) | 从 C++ 标准输出中解析 `[Time] ... ms` 记录。 | `run_protocol` 调用。 |
| `estimate_size_fields` (`benchmark_and_plot.py:457`) | 估算凭证、证明、公开材料和展示转录字节数。 | `build_rows` 调用。 |
| `run_protocol` (`benchmark_and_plot.py:494`) | 启动编译后的 `main_multi_issuer`，输入参数并收集计时。 | `collect_benchmarks` 和 `run_issuer_hiding_measurements.py` 间接使用。 |
| `trimmed_mean` (`benchmark_and_plot.py:529`) | 计算截尾均值，减小长尾慢样本影响。 | `summarize_rows` 调用。 |
| `build_rows` (`benchmark_and_plot.py:576`) | 将一次协议运行结果扩展成带参数、阶段、大小估计的 raw rows。 | `collect_benchmarks` 和实验 runner 使用。 |
| `summarize_rows` (`benchmark_and_plot.py:601`) | 按方案、参数、阶段、组件聚合 raw rows。 | 实验 runner 和测试调用。 |
| `write_summary_wide_csv` (`benchmark_and_plot.py:745`) | 写宽格式 summary CSV。 | 实验 runner 或独立 benchmark 使用。 |
| `write_performance_workbook` (`benchmark_and_plot.py:914`) | 写实验 Excel 工作簿。 | 独立 benchmark 和测试调用。 |
| `collect_benchmarks` (`benchmark_and_plot.py:1042`) | 按参数批量运行协议。 | `main` 调用。 |
| `main` (`benchmark_and_plot.py:1236`) | 独立 benchmark 入口。 | 命令行执行本脚本时调用。 |

### `run_unit_benchmark.py`

| 函数 | 作用 | 调用关系 |
| --- | --- | --- |
| `build_command` (`run_unit_benchmark.py:171`) | 构造单位操作 benchmark 可执行文件命令。 | `run` 调用。 |
| `parse_tsv` (`run_unit_benchmark.py:185`) | 解析 `unit_operation_benchmark.cpp` 输出的 TSV。 | `run` 调用。 |
| `write_xlsx` (`run_unit_benchmark.py:255`) | 写单位操作结果工作簿。 | `run` 调用；测试中也直接调用。 |
| `run` (`run_unit_benchmark.py:349`) | 运行单位操作 benchmark 并写 CSV/XLSX。 | 脚本入口调用；`run_issuer_hiding_measurements.py` 通过子进程调用。 |

### `estimate_issuer_hiding_baselines.py`

| 函数 | 作用 | 调用关系 |
| --- | --- | --- |
| `dimensions` (`estimate_issuer_hiding_baselines.py:68`) | 给出推算时使用的参数点。 | `build_rows` 调用。 |
| `katz_sefranek_2026` (`estimate_issuer_hiding_baselines.py:99`) | 按 Katz--Sefranek 2026 公式推算。 | `build_rows` 调用。 |
| `sanders_traore_2024_as_in_ks` (`estimate_issuer_hiding_baselines.py:144`) | 按 Katz--Sefranek 文中对 Sanders--Traore 2024 的公式描述推算。 | `build_rows` 调用。 |
| `bobolz_2021` (`estimate_issuer_hiding_baselines.py:189`) | 记录 Bobolz 2021 的可比指标和公式项。 | `build_rows` 调用。 |
| `bosk_2022_hiac` (`estimate_issuer_hiding_baselines.py:232`) | 推算 HIAC 相关指标。 | `build_rows` 调用。 |
| `elkhiyaoui_2021` (`estimate_issuer_hiding_baselines.py:278`) | 推算 multi-issuer anonymous credentials without root authority。 | `build_rows` 调用。 |
| `mir_2023_formula_only` (`estimate_issuer_hiding_baselines.py:322`) | 记录 Mir 2023 公式级比较项。 | `build_rows` 调用。 |
| `build_rows` (`estimate_issuer_hiding_baselines.py:358`) | 汇总所有对比方案推算结果。 | `main` 调用。 |
| `write_outputs` (`estimate_issuer_hiding_baselines.py:389`) | 写 CSV 和 XLSX 输出。 | `main` 调用。 |
| `main` (`estimate_issuer_hiding_baselines.py:411`) | 推算脚本入口。 | `run_issuer_hiding_measurements.py` 通过子进程调用。 |

### `render_chapter7_issuer_hiding_figures.py`

| 函数 | 作用 | 调用关系 |
| --- | --- | --- |
| `configure_style` (`render_chapter7_issuer_hiding_figures.py:53`) | 配置 Matplotlib/Seaborn 风格。 | `main` 调用。 |
| `render_ourscheme_scalability` (`render_chapter7_issuer_hiding_figures.py:163`) | 生成本方案 k 轴、q 轴和最大参数点组件开销图。 | `main` 调用。 |
| `render_issuer_hiding_comparison` (`render_chapter7_issuer_hiding_figures.py:316`) | 生成本方案与 issuer-hiding 对比方案的对比图。 | `main` 调用。 |
| `main` (`render_chapter7_issuer_hiding_figures.py:421`) | 图生成入口，读取 `ours_summary_wide.csv` 和 `issuer_hiding_baselines.csv`。 | 命令行执行本脚本时调用。 |

### `build_issuer_hiding_all_tables.py`

| 函数 | 作用 | 调用关系 |
| --- | --- | --- |
| `iter_csv_rows` (`build_issuer_hiding_all_tables.py:285`) | 读取 CSV 行。 | `add_rows_sheet` 调用。 |
| `iter_xlsx_rows` (`build_issuer_hiding_all_tables.py:293`) | 读取 XLSX 指定 sheet。 | `add_rows_sheet` 调用。 |
| `add_rows_sheet` (`build_issuer_hiding_all_tables.py:330`) | 将一个来源文件写入工作簿 sheet。 | `build_workbook` 调用。 |
| `add_manifest_sheet` (`build_issuer_hiding_all_tables.py:369`) | 写 manifest sheet。 | `build_workbook` 调用。 |
| `add_index_sheet` (`build_issuer_hiding_all_tables.py:391`) | 写索引 sheet。 | `build_workbook` 调用。 |
| `add_field_dictionary` (`build_issuer_hiding_all_tables.py:413`) | 写字段解释 sheet。 | `build_workbook` 调用。 |
| `build_workbook` (`build_issuer_hiding_all_tables.py:423`) | 汇总所有表格来源并生成总工作簿。 | `main` 调用。 |
| `main` (`build_issuer_hiding_all_tables.py:435`) | 表格汇总入口。 | 命令行执行本脚本时调用。 |

## 构建方式

先构建 MIRACL 依赖：

```sh
make algorithm
```

再构建协议原型：

```sh
g++ -std=c++11 -O2 -o main_multi_issuer \
  main_multi_issuer.cpp multi_issuer.cpp trusted_authority.cpp \
  nizk_proof.cpp or_proof.cpp Algorithm/bn_pair.cpp Algorithm/miracl.a -w
```

通常不需要手动运行上面的命令，因为 `run_issuer_hiding_measurements.py` 会自动编译当前实验所需的二进制文件。

## 验证方式

协议结构一致性检查：

```powershell
powershell -ExecutionPolicy Bypass -File .\protocol_consistency_test.ps1
```

Python 单元测试：

```sh
python -m unittest discover -s tests -p "test_*.py"
```

## 重要说明

- `q_internal` 是实验内部贡献数量，不是用户可见的发行方数量。
- 用户在当前构造中只接收聚合凭证材料和不透明聚合公钥向量，不获得真实签发方集合、`DM` 公钥或单个签发方公钥。
- `Algorithm/MIRACL` 是外部密码库依赖，不属于本方案业务逻辑；不要把其中示例程序当作论文方案代码。
- `results/new_aggregation_threshold` 是旧聚合门限实验结果，当前 issuer-hiding 主线优先使用 `results/issuer_hiding_*`。
