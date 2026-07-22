# Multi-Issuer Deniable Credential Prototype

This repository contains the experimental prototype for the concrete
construction used in the paper. The code checks algebraic consistency,
benchmarks the protocol phases, and demonstrates designated-verifier
deniability for presentation transcripts. It is research prototype code, not a
production cryptographic library.

The implementation follows this main flow:

```text
run_issuer_hiding_measurements.py
  -> build main_multi_issuer.cpp
  -> run the protocol prototype over benchmark parameters
  -> parse [Time] output with benchmark_and_plot.py
  -> benchmark unit operations with run_unit_benchmark.py
  -> estimate comparison baselines with estimate_issuer_hiding_baselines.py
  -> render Chapter 7 figures
  -> consolidate CSV/XLSX tables
```

`main_multi_issuer.cpp` is the end-to-end protocol entry point. It calls the
multi-issuer credential, TA certificate, verifier authentication, credential
blinding, OR-proof presentation, and verifier-side simulation modules.

## Repository Layout

| Path | Purpose |
| --- | --- |
| `main_multi_issuer.cpp` | End-to-end protocol demo and timing output. |
| `multi_issuer.cpp/.h` | PS-style issuer keys, signature shares, aggregation, public-key aggregation, and aggregate credential verification. |
| `trusted_authority.cpp/.h` | Randomizable TA certificate over `(apk_U, P_U)` and verification. |
| `nizk_proof.cpp/.h` | Verifier pre-authentication proving knowledge of `sk_V`. |
| `or_proof.cpp/.h` | Holder secret, blinding, presentation OR proof, full presentation verification, and verifier-side simulation. |
| `unit_operation_benchmark.cpp` | Unit benchmarks for group operations, pairings, and hashes. |
| `run_issuer_hiding_measurements.py` | Main issuer-hiding experiment driver. |
| `benchmark_and_plot.py` | Protocol runner, timing parser, statistics, and size estimates. |
| `run_unit_benchmark.py` | Unit-operation benchmark runner and workbook writer. |
| `estimate_issuer_hiding_baselines.py` | Formula-based comparison estimates from related work. |
| `render_chapter7_issuer_hiding_figures.py` | Figure generation for the experiment chapter. |
| `build_issuer_hiding_all_tables.py` | Consolidates CSV/XLSX/manifest outputs into one workbook. |
| `Algorithm/` | MIRACL, BN pairing, and Type-III pairing dependencies. |
| `results/` | Experiment outputs and historical results. |
| `tests/` | Python unit tests and structural checks. |

## Protocol Flow

The `main()` function in `main_multi_issuer.cpp` runs the prototype in this
order:

1. Initialize the pairing environment and sample `G1_gen` and `G2_gen`.
2. Generate keys for the coordinating issuer, one-time virtual issuer `DM`, and
   the other internal issuers.
3. Generate issuer signature shares with `signShare`.
4. Aggregate the shares and public keys into `(h, S_agg)` and opaque `APK`.
5. Verify the aggregate credential equation.
6. Generate a TA key pair, compute `apk_U`, create the holder public key `P_U`,
   and issue the TA certificate.
7. Authenticate the verifier with a Schnorr-style NIZK proof.
8. Blind the aggregate credential, TA certificate, holder public key, and
   presentation pseudonym.
9. Generate and verify the real holder presentation.
10. Generate a verifier-side simulated presentation over the same blinded
    public material.
11. Verify the simulated presentation with the same verification routine.

## Build

Build the MIRACL dependency first:

```bash
cd Algorithm/MIRACL
make linux64
```

Then build the protocol prototype:

```bash
cd ../..
make algorithm
```

Most experiment scripts build the required binaries automatically before they
run, so manual compilation is mainly useful for local debugging.

## Run

Run the interactive C++ prototype:

```bash
./main_multi_issuer
```

Run the lightweight Python tests:

```bash
python3 -m pytest tests -q
```

Run the issuer-hiding experiment driver:

```bash
python3 run_issuer_hiding_measurements.py
```

The full experiment can take longer and can overwrite files under `results/`.
For a quick confidence check, prefer the unit tests and the C++ build.

## Notes

- `q_internal` is an internal contribution count, not a user-visible issuer
  count.
- In the current construction, the user receives only aggregate credential
  material and an opaque aggregate public-key vector. The user does not receive
  the real issuer set, `pk_DM`, individual issuer public keys, or signature
  shares.
- `Algorithm/MIRACL` is a third-party cryptographic dependency. Its example
  programs are not part of the credential construction.
- `results/new_aggregation_threshold` contains historical threshold-aggregation
  outputs. The current issuer-hiding experiment path uses
  `results/issuer_hiding_*`.

## License

This repository includes third-party MIRACL material. See `LICENSE`,
`THIRD_PARTY_NOTICES.md`, and the MIRACL licensing files under `Algorithm/` for
license details.
