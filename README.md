# Multi-Issuer Deniable Credential Prototype

This C++ prototype implements aggregate issuance with a fresh one-time virtual
issuer, randomizable TA certification, credential blinding, and an OR proof
with a verifier-secret branch. The verifier can simulate the proof for fixed
publicly valid blinded material. See [the protocol description](scheme_description.md).

## Third-party dependency

The prototype uses the [MIRACL Crypto SDK](https://github.com/miracl/MIRACL)
by MIRACL Ltd. for elliptic-curve arithmetic and bilinear pairings. The
repository includes MIRACL source files under `Algorithm/` and
`Algorithm/MIRACL/`. See [Third-Party Notices](THIRD_PARTY_NOTICES.md)
for the upstream citation and licensing information.

## Build and test

Use Linux or WSL with a C++11 compiler, GNU Make, and Python 3.
The test suite uses pytest, pandas, and matplotlib. Figure generation
also uses pandas and matplotlib. Workbook consolidation requires openpyxl.

```bash
make algorithm
make protocol-test
python3 -m pytest tests -q
```

## Reproduce the experiments

The driver builds the protocol and unit benchmarks, runs the parameter sweeps,
and writes the timing data, checkpoints, build provenance, and baseline
estimates. Use a new results directory for each run.

For a short check of the pipeline:

```bash
python3 run_issuer_hiding_measurements.py \
  --results-dir results/smoke --rounds 1 --runs-per-round 1 \
  --warmup 0 --unit-samples 1
```

For the sampling configuration reported in the paper:

```bash
python3 -u run_issuer_hiding_measurements.py \
  --results-dir results/paper --rounds 10 --runs-per-round 50 \
  --warmup 20 --cooldown-seconds 120 --random-seed 20260621 \
  --unit-samples 30 --sentinel-max-relative-deviation 0.25
```

To resume an interrupted run, repeat its command with the same results
directory and add `--skip-build`. Keep the original source, executables, and
MIRACL archive. The driver checks the saved configuration and build
fingerprint before reusing completed batches.

```bash
python3 render_chapter7_issuer_hiding_figures.py \
  --results-dir results/paper --out-dir results/paper/figures
python3 build_issuer_hiding_all_tables.py \
  --results-dir results/paper --output results/paper/all_tables.xlsx
```

The benchmark times blinding, OR-proof generation, and local cryptographic
verification separately. Baseline timings are calculated from published
formulas and locally measured operation costs. Reported byte counts use
uncompressed elements. The sampling seed controls execution order.
Cryptographic randomness comes from the operating system.

## License

See [LICENSE](LICENSE), [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md),
and the [MIRACL license information](Algorithm/MIRACL/licensing.md).
