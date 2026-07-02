#!/usr/bin/env bash
set -u

cd /mnt/d/论文/Paper/xiuzheng/code/mul_code/mul-main || exit 1

out_dir="results/issuer_hiding_20260610"
mkdir -p "$out_dir"

date --iso-8601=seconds > "$out_dir/full_run_20260610.started"

python3 run_issuer_hiding_measurements.py \
  --runs 200 \
  --warmup 20 \
  --batches 5 \
  --unit-samples 30 \
  > "$out_dir/full_run_20260610.log" \
  2> "$out_dir/full_run_20260610.err.log"

status=$?
echo "$status" > "$out_dir/full_run_20260610.exit"
date --iso-8601=seconds > "$out_dir/full_run_20260610.finished"
exit "$status"
