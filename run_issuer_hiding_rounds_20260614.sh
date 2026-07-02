#!/usr/bin/env bash
set -u

RESULT_DIR="${1:-results/issuer_hiding_rounds_20260614}"
LOG_FILE="${RESULT_DIR}/run.log"
EXIT_FILE="${RESULT_DIR}/exit_code.txt"

mkdir -p "${RESULT_DIR}"
rm -f "${EXIT_FILE}"

python3 run_issuer_hiding_measurements.py \
  --results-dir "${RESULT_DIR}" \
  --rounds 10 \
  --runs-per-round 50 \
  --warmup 20 \
  --cooldown-seconds 120 \
  --skip-build \
  > "${LOG_FILE}" 2>&1

status=$?
printf "%s\n" "${status}" > "${EXIT_FILE}"
exit "${status}"
