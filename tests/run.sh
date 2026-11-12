#!/usr/bin/env bash
# Run every test file. Exit non-zero if any file fails.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
shopt -s nullglob
files=("$here"/test_*.sh)
if [ "${#files[@]}" -eq 0 ]; then
  echo "could not do it: no test files"
  exit 1
fi
fail=0
for t in "${files[@]}"; do
  echo "== $(basename "$t") =="
  bash "$t" || fail=1
done
if [ "$fail" -ne 0 ]; then
  echo "FAIL: one or more test files failed"
  exit 1
fi
echo "PASS: all test files"
