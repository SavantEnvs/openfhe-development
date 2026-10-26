#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# Known-answer probe: /mayhem/kat is the library built with normal flags and dynamically linked. Every
# output line must equal the value computed independently (python bigints, truth tables, plaintext slots).
read -r -d '' EXPECTED <<'EOT'
bigint mul 121932631137021795226185032733622923332237463801111263526900
bigint modmul 195963067
bigint div 8 rem 9000000000900000000090
native modexp 333986
native modinv 18633540
gcd 2087354105856
bgv add 6 8 10 12
bgv mult 5 12 21 32
bgv sub 4 4 4 4
binfhe and 0001
binfhe or 0111
binfhe xor 0110
binfhe nand 1110
EOT

passed=0; failed=0
[ -x "$SRC/kat" ] || { echo "missing $SRC/kat (build.sh bug)" >&2; emit_ctrf "openfhe-kat" 0 1 0; exit 1; }
ACTUAL="$("$SRC/kat" 2>/dev/null)"
n=0
while IFS= read -r want; do
  n=$((n + 1))
  got="$(printf '%s\n' "$ACTUAL" | sed -n "${n}p")"
  if [ "$got" = "$want" ]; then passed=$((passed + 1)); else failed=$((failed + 1)); echo "FAIL line $n: want '$want' got '$got'" >&2; fi
done <<< "$EXPECTED"
extra="$(printf '%s\n' "$ACTUAL" | wc -l)"
if [ "$extra" -ne "$n" ]; then failed=$((failed + 1)); echo "FAIL: kat printed $extra lines, expected $n" >&2; fi

# Replay every committed seed through the sanitized reproducers: the library must accept or reject it cleanly.
for t in fuzz_deser_binary fuzz_deser_json fuzz_params fuzz_binfhe fuzz_math; do
  [ -x "$SRC/$t-standalone" ] || { echo "missing $t-standalone (build.sh bug)" >&2; failed=$((failed + 1)); continue; }
  for seed in "$SRC/mayhem/$t/testsuite"/*; do
    if "$SRC/$t-standalone" "$seed" > /dev/null 2>&1; then passed=$((passed + 1)); else failed=$((failed + 1)); echo "FAIL: $t $seed" >&2; fi
  done
done

emit_ctrf "openfhe-kat" "$passed" "$failed" 0
