#!/usr/bin/env bash
#
# mayhem/build.sh — build OpenFHE (sanitized, for fuzzing), the five fuzz harnesses, and the KAT probe
# (normal flags, for mayhem/test.sh). Offline and re-runnable: cereal comes from the in-image cache.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${OPENFHE_CEREAL_CACHE:=/opt/openfhe-deps/cereal}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# 0) cereal (git submodule upstream; absent from a bare checkout). Copy the pinned in-image copy in.
if [ ! -f third-party/cereal/include/cereal/cereal.hpp ]; then
    [ -f "$OPENFHE_CEREAL_CACHE/include/cereal/cereal.hpp" ] || { echo "cereal cache missing: $OPENFHE_CEREAL_CACHE" >&2; exit 1; }
    mkdir -p third-party/cereal
    cp -a "$OPENFHE_CEREAL_CACHE"/. third-party/cereal/
fi

CMAKE_COMMON=(-G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_STATIC=ON -DBUILD_SHARED=OFF -DBUILD_UNITTESTS=OFF
    -DBUILD_EXAMPLES=OFF -DBUILD_BENCHMARKS=OFF -DGIT_SUBMOD_AUTO=OFF -DWITH_OPENMP=OFF
    -DWITH_MALLOC_TUNING=OFF -DWITH_NUMA_INTERLEAVE=OFF -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX")

# 1) The library with sanitizers + DWARF 3 + libFuzzer coverage instrumentation (fuzzer-no-link).
# cereal materializes arbitrary enum values from untrusted bytes (cereal/types/common.hpp), which UBSan's
# `enum` check reports on every deserialization attempt, so that one check is off; all others stay halting.
FUZZ_FLAGS="$SANITIZER_FLAGS -fno-sanitize=enum $DEBUG_FLAGS -fsanitize=fuzzer-no-link"
# A re-run can resolve `clang` to a different path than the image build did (ccache pre-fill); CMake then drops
# its cache mid-configure and loses the -D options, so always configure from a clean cache.
rm -f build-mayhem/CMakeCache.txt build-tests/CMakeCache.txt
cmake -S . -B build-mayhem "${CMAKE_COMMON[@]}" \
    -DCMAKE_C_FLAGS="$FUZZ_FLAGS" -DCMAKE_CXX_FLAGS="$FUZZ_FLAGS" \
    -DCMAKE_C_FLAGS_RELEASE="-O1" -DCMAKE_CXX_FLAGS_RELEASE="-O1" > /dev/null
cmake --build build-mayhem -j"$MAYHEM_JOBS"

# 2) Harnesses: compile each object once, link it as a libFuzzer binary and as a -standalone reproducer.
INC=(-DMATHBACKEND=4 -DOPENFHE_VERSION=1.6.1 -Ithird-party/include -Isrc/core/lib -Isrc/binfhe/lib
    -Isrc/core/include -Isrc/pke/include -Isrc/binfhe/include -Ibuild-mayhem/src/core
    -Ithird-party/cereal/include -Imayhem)
LIBS=(build-mayhem/lib/libOPENFHEpke_static.a build-mayhem/lib/libOPENFHEbinfhe_static.a
    build-mayhem/lib/libOPENFHEcore_static.a -lpthread)
OBJ=/tmp/mayhem-objs
mkdir -p "$OBJ"

compile_one() {  # compile_one <name> <source> [extra flags]
    local n=$1 s=$2; shift 2
    # shellcheck disable=SC2086
    $CXX -std=gnu++17 -Wno-unknown-pragmas -O1 $SANITIZER_FLAGS -fno-sanitize=enum $DEBUG_FLAGS \
        -fsanitize=fuzzer-no-link $INC_STR "$@" -c "$s" -o "$OBJ/$n.o"
}
export -f compile_one
export OBJ CXX SANITIZER_FLAGS DEBUG_FLAGS INC_STR="${INC[*]}"

printf '%s\n' \
    "fuzz_deser_binary mayhem/fuzz_deser.cpp -DMAYHEM_SER_BINARY" \
    "fuzz_deser_json mayhem/fuzz_deser.cpp -DMAYHEM_SER_JSON" \
    "fuzz_params mayhem/fuzz_params.cpp" \
    "fuzz_binfhe mayhem/fuzz_binfhe.cpp" \
    "fuzz_math mayhem/fuzz_math.cpp" |
    xargs -P 3 -L 1 bash -c 'compile_one "$@"' _

# shellcheck disable=SC2086
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o "$OBJ/lsan_off.o"
# shellcheck disable=SC2086
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$OBJ/standalone_main.o"
for t in fuzz_deser_binary fuzz_deser_json fuzz_params fuzz_binfhe fuzz_math; do
    # shellcheck disable=SC2086
    $CXX $SANITIZER_FLAGS -fno-sanitize=enum $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$OBJ/$t.o" "$OBJ/lsan_off.o" "${LIBS[@]}" -o "$SRC/$t"
    # shellcheck disable=SC2086
    $CXX $SANITIZER_FLAGS -fno-sanitize=enum $DEBUG_FLAGS "$OBJ/$t.o" "$OBJ/standalone_main.o" "$OBJ/lsan_off.o" "${LIBS[@]}" -o "$SRC/$t-standalone"
done

# 3) The KAT probe for mayhem/test.sh: the same library built with the project's NORMAL flags
#    (no sanitizers, no fuzzer instrumentation), dynamically linked against libc so the sabotage shim reaches it.
cmake -S . -B build-tests "${CMAKE_COMMON[@]}" \
    -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" -DCMAKE_CXX_FLAGS="$COVERAGE_FLAGS" > /dev/null
cmake --build build-tests -j"$MAYHEM_JOBS"
TINC=("${INC[@]/build-mayhem/build-tests}")
# shellcheck disable=SC2086
$CXX -std=gnu++17 -Wno-unknown-pragmas -O2 $COVERAGE_FLAGS "${TINC[@]}" mayhem/kat.cpp \
    build-tests/lib/libOPENFHEpke_static.a build-tests/lib/libOPENFHEbinfhe_static.a \
    build-tests/lib/libOPENFHEcore_static.a -lpthread -o "$SRC/kat"
file "$SRC/kat" | grep -q 'dynamically linked'
