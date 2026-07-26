#!/usr/bin/env bash
#
# Run the libFuzzer targets via cargo-fuzz.
#
# Usage:
#   scripts/fuzz.sh [seconds-per-target] [target ...]
#
# Examples:
#   scripts/fuzz.sh                 # run every target for 60s each
#   scripts/fuzz.sh 300             # run every target for 5 minutes each
#   scripts/fuzz.sh 120 txt_roundtrip
#
# Environment:
#   FUZZ_SECONDS    default seconds per target (overridden by the first arg)
#   FUZZ_TOOLCHAIN  rustup toolchain to use (default: nightly)
#
# Requires a nightly toolchain; cargo-fuzz is installed automatically if missing.
set -euo pipefail

cd "$(dirname "$0")/.."

DURATION="${FUZZ_SECONDS:-60}"
if [[ "${1:-}" =~ ^[0-9]+$ ]]; then
    DURATION="$1"
    shift
fi

NIGHTLY="${FUZZ_TOOLCHAIN:-nightly}"

if ! cargo "+${NIGHTLY}" fuzz --version >/dev/null 2>&1; then
    echo "==> installing cargo-fuzz"
    cargo "+${NIGHTLY}" install cargo-fuzz --locked
fi

targets=("$@")
if [[ ${#targets[@]} -eq 0 ]]; then
    mapfile -t targets < <(cargo "+${NIGHTLY}" fuzz list)
fi

status=0
for target in "${targets[@]}"; do
    # Build as its own step so a compile failure is not reported as a crash the
    # fuzzer found: those mean completely different things, and only the second
    # produces an artifact to reproduce from.
    echo "==> building '${target}'"
    if ! cargo "+${NIGHTLY}" fuzz build "${target}"; then
        echo "!!! target '${target}' failed to BUILD (toolchain or dependency problem, not a fuzz finding)" >&2
        status=1
        continue
    fi

    echo "==> fuzzing '${target}' for ${DURATION}s"
    if ! cargo "+${NIGHTLY}" fuzz run "${target}" -- -max_total_time="${DURATION}"; then
        echo "!!! target '${target}' found a failure; see fuzz/artifacts/${target}/" >&2
        status=1
    fi
done

exit "${status}"
