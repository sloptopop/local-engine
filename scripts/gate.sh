#!/bin/sh
# Quality gate shared by every sloptopop Rust repo; keep identical across repos.
# Fails unless: formatted, compiles with zero warnings (Clippy included via
# .cargo/config.toml), every test passes, coverage is 100% of lines, regions
# and functions, and every mutant is caught (tests actually check behaviour).
# Run from anywhere: scripts/gate.sh [--fast]
#   --fast  skip docs, cargo-deny and mutation testing (Claude Code Stop hook)
set -eu
cd "$(dirname "$0")/.."

for tool in cargo-llvm-cov cargo-deny cargo-mutants; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "gate: $tool not installed (brew install $tool)" >&2
        exit 1
    fi
done

echo "gate: fmt" >&2
cargo fmt --check

echo "gate: build (zero warnings)" >&2
cargo build --all-targets --all-features --locked

# Runs unit and integration tests with instrumentation; any failing test or
# any uncovered line/region/function fails the gate. Doctest coverage needs
# nightly, so doctests only have to pass (below), not count toward coverage.
echo "gate: tests + 100% coverage" >&2
cargo llvm-cov --all-features --locked \
    --fail-under-lines 100 --fail-under-regions 100 --fail-under-functions 100 \
    --fail-uncovered-lines 0 \
    --fail-uncovered-regions 0 \
    --fail-uncovered-functions 0 \
    --show-missing-lines

if [ -f src/lib.rs ]; then
    echo "gate: doctests" >&2
    cargo test --doc --all-features --locked
fi

if [ "${1:-}" != "--fast" ]; then
    echo "gate: docs" >&2
    RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features --locked

    echo "gate: cargo-deny" >&2
    cargo deny --all-features check

    # Mutants are compiled with lints capped: a mutant like "replace body
    # with Default" leaves unused parameters, which warnings=deny rejects.
    # Exit 3 means some mutants made the tests hang (e.g. an endless read
    # loop) and none were missed: a hang is the tests noticing the change.
    echo "gate: mutation testing" >&2
    status=0
    cargo mutants --cap-lints=true || status=$?
    if [ "$status" -ne 0 ] && [ "$status" -ne 3 ]; then
        exit "$status"
    fi
fi

# Repo-specific checks (e.g. the web repo boots its Hermit unikernel image).
# They are additions only: this script has already run every shared check.
if [ -x scripts/gate-extra.sh ]; then
    echo "gate: repo-specific checks (scripts/gate-extra.sh)" >&2
    scripts/gate-extra.sh "${1:-}"
fi

echo "gate: passed" >&2
