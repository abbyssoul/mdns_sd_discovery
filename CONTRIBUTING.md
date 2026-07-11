# Contributing

Thanks for helping improve `mdns-sd-discovery`. This crate is an async Rust
wrapper over the operating system's native DNS-SD/mDNS service discovery
stack: the DNS-SD framework on macOS, the Win32 DNS-SD API on Windows, and
Avahi over D-Bus on Linux/FreeBSD.

## Development Setup

Install the Rust toolchain from `rust-toolchain.toml`:

```sh
rustup show
```

There are no native build dependencies on any platform — the Linux backend
talks to Avahi over D-Bus (via `zbus`), so not even the Avahi client headers
are needed. To *run* discovery on Linux, the Avahi daemon must be active on
the system.

## Local Commands

Build the project:

```sh
cargo build --locked
```

Run tests:

```sh
cargo test --locked
```

Check formatting:

```sh
cargo fmt -- --check
```

Run lint checks:

```sh
cargo clippy --locked --all-targets -- -D warnings
```

Browse services on the local network with the example:

```sh
cargo run --example discover-service
```

Note that each platform backend is `cfg`-gated, so a local build only checks
the backend for your OS; CI lints and tests all three.

## Fuzzing

The wire-format helpers (TXT record parsing and DNS name trimming) are
exercised by [`cargo-fuzz`] (libFuzzer) targets in `fuzz/`. They require a
nightly toolchain; the helper script installs `cargo-fuzz` if needed:

```sh
scripts/fuzz.sh            # run every target for 60s each
scripts/fuzz.sh 300        # 5 minutes per target
scripts/fuzz.sh 120 txt_roundtrip   # one target
```

Besides panic-safety, each target asserts semantic properties — a plain
"doesn't crash" oracle cannot see wrong-output bugs in record framing:

- `parse_txt_entry`: the `key[=value]` splitter checked against a
  straight-line spec; binary values must survive untouched.
- `parse_txt_buffer`: arbitrary bytes through the length-prefixed buffer
  parser; output must respect the framing limits.
- `txt_roundtrip`: entries encoded the way a responder would send them must
  decode back exactly — the guard against off-by-one framing bugs.
- `trim_dot`: trimming a fully-qualified name only ever removes trailing
  dots and is idempotent.

The targets reach the crate's internals through the `fuzzing` module in
`src/lib.rs`, which only exists when building with `--cfg fuzzing` (set
automatically by `cargo fuzz`).

CI runs a short soak on every push/PR and a longer one on a weekly schedule
(`.github/workflows/fuzz.yml`); any crash inputs are uploaded as artifacts.

[`cargo-fuzz`]: https://github.com/rust-fuzz/cargo-fuzz

## Project Layout

- `src/browse.rs`: the shared model — builders, events, errors, and the
  wire-format helpers.
- `src/linux/`, `src/macos/`, `src/windows/`: the `cfg`-gated platform
  backends, each exposing `browse_start` and `resolve_once`.
- `examples/`: runnable discovery examples.
- `fuzz/`: `cargo-fuzz` targets; `scripts/fuzz.sh`: the fuzz runner.
- `.github/workflows/`: CI, fuzzing, audit, analysis, and publish workflows.

## Contribution Guidelines

Keep changes focused and easy to review. Changes to the public API need doc
comments (`#![warn(missing_docs)]` is enforced) and should keep the three
backends behaviorally aligned. Update the README in the same pull request if
user-facing behavior changes.

Before opening a pull request, run:

```sh
cargo fmt -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
```

When reporting bugs, include:

- operating system and version
- crate version
- the discovery backend involved (Avahi / DNS-SD framework / Win32 API)
- a minimal code snippet reproducing the problem
- for Linux: whether `avahi-daemon` is running
- the full error output
