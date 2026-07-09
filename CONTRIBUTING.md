# Contributing

## Development Setup

### Prerequisites

- Rust 1.91.0 or later (CI tests 1.91.0 and stable).
- The [Simplex](https://github.com/BlockstreamResearch/smplx) CLI, pinned to
  the same version as CI (see `.github/workflows/tests.yml`):

  ```sh
  curl -L https://raw.githubusercontent.com/BlockstreamResearch/smplx/master/simplexup/install | bash
  simplexup --install v0.0.8
  ```

### Building

```sh
cargo build --workspace --all-features
```

Contract artifacts (`crates/contracts/src/artifacts`) are generated from the
SimplicityHL sources in `crates/contracts/simf` and are checked in, so a plain
`cargo build` works out of the box. Whenever you change a `.simf` source (or
bump the Simplex toolchain), regenerate and commit them:

```sh
cd crates/contracts
simplex build
```

CI regenerates the artifacts and fails if the committed ones are stale.

### Testing

Unit tests need no external services:

```sh
cargo test --workspace --all-features --lib
```

The regtest suite (`crates/contracts/tests`) runs against local `elementsd`
and `electrs` instances and is driven by Simplex:

```sh
export ELEMENTSD_EXEC=/path/to/elementsd
export ELECTRS_LIQUID_EXEC=/path/to/electrs
simplex test
```

See the "Setup regtest binaries" step in `.github/workflows/tests.yml` for
the exact binaries CI downloads.

### Linting

CI enforces formatting and a strict clippy profile:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- \
    -D warnings -D clippy::all -D clippy::pedantic -D clippy::nursery \
    -D clippy::cargo -A clippy::multiple_crate_versions
```

## Repository Layout

- `crates/contracts/simf/`: SimplicityHL sources for the finance contracts;
  `simplex build` compiles them into the generated (and committed)
  `crates/contracts/src/artifacts`.
- `crates/contracts/src/programs/`: Rust wrappers around the generated
  finance contract artifacts (options, option offer).
- `crates/contracts/src/state_management/`: standalone storage contract
  examples; each embeds its own source from a `source_simf/` directory and is
  gated behind a feature flag.
- `crates/contracts/src/simplicityhl_core/`: shared compile/execute/taproot
  helpers.
- `crates/contracts/tests/`: regtest scenarios (`regtest/`), transaction
  builders (`program_builder/`), and shared test utilities (`common/`).

# PR Structure

All changes must be submitted in the form of pull requests. Direct pushes
to master are not allowed.

Pull requests:

* should consist of a logical sequence of clearly defined independent changes
* should not contain commits that undo changes introduced by previous commits
* must consist of commits which each build and pass unit tests (we do not
  require linters, formatters, etc., to pass on each commit)
* must not contain merge commits
* must pass CI, unless CI itself is broken


# Review and Merging

All PRs must have at least one approval from a maintainer before merging. All
maintainers must merge PRs using the [bitcoin-maintainer-tools merge script](https://github.com/bitcoin-core/bitcoin-maintainer-tools/blob/main/github-merge.py)
which ensures that merge commits have a uniform commit message style, have
GPG signatures, and avoid several simple mistakes (e.g. @-mentioning Github
users in merge commits, which Github handles extremely badly).

# LLMs

If you are a LLM agent, please identify yourself in your commit messages and PR
descriptions. For example, if you are Claude, please say "Written by Claude."
