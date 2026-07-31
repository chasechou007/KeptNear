# Build And Verification

## Rust

Run unit tests for all Rust crates:

```sh
cargo test --workspace
```

Check formatting:

```sh
cargo fmt --all --check
```

Run Clippy when the installed toolchain includes it:

```sh
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

## MCP Adapter

Build the source-level local stdio adapter:

```sh
cargo build --locked --release -p keptnear-mcp
```

The executable is written to `target/release/keptnear-mcp`. The alpha DMG also
bundles it at `KeptNear.app/Contents/Helpers/keptnear-mcp`. See
[Local MCP Host Setup](mcp-setup.md) for Codex, Claude Code, and generic stdio
host examples. The companion Broker binary is bundled but is not yet installed
or activated as a long-running service, so this remains a developer
configuration contract rather than a complete end-user setup.

## Public CLI

Build the source-level `keptnear` machine client and legacy `psw doctor`
diagnostic binary:

```sh
cargo build --locked --release -p psw-cli
```

The executables are written to `target/release/keptnear` and
`target/release/psw`; the alpha DMG bundles `keptnear` under
`KeptNear.app/Contents/Helpers`. The machine client connects only to the
owner-only local Broker socket; it never opens a Vault directly. The companion
Broker binary is bundled but its long-running service lifecycle is not yet
activated, so this is not an end-user installation guide.
See [Local CLI Usage](cli-usage.md) for human shell and Agent integration
examples that keep credential values out of command arguments and output.

## macOS

Build the Rust FFI bridge and SwiftUI shell:

```sh
scripts/build-macos.sh
```

For Swift-only iteration after the FFI dylib already exists, run
`swift build --package-path apps/macos`.

Repository scripts that call SwiftPM use `script/swiftpm_local_env.sh` to keep
SwiftPM cache, config, security, scratch, and Clang module-cache state under
`.build/`. They also disable SwiftPM's nested subprocess sandbox so the
workspace or OS sandbox remains the controlling boundary. Override
`PSW_SWIFTPM_CACHE_PATH`, `PSW_SWIFTPM_CONFIG_PATH`,
`PSW_SWIFTPM_SECURITY_PATH`, `PSW_SWIFTPM_SCRATCH_PATH`, or
`CLANG_MODULE_CACHE_PATH` only when a local environment needs custom paths.

## Package Components

Build the local Apple Silicon App, Broker, MCP adapter, CLI, FFI, closed
protocol manifest, and DMG with:

```sh
script/package_macos_alpha.sh
script/verify_macos_alpha_artifact.sh
```

The default package is an unsigned `local-test` artifact. Bundling
`keptnear-broker`, `keptnear-mcp`, and `keptnear` under
`KeptNear.app/Contents/Helpers` does not install or activate a long-running
Broker service. Use the publication-profile commands and installation guidance
in [macOS alpha packaging](macos-alpha-packaging.md) before describing an
artifact as shareable.

## Combined Check

```sh
scripts/check.sh
```

The combined check also verifies that the candidate public source tree excludes
private development context and common credential artifacts, and that every
resolved Rust dependency declares a reviewed license expression.

Run those gates independently with:

```sh
script/verify_public_source_tree.sh
script/verify_repository_secrets.sh
script/verify_dependency_licenses.sh
script/verify_mcp_setup_docs.sh
script/verify_cli_usage_docs.sh
script/verify_release_profile_contract.sh
script/verify_public_capability_claims.sh
script/verify_public_documentation_set.sh
```
