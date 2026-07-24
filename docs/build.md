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
cargo clippy --workspace --all-targets -- -D warnings
```

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
script/verify_dependency_licenses.sh
```
