.PHONY: check rust-test rust-fmt rust-clippy macos-build

check:
	./scripts/check.sh

rust-test:
	cargo test --workspace

rust-fmt:
	cargo fmt --all --check

rust-clippy:
	cargo clippy --workspace --all-targets -- -D warnings

macos-build:
	./scripts/build-macos.sh
