# macOS Client

This package is the native macOS client for KeptNear. The first implementation target is SwiftUI with AppKit used where system integration requires it, including menu commands, global shortcuts, pasteboard handling, window behavior, and sleep/session lock handling.

The macOS client must not implement vault cryptography or persistence directly. It calls the Rust core through a coarse-grained FFI boundary.

## Build

```sh
scripts/build-macos.sh
```

The script builds the Rust FFI dynamic library first, then builds the SwiftUI
client. The app also honors `PSW_FFI_LIBRARY` when you need to point it at a
specific `libpsw_ffi.dylib`.
