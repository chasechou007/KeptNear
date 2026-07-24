# Architecture

KeptNear uses a native-client, shared-core architecture.

```text
macOS SwiftUI/AppKit client
  - windows, menus, search UI, clipboard, local unlock UX
  - no custom vault cryptography
        |
        v
Rust core
  - vault format
  - key derivation and key wrapping
  - authenticated record encryption
  - item model and search
  - sync metadata and conflict handling
  - import conversion
        |
        v
Local filesystem vault directory
  - public format metadata
  - encrypted key material
  - encrypted item records
  - encrypted attachments
  - encrypted tombstones
        |
        v
External sync provider
  - iCloud Drive, Dropbox, Syncthing, WebDAV, or similar
  - untrusted transport only
```

## Boundaries

The Rust core is the only layer allowed to interpret encrypted vault records. UI clients may render decrypted data returned from an unlocked session, but they must not parse, decrypt, merge, or rewrite vault records independently.

The local filesystem is trusted only as storage. Record authentication must detect tampering or partial sync corruption before decrypted content is exposed.

Sync providers are untrusted. They may observe filenames, file sizes, timestamps, directory shape, and encrypted bytes. They must never receive plaintext item data, vault keys, or master passwords from the application.

## Initial Modules

- `crates/psw-core`: Rust core API and implementation.
- `apps/macos`: SwiftUI/AppKit macOS client shell.
- `fixtures`: sanitized input and vault fixtures for repeatable tests.
- `docs`: architecture, build, and security notes.
