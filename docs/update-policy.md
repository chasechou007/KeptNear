# Alpha Update Policy

KeptNear uses manual updates for the public alpha. The app does not
contact an update server and does not include an automatic updater in this
phase.

The App does not piggyback update checks on diagnostics, file sync, Usage
Profile templates, or Broker activity. Built-in templates remain offline.

## Rationale

Manual updates keep the alpha local-first while security review and release
processes are still maturing. An automatic updater would add a networked trust
boundary, update-feed signing, provider availability, and extra privacy review.

## Release Artifact Expectations

Each alpha release should provide:

- Apple Silicon (`arm64`) `KeptNear.app` packaged in a DMG with an
  `/Applications` installation link
- SHA-256 checksum file
- release manifest
- signing and notarization status in the manifest
- update channel recorded as `manual`

Signed public distribution requires Developer ID signing and notarization for
the app and DMG. A separate unsigned experimental profile may be published
without Apple credentials only when its dedicated release mode and verifier are
implemented and pass, and when checksum, manifest, Gatekeeper installation
guidance, and adjacent unsigned/unaudited/experimental warnings are present.
The current `local-test` unsigned output remains a local testing artifact until
that profile exists.

## Tester Update Workflow

1. Download the newer alpha DMG and matching `.sha256` file from the release
   location.
2. Verify the checksum:

   ```sh
   shasum -a 256 -c KeptNear-0.1.0-alpha-macos-arm64.dmg.sha256
   ```

3. Quit KeptNear.
4. Open the DMG.
5. Drag `KeptNear.app` to Applications and replace the old app when prompted.
6. Launch KeptNear and open the existing local `.pswvault`.

Vault data remains in the selected `.pswvault` directory. Replacing the app
bundle must not require moving or rewriting the vault.

## Future Automatic Updates

Automatic updates are deferred until after alpha trust boundaries are reviewed.
A future updater decision must document update feed signing, network behavior,
rollback behavior, user controls, and secret-exclusion rules before it is
enabled. It must remain a separately disclosed and configurable network flow,
not an implicit consequence of launching the App.
