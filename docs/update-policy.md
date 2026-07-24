# Alpha Update Policy

KeptNear uses manual updates for the public alpha. The app does not
contact an update server and does not include an automatic updater in this
phase.

## Rationale

Manual updates keep the alpha local-first while security review and release
processes are still maturing. An automatic updater would add a networked trust
boundary, update-feed signing, provider availability, and extra privacy review.

## Release Artifact Expectations

Each alpha release should provide:

- `KeptNear.app` packaged as a zip archive
- SHA-256 checksum file
- release manifest
- signing and notarization status in the manifest
- update channel recorded as `manual`

For public alpha distribution, the archive should be built with Developer ID
signing and notarization credentials. Unsigned archives remain local testing
artifacts.

## Tester Update Workflow

1. Download the newer alpha archive and matching `.sha256` file from the release
   location.
2. Verify the checksum:

   ```sh
   shasum -a 256 -c KeptNear-0.1.0-alpha-macos-alpha.zip.sha256
   ```

3. Quit KeptNear.
4. Unzip the archive.
5. Replace the old `KeptNear.app` with the new one.
6. Launch KeptNear and open the existing local `.pswvault`.

Vault data remains in the selected `.pswvault` directory. Replacing the app
bundle must not require moving or rewriting the vault.

## Future Automatic Updates

Automatic updates are deferred until after alpha trust boundaries are reviewed.
A future updater decision must document update feed signing, network behavior,
rollback behavior, user controls, and secret-exclusion rules before it is
enabled.
