# Local File Sync

KeptNear does not talk to iCloud, Dropbox, Syncthing, WebDAV, or any
other provider API. A vault is a local encrypted directory. External tools only
copy encrypted files.

## macOS Sync Behavior

While a vault is unlocked, the macOS client watches required vault structure
(`vault.json`, `keys.enc`, `items/`, `attachments/`, and `tombstones/`) plus
encrypted records in the local `items/` and `tombstones/` directories with
lightweight polling. When required structure or encrypted record files change,
the app asks the Rust core to refresh from disk, verifies records, and reloads
item summaries or surfaces the refresh failure.

The sync status panel reports:

- loaded encrypted item records
- applied tombstones
- detected item conflicts
- rejected records that failed verification

Users can also trigger `Refresh Sync` manually from the toolbar.

The app can also handle `.pswvault` paths supplied by macOS file-open events,
using the same open-vault workflow as the in-app Open action. Unsupported paths
are rejected before the Rust core is called. Packaged document type registration
and Finder double-click association are separate distribution-layer work.

To place an existing vault in a sync folder, use `Copy to Sync` from the macOS
toolbar. The app copies the selected vault's portable encrypted structure to a
new destination, clears the previous decrypted state, selects the copied vault,
and leaves it locked until normal unlock. The source vault is not deleted or
moved. This workflow is local file copying only; provider upload/download status
remains outside the app.

After Copy to Sync succeeds, the macOS app shows a result confirmation with
aggregate copied counts for item records, attachments, and tombstones. The
confirmation shows only the copied vault destination name and can reveal that
destination in Finder. It does not show full local paths, item contents,
secrets, provider account state, or provider upload/download status.

The macOS sidebar shows a local-only placement hint for the selected vault. If
the vault path appears to be inside a common sync-provider folder such as iCloud
Drive, Dropbox, OneDrive, Google Drive, or Syncthing, the hint names that
provider as a likely synced location. Otherwise it shows the vault as local or
unknown. This hint is based only on local path components; it does not contact
provider APIs and does not prove upload or download completion.

The sidebar also shows local sync readiness for the selected vault. Readiness
checks only local filesystem state:

- required portable vault files: `vault.json` and `keys.enc`
- required portable vault directories: `items/`, `attachments/`, and
  `tombstones/`
- likely sync-provider placement from the local path
- whether `local_unlock.enc` exists for local Keychain convenience unlock

Readiness does not decrypt item records, repair files, contact provider APIs, or
prove that another device has received the latest copy. If `local_unlock.enc` is
present, it is shown as local convenience unlock context for this Mac, not as
portable recovery material.

When readiness is incomplete, the macOS sidebar offers local recovery actions
from the same readiness panel: reveal the selected vault directory in Finder and
copy the non-secret sync diagnostics report. These actions do not repair missing
files, call provider APIs, or add full local paths to copied diagnostics.

Successful sync refreshes preserve the current list context. If a user is
searching, has archived items included, or has favorite-only, conflict-only,
tag, or item-type filters enabled, manual refresh, automatic file-change
refresh, conflict-resolution refresh, and recovery refreshes keep the visible
list filtered the same way while updating sync counts and refresh time. Tag and
item-type selections remain active when refreshed non-secret summaries still
contain matching values.

Sync refreshes also respect active editor drafts. Manual `Refresh Sync` asks for
discard confirmation before it can replace an unsaved item editor draft, and the
store rejects unconfirmed manual refresh calls while an editor is dirty.
Rejected-record quarantine uses the same confirmed discard path before it
refreshes vault data.
Automatic file-change refresh is paused while the active editor has unsaved
changes, shows a persistent paused sync status in the sync status panel, and
runs once the draft is saved or discarded.

If a refresh fails, the app clears the previous successful sync report and last
refresh time rather than presenting stale counts as current state. The item list
already loaded in memory remains visible, and the status message reports the
refresh failure.

When the latest refresh reports conflicts or rejected records, the sync status
panel shows issue guidance and direct recovery actions:

- refresh sync again
- reveal the vault directory in Finder
- quarantine rejected sync records when rejected records are present
- copy the non-secret diagnostics report for support or alpha feedback

The sidebar list can also be filtered to show only sync-conflicted items. This
filter can be enabled directly from the sync issue panel when conflicts are
reported, or from the sidebar filter controls. It composes with search text,
favorite-only filtering, archived-item inclusion, selected item type, and
selected tag, and it uses already loaded item summary status only. It does not
decrypt additional fields, contact provider APIs, or expose full local paths.

When rejected `.enc` records have usable local file names, the sync issue panel
also lists those file names with an item or tombstone category label. This is a
local troubleshooting aid only. It does not include parent directories, full
paths, plaintext, decrypted item titles, or secrets, and it does not prove
provider upload or deletion state.

The diagnostics report includes aggregate sync counts, rejected item-record and
tombstone-record counts, local sync readiness status, required-structure status,
likely provider class, local unlock envelope presence, whether sync refresh is
currently deferred by unsaved edits, and preferences, but omits item content,
secrets, rejected record file names, rejected record paths, local unlock
material, and full local vault paths.

## Vault Doctor CLI

For scripted checks or support workflows, use the Rust CLI to inspect a local
vault directory without unlocking it:

```sh
cargo run -p psw-cli -- doctor path/to/Vault.pswvault
cargo run -p psw-cli -- doctor --json path/to/Vault.pswvault
```

`psw doctor` checks only local filesystem readiness. It reports required
portable structure, supported vault and record format metadata, encrypted item,
attachment, and tombstone file counts, and whether `local_unlock.enc` is
present. Exit code `0` means the vault structure and format are locally usable
by this client. Missing required paths, wrong file types, malformed metadata, or
unsupported future formats exit non-zero.

The command does not ask for the master password, decrypt item records, print
item titles or secret fields, repair files, or contact provider APIs. The JSON
mode contains the same non-secret information as text mode for automation and
support attachments.

The repository includes a focused readiness gate for this support workflow:

```sh
script/verify_vault_doctor_readiness.sh
```

The verifier generates local vault cases, runs both text and JSON doctor output,
checks incomplete and unsupported-format failures, and asserts that known item
plaintext does not appear in doctor output. It is also included in
`script/verify_local_alpha_readiness.sh`. Passing it proves only local doctor
behavior, not provider upload/download state.

Malformed, unreadable, or authentication-failing `.enc` records are treated as
rejected sync records. The Rust core excludes them from item lists, search,
detail loading, conflict detection, and mutation decisions, increments the
rejected record count, and continues using the valid records in the same vault.
The refresh report keeps an aggregate rejected-record count and category counts
for rejected item records and rejected tombstone records. It also keeps
available rejected `.enc` file names for local UI troubleshooting while keeping
copied diagnostics aggregate-only. This handles transient provider states such
as partially written files without trusting unverifiable plaintext or exposing
full paths.

Missing required vault structure is still a hard error. Before refresh treats
local record files as sync input, the Rust core revalidates `vault.json`,
`keys.enc`, `items/`, `attachments/`, and `tombstones/`. If any required path is
missing or has the wrong file/directory type, the vault is considered
incomplete rather than a normal rejected-record refresh. The macOS watcher
includes these required paths in its local signature so empty-vault structure
changes are detected without requiring an app restart.

When rejected records persist, the macOS sync issue panel can ask the Rust core
to quarantine them. This moves rejected encrypted `.enc` files out of the active
`items/` and `tombstones/` directories into a vault-local `quarantine/` batch
directory, then refreshes sync counts. The action reports only aggregate moved
counts, and the sync status panel keeps that aggregate result visible until the
next ordinary sync refresh or vault state reset. It does not decrypt, repair,
delete, or expose rejected record plaintext, full paths, or file names. Because
external sync providers remain outside the app's trust boundary, a provider may
later re-download the same rejected files; in that case they will be rejected
again until the provider-side copy is also handled outside the app.

When a refreshed item is marked as conflicted, select it in the item list. The
editor command area can load conflict candidate summaries for that conflict and
let you choose which version to keep, or merge selected safe fields from another
candidate into a chosen base revision. Candidate summaries include non-secret
context such as title, item type, status, favorite state, tags, revision, and a
short preview. They also include structured comparison fields so candidates can
be scanned field by field. High-risk values such as passwords, TOTP secrets,
credit card numbers, verification codes, secure-note bodies, and software
license keys are shown as hidden/redacted fields rather than plaintext values.
Changed-field labels still identify which fields differ from at least one other
candidate, such as `username`, `password`, `TOTP`, `tags`, `body`, `card number`,
or `license key`.

While an item is conflicted, ordinary save, favorite, archive, delete, and tag
replacement actions are unavailable; resolve the conflict first, then edit the
kept version if more changes are needed.

Choosing a candidate writes a new active revision based on that specific
candidate, then refreshes item summaries and sync counts. The existing quick
`Resolve Conflict` action remains available for simple alpha workflows, but the
candidate-based flow is the safer path when competing edits need inspection.

Safe field merge writes a new active revision using one selected candidate as
the base and copying only explicitly allowed non-secret fields from selected
candidate revisions. The current allowlist is title, favorite, tags, login
username, login URLs, credit-card cardholder name, credit-card expiration,
software-license product, and software-license licensed-to. Passwords, TOTP
secrets, secure-note bodies, credit-card numbers, verification codes, license
keys, notes fields, and unsupported fields stay inherited from the base
candidate.

## Stale Edit Protection

Item list rows and item detail payloads include revision identifiers from the
Rust core. When the macOS client saves an existing item, toggles favorite,
archives, or deletes, it sends the revision it last displayed as the expected
revision for that mutation.

If another device or sync process writes a newer revision before the mutation
reaches the core, the core rejects the stale operation before writing a new item
record or tombstone. For editor saves, the macOS client refreshes the selected
item from disk, reloads the current synced revision as the clean baseline, and
keeps the rejected local edit visible as an unsaved draft. Review the current
synced state, then save the preserved draft again only if the local edit is
still intended.

This is optimistic concurrency protection, not automatic merge. It prevents a
stale editor form from silently hiding a newer synced edit, and it keeps the
local input available for deliberate follow-up. After a stale save, the macOS
client shows a review summary comparing the current synced value with the
preserved local draft for non-secret fields. Secret-bearing fields are labeled
but remain hidden. The user must still explicitly save again to apply the
preserved draft over the current synced item.

## Security Boundary

The SwiftUI client does not parse or decrypt synced files. The Rust core remains
responsible for record authentication, tombstone handling, and conflict
detection. Rejected records are counted but their plaintext and local file paths
are never exposed in the current UI contract.

## Current Limits

- The app must be running and the vault must be unlocked to refresh active item
  views.
- Rejected record reporting can show local `.enc` file names when available,
  but the app does not repair records or automatically delete rejected sync
  records.
- Stale edit protection preserves rejected editor saves as local drafts and can
  show non-secret differences for review, but it does not merge rejected local
  edits automatically.
- Conflict resolution can keep one selected version or merge explicitly safe
  non-secret fields by candidate revision. It does not yet merge passwords,
  TOTP secrets, secure-note bodies, credit-card numbers, verification codes,
  license keys, notes fields, arbitrary edited values, or reveal secrets inside
  the conflict picker.
- Provider-specific status such as "uploading" or "download complete" is outside
  the app's trust boundary and not shown. The sidebar placement hint can only
  identify common local sync-folder markers.
