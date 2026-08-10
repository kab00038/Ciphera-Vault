# Ciphera project handoff

This is the canonical context for continuing Ciphera. Read it before changing the project.

Last updated: 2026-08-09.

## Repository

Permanent project path:

```text
/home/kyle/Projects/ciphera-vault
```

Ciphera is a Tauri 2 desktop application with a React 19 frontend, shared Rust vault and platform crates, a Rust native-messaging bridge, and a Chromium Manifest V3 extension. The product is offline-first and user-owned, following KeePassXC's local-file model. A server must remain optional.

## Product invariants

1. Unlocking, reading, editing, generating passwords, TOTP, and autofill must work offline.
2. The user owns the encrypted vault file.
3. A sync server is optional ciphertext transport and must never receive vault keys or plaintext.
4. Browser filling goes through the local desktop process, not a web service.
5. A locked desktop vault rejects all browser vault requests.
6. Do not add remote fonts, remote runtime logos, analytics, or CDN dependencies.
7. Plugins must eventually be capability-limited WebAssembly components; never load unrestricted native plugins into the vault process.
8. Production-format cryptography stays in the shared Rust core. TypeScript is limited to password/passphrase generation and presentation.
9. Do not describe Ciphera as audited, zero-knowledge, or production-ready without an independent review that supports the claim.

## Current stack

- React 19 and TypeScript 6
- Vite 8
- Tauri 2 desktop shell
- Tauri single-instance guard, registered before bridge startup
- Rust workspace with `ciphera-core`, `ciphera-platform`, and `src-tauri`
- Pinned `keepass` 0.13.20 with KDBX 4 writing and TOTP features
- `atomic-write-file` 0.3 for cross-platform atomic replacement
- `keyring` 4.1 for OS credential-vault integration
- Tauri dialog plugin for native KDBX and attachment file selection
- Chromium Manifest V3 extension and native host
- Lucide icons and bundled Simple Icons paths
- Local CSS light/dark themes

No runtime network request is required for fonts, service marks, vault behavior, TOTP, or browser filling.

## Implemented vault core

Workspace:

```text
crates/
  ciphera-core/       Vault model, locking, KDBX persistence, search, history, TOTP
  ciphera-platform/   OS credential-vault quick unlock
src-tauri/            Tauri commands, native browser bridge, browser installer
```

`ciphera-core` now provides:

- Stable `Vault`, entry/group/history/attachment/backup models, `VaultInfo`, and `VaultError` APIs
- KDBX 3/4 open and KDBX 4.1 create/write; writable older files are upgraded to KDBX 4.1 on the next save
- AES-256 outer encryption and ChaCha20 protected-value stream through the KDBX implementation
- Explicit Argon2id configuration with device calibration, 64 MiB desktop memory, 32 MiB mobile memory, and bounded iterations/parallelism
- Format-compatible random master seed, KDF seed, IV, and protected-stream key generation on every save
- Entry UUIDs, tracked/restorable history, KDBX deletion tombstones, groups, and encrypted file attachments
- Metadata-only listing and explicit single-entry secret retrieval
- Offline TOTP generation in Rust; TOTP secrets are not mirrored into React
- Normalized exact-origin browser matching
- Master-password rotation with backup and atomic re-encryption
- Distinct wrong-password, corrupted-file, locked, and external-modification errors
- Five rotating encrypted backups with in-app inspection and one-action restore
- Logical post-serialization verification for groups, entries, history, and attachment contents

Persistence behavior:

1. Detect an unexpected on-disk change by SHA-256 fingerprint and refuse to overwrite it.
2. Serialize the updated KDBX database to memory.
3. Reopen the serialized ciphertext with the active database key and verify logical groups, entries, history, and attachment contents.
4. Rotate five prior encrypted versions as `<vault>.bak` through `<vault>.bak.4`.
5. Write, flush, fsync, and atomically replace the destination.
6. Use mode `0700` for newly created private directories and mode `0600` for vault/backup files on Unix without changing existing parent-directory permissions.

The KDBX password component is held by `keepass::DatabaseKey`, which implements zeroization on drop. Locking drops the entire decrypted `Database` and key state.

## Desktop and React integration

The demo records and transitional `sync_browser_items` flow are removed.

React now owns:

- Search/filter UI state
- A metadata-only `EntrySummary` list
- At most the explicitly selected `EntryDetail`
- Generated password/passphrase session history
- Current TOTP codes, never TOTP secrets

Rust owns the decrypted database and every mutation. Tauri commands cover status, create/open, native file selection, quick unlock, lock, entries, groups, history restore, attachments, rotating-backup restore, password rotation, and TOTP codes.

User-facing local behavior:

- First-run local vault creation and existing-vault open through native file dialogs
- Create/open mode switching without restarting the desktop app
- Add, edit, favorite, delete, search, category filtering, and group filtering
- KDBX-compatible group create, rename, item assignment, and empty-group deletion
- Entry-history inspection and restoration while retaining the current version in history
- Attachment add, encrypted storage, safe export, and removal with a 20 MiB per-file limit
- Five rotating encrypted recovery snapshots with Settings restore UX
- Automatic lock after ten minutes of inactivity
- Best-effort clipboard clearing after 60 seconds
- Optional OS credential-vault quick unlock after full password verification
- Quick-unlock disable and master-password rotation in Settings
- Accurate local password health review for weak, reused, and old passwords
- Single-instance desktop startup so a second process cannot race the vault or native bridge

## Browser integration

Native host name:

```text
com.ciphera.browser
```

Stable Chromium extension ID:

```text
nbnpilplfaaigikkigfoeolljlpgknbg
```

The extension:

- Uses only `activeTab`, `nativeMessaging`, and `scripting`
- Looks up metadata for the active URL
- Requests the selected secret only after explicit user action
- Injects `content.js` only while filling
- Uses DOM creation and `textContent`, not vault-controlled `innerHTML`
- Uses local assets and OS light/dark preference

The native path:

- Uses Chromium's length-prefixed JSON protocol with a one-megabyte limit
- Forwards to the desktop process over loopback only
- Authenticates each desktop launch with a random 256-bit token in a mode-`0600` descriptor
- Applies three-second read/write timeouts and bounded loopback messages
- Queries the same `Arc<Mutex<Vault>>` used by Tauri commands
- Returns no vault data while locked
- Uses exact normalized origins, so `example.com.attacker.test` never matches `example.com`
- Registers manifests for Chromium, Chrome, Brave, Edge, and their supported OS locations

## Interoperability evidence

`crates/ciphera-core/tests/keepassxc_interop.rs` is an independent executable-level roundtrip test. With KeePassXC 2.7.12 it:

1. Creates a Ciphera KDBX 4.1 database and entry.
2. Reads the protected password using `keepassxc-cli`.
3. Adds a new entry using `keepassxc-cli`.
4. Reopens the KeePassXC-modified file in Ciphera and validates username, password, and URL.
5. Re-saves that imported entry in Ciphera and reopens its protected password with KeePassXC.

Run it with:

```bash
KEEPASSXC_CLI=/path/to/keepassxc-cli \
  cargo test -p ciphera-core --test keepassxc_interop -- --ignored
```

The normal Rust suite also covers restart persistence, lock rejection, wrong-password versus corruption errors, encrypted-at-rest output, rotating backup restore, entry-history restore, group lifecycle, attachment roundtrips, malformed KDBX rejection, tombstones, external modification rejection, TOTP generation, browser metadata separation, and lookalike-domain rejection.

## Build and verification

From the repository root:

```bash
npm install
npm run lint
npm run build
cargo test --workspace
cargo audit
npm run desktop
npm run desktop:build
npm run desktop:bundle:linux
```

Install browser integration from Settings, or after a release build:

```bash
target/release/ciphera --install-browser
```

Then load the unpacked directory:

```text
~/.local/share/Ciphera/browser-extension
```

## Architecture map

```text
Cargo.toml                              Rust workspace and shared dependency policy
crates/ciphera-core/src/model.rs        Stable serialized domain and response types
crates/ciphera-core/src/lib.rs          Vault lifecycle, KDBX operations, atomic saves
crates/ciphera-core/tests/              Real KeePassXC compatibility test
crates/ciphera-platform/src/lib.rs      OS credential-vault quick unlock
src/App.tsx                             Metadata-oriented product UI and Tauri calls
src/App.css                             Local light/dark design system
src/security.ts                         Password generator and local strength presentation
extension/manifest.json                 Chromium extension manifest
extension/popup.*                       Browser login selection UI
extension/content.js                    Explicit-action credential filling
src-tauri/src/main.rs                   Desktop/native-host argument dispatch
src-tauri/src/lib.rs                    Thin commands, bridge, protocol, installer
src-tauri/tauri.conf.json               Window, resources, bundle, CSP
```

## Important limitations and next work

Ciphera now has the local recovery and organization workflows needed for careful day-to-day use with independent backups, but it must not be represented as independently production-ready:

- No external cryptographic or application security audit has been completed.
- The selected upstream `keepass` crate calls KDBX 4.1 writing experimental. It is pinned to 0.13.20; upgrades require source review and a repeated real KeePassXC roundtrip.
- `cargo audit` reports no vulnerable packages, but currently emits 17 allowed warnings from transitive dependencies: unmaintained GTK 3/UNIC packages and `RUSTSEC-2024-0429` for a `glib` iterator API Ciphera does not call directly. These are inherited from the Linux Tauri/GTK stack and remain release risks.
- KDBX deletion tombstones are written, but recycle-bin browsing and tombstone restoration are not yet exposed.
- Key files and hardware challenge-response credentials are not implemented.
- Concurrent external modifications are safely rejected, but automatic merge is not implemented.
- OS quick unlock depends on platform credential-vault availability and is not guaranteed to require biometric authentication.
- Clipboard clearing cannot defeat clipboard managers or operating-system history.
- The extension is not packaged for browser stores.
- Linux packages are the currently exercised release target. Windows and macOS need native packaging and secure-storage verification.
- Memory-locking decrypted database pages against swap/core dumps is not implemented by the upstream database model.

The next engineering phase may begin encrypted sync design, followed by capability-limited WASM plugins and shared-core mobile clients. Preserve the offline-first invariant: sync transports ciphertext only, and no server may become necessary to unlock or edit a vault. Before recommending broad production use, complete recycle-bin recovery UX, Windows/macOS validation, fuzzing beyond the deterministic malformed-input regression set, and an independent security review.

## Primary dependency references

- `keepass` crate documentation: <https://docs.rs/keepass/0.13.20/keepass/>
- `keepass-rs` source and security policy: <https://github.com/sseemayer/keepass-rs>
- KeePass KDBX 4 specification: <https://keepass.info/help/kb/kdbx_4.html>
- KeePassXC: <https://keepassxc.org/>
