# Ciphera

Ciphera is an offline-first, user-owned password manager built as a Tauri 2 desktop application with a React interface, a Rust KDBX 4.1 vault core, a local native-messaging bridge, and a Chromium Manifest V3 extension.

Ciphera now stores records in an encrypted local KDBX file. React receives metadata lists and only the explicitly selected secret; the browser bridge queries the same locked Rust vault directly.

> Security status: Ciphera is suitable for careful local evaluation and day-to-day use with independent backups, but it has not received an external security audit. The pinned `keepass` crate describes KDBX 4.1 writing as experimental. Do not treat this build as audited or use it as the only copy of irreplaceable credentials.

## Daily use

```bash
npm install
npm run desktop
```

On first launch, create a vault or open an existing KDBX file with the native file picker. The default Linux path is:

```text
~/.local/share/Ciphera/vault.kdbx
```

Ciphera cannot recover the master password. Every successful mutation writes the KDBX file atomically and rotates five encrypted prior versions beside it as `<vault>.bak` through `<vault>.bak.4`. Keep additional offline backups under your control.

PIN quick unlock is optional. Setup verifies the master password, stores the quick-unlock secret and a salted Argon2id PIN verifier in the operating-system credential vault, and accepts only a 4 or 6 digit PIN. Failed attempts have increasing delays; five failures require one successful master-password unlock before the PIN works again. This protects the normal application flow, not a compromised operating-system account that can directly access its credential vault.

Daily organization and recovery workflows include KDBX-compatible groups, entry-history restore, encrypted attachments up to 20 MiB, and in-app restore of rotating encrypted snapshots.

## Security boundaries

- Vault create, open, edit, delete, password rotation, TOTP, and browser filling work offline.
- KDBX 4.1 uses AES-256 outer encryption, a ChaCha20 protected-value stream, and device-calibrated Argon2id parameters.
- The KDBX format generates independent random master seed, KDF seed, IV, and protected-stream key material on save.
- Saves serialize, decrypt-verify logical vault contents, rotate five backups, flush, and atomically replace the destination.
- Unexpected external file changes are rejected rather than overwritten.
- Locking drops the Rust database and zeroizing `DatabaseKey`, then immediately blocks browser metadata and secret requests.
- Browser matching uses exact normalized origins; lookalike domains do not match.
- No server, analytics, remote font, CDN asset, or runtime logo request is required.
- A single-instance guard prevents two Ciphera processes from racing the local vault or browser bridge.

Read [`docs/PROJECT_HANDOFF.md`](docs/PROJECT_HANDOFF.md) before changing the project. It is the canonical architecture and security handoff.

## Architecture

```text
crates/ciphera-core/       Rust vault model, KDBX persistence, locking, groups, attachments, history, TOTP
crates/ciphera-platform/   OS credential-vault PIN quick unlock and attempt limiting
src/                       React interface; metadata list plus selected entry detail
src-tauri/                 Thin Tauri command layer and locked native browser bridge
extension/                 Chromium Manifest V3 explicit-action autofill extension
```

The KDBX implementation is pinned to `keepass = 0.13.20` with `save_kdbx4` and `totp` features. Version changes require a dependency review and a repeated KeePassXC interoperability run.

## Development and verification

```bash
npm install
npm run lint
npm run build
cargo test --workspace
npm run desktop
```

Linux release artifacts:

```bash
npm run desktop:build
npm run desktop:bundle:linux
npm run desktop:bundle:arch
```

On Arch Linux and Arch-based distributions, install the native pacman package with:

```bash
sudo pacman -S --needed base-devel gtk3 webkit2gtk-4.1
npm run desktop:bundle:arch
sudo pacman -U packaging/arch/ciphera-0.1.0-1-x86_64.pkg.tar.zst
```

The Arch recipe builds against the system WebKitGTK libraries and includes the desktop entry, icons, and browser-extension resources. It declares `gnome-keyring` and KeePassXC as optional Secret Service providers for PIN quick unlock.

Every branch push and pull request runs `.github/workflows/package.yml`. After verification, GitHub Actions builds downloadable workflow artifacts for:

- Linux x86_64: AppImage, Debian package, RPM package, and Arch pacman package
- Windows x86_64: NSIS installer and MSI installer
- macOS: separate DMG images for Apple Silicon and Intel

These CI artifacts are unsigned development builds. Public distribution should use a Windows code-signing certificate and an Apple Developer ID certificate with Apple notarization; otherwise Windows SmartScreen and macOS Gatekeeper may warn or block users.

Version tags publish signed updater artifacts through `.github/workflows/release.yml`. The updater trust root is the public key embedded in `src-tauri/tauri.conf.json`; its matching private key is intentionally ignored at `.tauri/keys/ciphera-updater.key`. Back up that private key securely before distributing the first release—losing it prevents existing installations from accepting future updates. Add it to the GitHub repository as the `TAURI_SIGNING_PRIVATE_KEY` Actions secret:

```bash
gh secret set TAURI_SIGNING_PRIVATE_KEY < .tauri/keys/ciphera-updater.key
```

After synchronizing the version in `package.json`, `src-tauri/Cargo.toml`, and `src-tauri/tauri.conf.json`, push a matching tag:

```bash
git tag -a v0.1.0 -m "Ciphera 0.1.0"
git push origin v0.1.0
```

The workflow creates a draft GitHub Release containing installers, signatures, `latest.json`, and the Arch `.pkg.tar.zst` package. Inspect and publish the draft to make it visible to the in-app updater. Ciphera checks that endpoint after launch, verifies downloads with the embedded updater public key, installs the selected update, and restarts. Linux in-app replacement is supported by the AppImage distribution; pacman installations remain package-manager-owned and should be upgraded by downloading the new `.pkg.tar.zst` release asset and running `sudo pacman -U`.

The real interoperability test is ignored by default because it requires an independent KeePassXC executable:

```bash
KEEPASSXC_CLI=/path/to/keepassxc-cli \
  cargo test -p ciphera-core --test keepassxc_interop -- --ignored
```

That test creates a Ciphera KDBX file, reads its protected value with KeePassXC, adds a record with KeePassXC, reopens and re-saves the modified file in Ciphera, then verifies the re-save again with KeePassXC.

## Browser extension

Install the native host from **Settings → Browser extension** in the desktop application, then load the displayed directory as an unpacked Chromium extension.

Development installer:

```bash
target/release/ciphera --install-browser
```

Default installed extension directory on Linux:

```text
~/.local/share/Ciphera/browser-extension
```

The extension requests metadata first and asks for a selected password only after explicit user action. A locked desktop vault rejects both lookups and secret retrieval.

## Current limitations

- No external cryptographic or application security audit has been completed.
- The upstream Rust KDBX 4.1 writer is explicitly marked experimental.
- `cargo audit` reports no known vulnerable crates, but the Linux Tauri/GTK 3 dependency tree includes RustSec unmaintained warnings and `RUSTSEC-2024-0429` for a `glib` iterator API Ciphera does not call directly.
- Ciphera preserves KDBX fields it does not edit through the upstream database model and verifies logical entries, groups, history, and attachment contents after serialization. Recycle-bin restoration and merge conflict resolution do not yet have UI workflows.
- Concurrent external edits are detected and rejected; automatic KDBX merge is not implemented.
- Browser-store packaging is not complete.
- Linux packaging is exercised locally; Windows and macOS packages require verification on their native build systems.
- Clipboard clearing is best-effort because operating systems and clipboard managers can retain copied data.
