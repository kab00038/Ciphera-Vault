# Changelog

All notable changes to Ciphera are documented in this file.

## [0.1.3] - 2026-08-17

### Added

- Bulk CSV password import for common Chromium, Firefox, Bitwarden, KeePassXC, 1Password, Proton Pass, and generic export headers.
- Native import preview with importable, duplicate, and skipped-row counts plus bounded row-number diagnostics.
- Destination-group selection for imported login records.
- TOTP, notes, favorite state, URL, username, and title migration when the source export provides them.

### Security

- Parse CSV secrets only in the Rust process; the React preview receives counts and diagnostics rather than passwords or notes.
- Limit imports to 10 MiB, 100,000 rows, and 64 KiB fields.
- Bind each import to an expiring random preview token and SHA-256 source digest, rejecting files changed after preview.
- Deduplicate exact records against both the existing vault and earlier rows in the same import.
- Commit accepted records through one backed-up, logically verified, atomic KDBX save.

### Changed

- Strip release symbols and abort on unrecoverable release panics, reducing the Linux native executable from 24,783,280 to 13,237,136 bytes while retaining normal cryptographic optimization.
- Cache release dependencies per operating system and target architecture.
- Build the Arch package concurrently with the primary release matrix instead of extending the release critical path.
- Restrict routine pull-request and `main` CI to verification; full unsigned cross-platform packages are generated on manual dispatch.
- Publish NSIS as the Windows release installer and updater artifact; manual packaging can still generate MSI when required.

[0.1.3]: https://github.com/kab00038/Ciphera-Vault/compare/v0.1.2...v0.1.3
