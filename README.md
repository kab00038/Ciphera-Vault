# Ciphera

Ciphera is an offline-first desktop password manager. Vaults are encrypted local KDBX files that remain under your control; creating, unlocking, editing, TOTP generation, and browser filling do not require a server.

> Ciphera is currently distributed as a prerelease. The application has automated security scanning, but it has not received an independent cryptographic or application security audit. Keep independent backups and do not use Ciphera as the only copy of irreplaceable credentials.

## Download

Download Ciphera only from the repository's official **[GitHub Releases page](https://github.com/kab00038/Ciphera-Vault/releases)**. Open the newest release and expand **Assets**, then choose the installer for your platform:

| Platform | Download | Notes |
| --- | --- | --- |
| Windows x86-64 | `Ciphera_*_x64-setup.exe` | Recommended interactive installer |
| Windows x86-64 | `Ciphera_*_x64_en-US.msi` | MSI package for managed or manual installation |
| macOS Apple Silicon | `Ciphera_*_aarch64.dmg` | M1, M2, M3, M4, and later Apple Silicon Macs |
| macOS Intel | `Ciphera_*_x64.dmg` | Intel-based Macs |
| Debian or Ubuntu x86-64 | `Ciphera_*_amd64.deb` | Native Debian package |
| Fedora, RHEL, or compatible x86-64 | `Ciphera-*.x86_64.rpm` | Native RPM package |
| Arch Linux x86-64 | `ciphera-*-x86_64.pkg.tar.zst` | Native pacman package |
| Other x86-64 Linux | `Ciphera_*_amd64.AppImage` | Portable application |

Package availability can vary by release. If your platform's installer is not listed under **Assets**, that release does not provide it.

Files ending in `.sig` and `latest.json` support automatic updates; they are not installers.

## Install

### Automatic Linux installer

The installer detects Debian, Ubuntu, Fedora, RHEL, compatible RPM distributions, Arch-based distributions, or a generic x86-64 Linux system. It verifies the package SHA-256 digest reported by GitHub before installation:

```bash
curl -fsSL https://raw.githubusercontent.com/kab00038/Ciphera-Vault/main/install.sh | bash
```

For the most conservative installation, download `install.sh`, inspect it, and run it locally instead of piping it directly to Bash.


### Windows

1. Download the `.exe` installer, or the `.msi` if you specifically need MSI.
2. Open the downloaded file.
3. Follow the installer prompts, then launch **Ciphera** from the Start menu.

The prerelease installers are not yet Authenticode-signed. Windows SmartScreen may display an unknown-publisher warning. Confirm that the file came from the official Releases page before deciding whether to run it.

### macOS

1. Download the DMG matching your Mac: `aarch64` for Apple Silicon or `x64` for Intel.
2. Open the DMG.
3. Drag **Ciphera** into **Applications**.
4. Eject the DMG and open Ciphera from Applications.

The prerelease DMGs are not yet signed with an Apple Developer ID or notarized. macOS may block the first launch. After confirming that the DMG came from the official Releases page, Control-click Ciphera, choose **Open**, then confirm **Open**.

### Debian and Ubuntu

From the directory containing the downloaded package:

```bash
sudo apt install ./Ciphera_*_amd64.deb
```

Launch Ciphera from the application menu.

### Fedora, RHEL, and compatible distributions

From the directory containing the downloaded package:

```bash
sudo dnf install ./Ciphera-*.x86_64.rpm
```

Launch Ciphera from the application menu.

### Arch Linux

From the directory containing the downloaded package:

```bash
sudo pacman -U ./ciphera-*-x86_64.pkg.tar.zst
```

Launch Ciphera from the application menu. PIN quick unlock requires an available Secret Service provider such as GNOME Keyring or KeePassXC.

### AppImage

From the directory containing the downloaded AppImage:

```bash
chmod +x ./Ciphera_*_amd64.AppImage
./Ciphera_*_amd64.AppImage
```

The AppImage is portable and does not require installation. Move it to a stable location before enabling automatic updates.

## First launch

Choose **Create a new vault** or open an existing KDBX file. On Linux, the default new-vault location is:

```text
~/.local/share/Ciphera/vault.kdbx
```

Ciphera cannot recover a forgotten master password. Every successful vault change is written atomically and rotates five encrypted snapshots beside the vault as `<vault>.bak` through `<vault>.bak.4`. Keep additional backups on separate storage.

Optional PIN quick unlock stores its protected credential and PIN verifier in the operating-system credential vault. The master password remains the vault's encryption credential.

## Browser extension

In Ciphera, open **Settings → Browser extension** and install the native host. The app displays separate bundled-extension paths for Chromium browsers and Firefox. Follow the on-screen browser instructions for the path you use. Browser filling requires Ciphera to be running with the vault unlocked and only occurs after an explicit user action.

## Updates

Ciphera checks the official GitHub release feed after launch and offers **Update and restart** when a compatible signed update is available.

- Windows, macOS, and AppImage installations can use the in-app updater.
- Debian, RPM, and Arch installations remain package-manager-owned. Download the package from the newer release and install it with the same package-manager command shown above.

On Windows and Linux, closing the Ciphera window hides it to the system tray so browser filling can remain available. Use **Quit Ciphera** from the tray menu to stop the native process.

## Security and data ownership

- Vault operations work offline and no account is required.
- Vault files use KDBX 4.1 with AES-256 outer encryption and Argon2id key derivation.
- Browser matching uses normalized exact origins; lookalike domains do not match.
- Unexpected external vault changes are rejected instead of overwritten.
- Optional daily breach monitoring uses the Pwned Passwords range API: Ciphera sends only the first five characters of each SHA-1 password hash, requests padded responses, and performs full-suffix matching locally. The feature is disabled until enabled in Settings.
- Clipboard clearing is best-effort because operating systems and clipboard managers may retain copied data.
- The upstream Rust KDBX writer describes KDBX 4.1 writing as experimental. Maintain independent backups and verify important vaults with another KDBX-compatible application.

Ciphera is licensed under the [GNU General Public License v3.0 or later](LICENSE).
