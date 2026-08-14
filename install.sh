#!/usr/bin/env bash
set -Eeuo pipefail

readonly REPOSITORY="kab00038/Ciphera-Vault"
readonly RELEASES_API="https://api.github.com/repos/${REPOSITORY}/releases?per_page=10"
readonly RESET='\033[0m'
readonly PURPLE='\033[1;35m'
readonly GREEN='\033[1;32m'
readonly DIM='\033[2m'

temp_dir=""
cleanup() {
  [[ -z "$temp_dir" ]] || rm -rf "$temp_dir"
}
trap cleanup EXIT

step() {
  printf '\n%b==>%b %s\n' "$PURPLE" "$RESET" "$1"
}

fail() {
  printf '\nCiphera installer: %s\n' "$1" >&2
  exit 1
}

command -v curl >/dev/null 2>&1 || fail "curl is required"
command -v python3 >/dev/null 2>&1 || fail "python3 is required to verify release metadata"
command -v sha256sum >/dev/null 2>&1 || fail "sha256sum is required to verify the download"

case "$(uname -m)" in
  x86_64 | amd64) ;;
  *) fail "Linux packages are currently available only for x86-64 systems" ;;
esac

os_id=""
os_like=""
if [[ -r /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  os_id="${ID:-}"
  os_like="${ID_LIKE:-}"
fi

package_kind="appimage"
asset_pattern='Ciphera_*_amd64.AppImage'
case " $os_id $os_like " in
  *' debian '* | *' ubuntu '*) package_kind="deb"; asset_pattern='Ciphera_*_amd64.deb' ;;
  *' fedora '* | *' rhel '* | *' centos '* | *' suse '*) package_kind="rpm"; asset_pattern='Ciphera-*.x86_64.rpm' ;;
  *' arch '* | *' manjaro '* | *' endeavouros '*) package_kind="arch"; asset_pattern='ciphera-*-x86_64.pkg.tar.zst' ;;
esac

printf '%b\n' "${PURPLE}Ciphera secure installer${RESET}"
printf '%b\n' "${DIM}Detected ${os_id:-generic Linux} on x86-64; preferred package: ${package_kind}.${RESET}"
printf '%s\n' "Source: https://github.com/${REPOSITORY}/releases"

temp_dir="$(mktemp -d)"
metadata_file="$temp_dir/releases.json"
step "Fetching official release metadata"
curl --fail --silent --show-error --location \
  --header 'Accept: application/vnd.github+json' \
  --header 'X-GitHub-Api-Version: 2022-11-28' \
  --user-agent 'Ciphera-Linux-Installer' \
  "$RELEASES_API" -o "$metadata_file"

select_asset() {
  python3 - "$metadata_file" "$1" <<'PY'
import fnmatch
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    releases = json.load(source)
for release in releases:
    if release.get("draft"):
        continue
    for asset in release.get("assets", []):
        if fnmatch.fnmatchcase(asset.get("name", ""), sys.argv[2]):
            digest = asset.get("digest", "")
            if not digest.startswith("sha256:"):
                continue
            print(asset["browser_download_url"])
            print(digest.removeprefix("sha256:"))
            print(asset["name"])
            raise SystemExit(0)
raise SystemExit(4)
PY
}

if ! asset_data="$(select_asset "$asset_pattern")"; then
  if [[ "$package_kind" == "appimage" ]]; then
    fail "no compatible package was found in the published releases"
  fi
  printf '%s\n' "No ${package_kind} asset is published in the newest releases; falling back to the portable AppImage."
  package_kind="appimage"
  asset_pattern='Ciphera_*_amd64.AppImage'
  asset_data="$(select_asset "$asset_pattern")" || fail "no compatible AppImage was found"
fi

mapfile -t asset_fields <<<"$asset_data"
asset_url="${asset_fields[0]}"
expected_sha256="${asset_fields[1]}"
asset_name="${asset_fields[2]}"
download="$temp_dir/$asset_name"

step "Downloading $asset_name"
curl --fail --location --progress-bar "$asset_url" -o "$download"

step "Verifying SHA-256 digest from GitHub release metadata"
printf '%s  %s\n' "$expected_sha256" "$download" | sha256sum --check --status \
  || fail "the downloaded package digest does not match the release metadata"
printf '%bVerified%b %s\n' "$GREEN" "$RESET" "$expected_sha256"

if [[ "${CIPHERA_INSTALLER_DRY_RUN:-0}" == "1" ]]; then
  printf '%s\n' "Dry run complete; would install $asset_name as $package_kind."
  exit 0
fi

step "Installing Ciphera"
case "$package_kind" in
  deb)
    command -v apt >/dev/null 2>&1 || fail "apt is required to install the Debian package"
    sudo apt install -y "$download"
    ;;
  rpm)
    if command -v dnf >/dev/null 2>&1; then
      sudo dnf install -y "$download"
    elif command -v zypper >/dev/null 2>&1; then
      sudo zypper --non-interactive install "$download"
    else
      fail "dnf or zypper is required to install the RPM package"
    fi
    ;;
  arch)
    command -v pacman >/dev/null 2>&1 || fail "pacman is required to install the Arch package"
    sudo pacman -U --noconfirm "$download"
    ;;
  appimage)
    install_dir="${XDG_DATA_HOME:-$HOME/.local/share}/Ciphera"
    bin_dir="$HOME/.local/bin"
    desktop_dir="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
    mkdir -p "$install_dir" "$bin_dir" "$desktop_dir"
    install -m 0755 "$download" "$install_dir/Ciphera.AppImage"
    ln -sfn "$install_dir/Ciphera.AppImage" "$bin_dir/ciphera"
    cat >"$desktop_dir/ciphera.desktop" <<EOF
[Desktop Entry]
Name=Ciphera
Comment=Offline-first password manager
Exec=$install_dir/Ciphera.AppImage
Terminal=false
Type=Application
Categories=Utility;Security;
EOF
    printf '%s\n' "Installed the AppImage at $install_dir/Ciphera.AppImage"
    if [[ ":$PATH:" != *":$bin_dir:"* ]]; then
      printf '%s\n' "Add $bin_dir to PATH to run Ciphera as: ciphera"
    fi
    ;;
esac

printf '\n%bCiphera is installed.%b Launch it from your application menu.\n' "$GREEN" "$RESET"
printf '%s\n' "After launch, open Settings > Browser extension to install the bundled Chromium and Firefox files."
