#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

if [[ ! -r /etc/arch-release ]]; then
  printf 'Ciphera Arch packages must be built on Arch Linux or an Arch-based distribution.\n' >&2
  exit 1
fi

for command in makepkg cargo npm pkg-config; do
  if ! command -v "$command" >/dev/null 2>&1; then
    printf 'Missing build command: %s\n' "$command" >&2
    exit 1
  fi
done

for module in gtk+-3.0 webkit2gtk-4.1; do
  if ! pkg-config --exists "$module"; then
    printf 'Missing Arch build dependency for pkg-config module: %s\n' "$module" >&2
    exit 1
  fi
done

cd "$script_dir"
makepkg --clean --cleanbuild --force --nodeps
