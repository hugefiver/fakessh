#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-.#fakessh-git}"
VENDOR_FILE="${2:-nix/vendor-hash.json}"

if ! command -v nix >/dev/null 2>&1; then
  echo "::error::nix command not found"
  exit 1
fi

set +e
BUILD_OUTPUT="$(nix build "$TARGET" --no-link 2>&1)"
BUILD_EXIT=$?
set -e

if [ "$BUILD_EXIT" -eq 0 ]; then
  echo "vendorHash is up-to-date"
  exit 0
fi

NEW_HASH="$({
  printf '%s\n' "$BUILD_OUTPUT" \
    | grep -oE 'got:[[:space:]]+sha256-[A-Za-z0-9+/=]+' \
    | awk '{print $2}' \
    | tail -n 1
} || true)"

if [ -z "$NEW_HASH" ]; then
  echo "::error::Failed to extract vendor hash from nix build output"
  printf '%s\n' "$BUILD_OUTPUT"
  exit "$BUILD_EXIT"
fi

mkdir -p "$(dirname "$VENDOR_FILE")"
printf '{\n  "vendorHash": "%s"\n}\n' "$NEW_HASH" > "$VENDOR_FILE"

echo "vendorHash updated to: $NEW_HASH"
