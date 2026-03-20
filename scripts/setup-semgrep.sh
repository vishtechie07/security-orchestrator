#!/usr/bin/env bash
# Download and extract Semgrep binary for Security Orchestrator (Linux/macOS).
# Run from repo root: ./scripts/setup-semgrep.sh
# Requires: curl, tar or unzip, and jq (or falls back to fixed version)

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)/tools/semgrep"
API_URL="https://api.github.com/repos/semgrep/semgrep/releases/latest"

UNAME=$(uname -s)
if [[ "$UNAME" == "Darwin" ]]; then
  PATTERN="osx|mac"
elif [[ "$UNAME" == "Linux" ]]; then
  PATTERN="linux|ubuntu"
else
  echo "Unsupported OS: $UNAME" >&2
  exit 1
fi

ASSET_URL=""
ASSET_NAME=""
if command -v jq &>/dev/null; then
  echo "Fetching latest Semgrep release..."
  RELEASE_JSON=$(curl -sL -H "Accept: application/vnd.github+json" "$API_URL")
  ASSET_URL=$(echo "$RELEASE_JSON" | jq -r --arg re "$PATTERN" '.assets[] | select(.name | test($re)) | .browser_download_url' | head -1)
  ASSET_NAME=$(echo "$RELEASE_JSON" | jq -r --arg re "$PATTERN" '.assets[] | select(.name | test($re)) | .name' | head -1)
fi

if [[ -z "$ASSET_URL" ]] || [[ "$ASSET_URL" == "null" ]]; then
  echo "jq not found or no matching asset. Install jq, or run: pip install semgrep" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"
TMP_FILE="$OUT_DIR/../semgrep-dl-$$"
echo "Downloading $ASSET_NAME..."
curl -sL -o "$TMP_FILE" "$ASSET_URL"

if echo "$ASSET_NAME" | grep -q "\.zip"; then
  unzip -o -q "$TMP_FILE" -d "$OUT_DIR"
elif echo "$ASSET_NAME" | grep -q "\.tgz\|\.tar\.gz"; then
  tar -xzf "$TMP_FILE" -C "$OUT_DIR"
else
  echo "Unknown archive format: $ASSET_NAME" >&2
  exit 1
fi
rm -f "$TMP_FILE"

# Find semgrep binary (no .exe) and flatten to OUT_DIR if in subdir
BIN=$(find "$OUT_DIR" -maxdepth 3 -type f -name "semgrep" ! -path "*/.git/*" 2>/dev/null | head -1)
if [[ -n "$BIN" ]] && [[ "$(dirname "$BIN")" != "$OUT_DIR" ]]; then
  mv "$BIN" "$OUT_DIR/semgrep"
  find "$OUT_DIR" -mindepth 1 -maxdepth 1 ! -name "semgrep" -exec rm -rf {} +
fi
chmod +x "$OUT_DIR/semgrep" 2>/dev/null || true
echo "Semgrep installed at: $OUT_DIR/semgrep"
echo "Done. Start the app with: mvn spring-boot:run"
