#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [ -n "${GO_BIN:-}" ]; then
  GO_CMD="$GO_BIN"
elif command -v go >/dev/null 2>&1; then
  GO_CMD="go"
elif [ -x "$HOME/.local/go/bin/go" ]; then
  GO_CMD="$HOME/.local/go/bin/go"
else
  echo "error: go compiler not found in PATH or \$HOME/.local/go/bin/go" >&2
  exit 1
fi

OUT_DIR="${ROOT}/dist"
mkdir -p "$OUT_DIR"
cd "$ROOT"

echo "Building multi-platform static binaries with $($GO_CMD version)..."
CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 "$GO_CMD" build -buildvcs=false -trimpath -ldflags="-s -w" -o "$OUT_DIR/guest-relay" ./cmd/guest-relay
CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 "$GO_CMD" build -buildvcs=false -trimpath -ldflags="-s -w" -o "$OUT_DIR/guestctl" ./cmd/guestctl
CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 "$GO_CMD" build -buildvcs=false -trimpath -ldflags="-s -w" -o "$OUT_DIR/guest-agent-linux-amd64" ./cmd/guest-agent
CGO_ENABLED=0 GOOS=linux   GOARCH=arm64 "$GO_CMD" build -buildvcs=false -trimpath -ldflags="-s -w" -o "$OUT_DIR/guest-agent-linux-arm64" ./cmd/guest-agent
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 "$GO_CMD" build -buildvcs=false -trimpath -ldflags="-s -w" -o "$OUT_DIR/guest-agent-windows-amd64.exe" ./cmd/guest-agent

# Record host-local pinned SHA-256 digests so guestctl verifies binary integrity independently of relay.
mkdir -p "$HOME/.local/share/guestctl"
chmod 700 "$HOME/.local/share/guestctl"
sha256sum "$OUT_DIR/guest-agent-linux-amd64" | awk '{print $1}' > "$HOME/.local/share/guestctl/agent-linux-amd64.sha256"
sha256sum "$OUT_DIR/guest-agent-linux-arm64" | awk '{print $1}' > "$HOME/.local/share/guestctl/agent-linux-arm64.sha256"
sha256sum "$OUT_DIR/guest-agent-windows-amd64.exe" | awk '{print $1}' > "$HOME/.local/share/guestctl/agent-windows-amd64.sha256"
chmod 600 "$HOME/.local/share/guestctl"/agent-*.sha256

ls -lh "$OUT_DIR"
sha256sum "$OUT_DIR"/*
