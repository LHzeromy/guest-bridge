# guest-bridge (`guestctl`)

**Zero-dependency, pure Go stdlib, end-to-end encrypted interactive remote troubleshooting bridge.**

`guest-bridge` lets a helper assist with debugging a secondary **Linux (x86_64 / ARM64)** or **Windows (x64)** machine **without installing SSH servers, without placing helper credentials on the target machine, and while keeping interactive consent in the hands of the person sitting at the target keyboard**.

---

## Highlights

- **Zero Third-Party Dependencies**: Written 100% with the Go standard library (`go.mod` has zero external dependencies) — concise and auditable.
- **Mandatory Local Permission Menu Before Connecting**: Once started on an interactive console, `guest-agent` prompts the machine owner *before* dialing the relay:
  - `[1]` **Strict Read-Only** — inspect files/directories/system info only; all writes and generic commands are disabled.
  - `[2]` **Interactive Read + Confirm Writes** — allowlisted system read-only queries run with live terminal logs; sensitive paths (`~/.ssh`, `.env`, `*.key`, etc.), all file edits (with colored unified diff preview), mutating/compound commands, and screenshots pause for `[y/N]` approval.
  - `[3]` **Directory-Scoped Mode** — locks file operations strictly inside the starting working directory (with canonical path & symlink checks), disables generic shell `exec`, and requires `[y/N]` for writes.
  - `[q]` **Cancel** — exits immediately without opening any network connection.
- **On-Screen Exit Summary**: Exiting (`Ctrl+C` or `guestctl close`) disconnects the tunnel, attempts best-effort temp-file cleanup, and prints an in-memory operation summary (files read, query count, approved edits/commands/screenshots, and rejected requests) without writing log files to the target.
- **End-to-End Encrypted Blind Relay**: TLS 1.3 cert-pinned tunnel + mutual HMAC handshake + AES-256-GCM sequence-numbered framing. The relay never receives the 256-bit E2EE PSK and writes zero session logs to disk.
- **Local Archival Only on Controller Host**: Metadata (`meta.json`), session audit logs (`session.jsonl`), pre-edit backups/diffs (`diffs/`), and screenshots (`screenshots/`) are saved solely on the controller machine under `~/.local/share/guestctl/sessions/`. *(Note: upon connection, the guest shares its username, hostname, OS, and working directory with the controller.)*

---

## Quick Start

### 1. Build Static Binaries

Requires Go 1.24+:

```bash
chmod +x scripts/build.sh
./scripts/build.sh
install -m 0755 dist/guestctl ~/.local/bin/guestctl
```

`scripts/build.sh` produces static `CGO_ENABLED=0` binaries in `dist/`:
- `guest-relay` (Linux x86_64)
- `guestctl` (Linux x86_64)
- `guest-agent-linux-amd64`
- `guest-agent-linux-arm64` (Jetson / Raspberry Pi / Termux)
- `guest-agent-windows-amd64.exe` (Windows 10 / 11; verify natively in PowerShell before production use)

It also writes independent controller-local SHA-256 digests under `~/.local/share/guestctl/agent-*.sha256` so `guestctl` verifies the binary independently of the relay.

### 2. Deploy `guest-relay` on Your Relay Server

Install `dist/guest-relay` to `/usr/local/bin/guest-relay` and the `dist/guest-agent-*` binaries to `/var/lib/guest-relay/bin/` (`root:root`, read-only to the relay process), create a dedicated unprivileged user `guest-relay`, and run it with systemd:

```ini
[Unit]
Description=Hardened E2EE Guest Bridge Relay
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=guest-relay
Group=guest-relay
RuntimeDirectory=guest-relay
RuntimeDirectoryMode=0750
ExecStart=/usr/local/bin/guest-relay \
  -addr=:34434 \
  -admin-sock=/run/guest-relay/admin.sock \
  -ip=YOUR_RELAY_PUBLIC_IP \
  -data=/var/lib/guest-relay \
  -ttl=10m
Restart=always
RestartSec=3
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ReadWritePaths=/var/lib/guest-relay /run/guest-relay
ReadOnlyPaths=/var/lib/guest-relay/bin

[Install]
WantedBy=multi-user.target
```

Open TCP port `34434` on your relay firewall. The admin API listens solely on `/run/guest-relay/admin.sock` (`0600`, owned by `guest-relay`).

### 3. Configure `guestctl` Locally

Create `~/.config/guestctl/config.json` with strict `0600` permissions:

```bash
mkdir -p ~/.config/guestctl && chmod 700 ~/.config/guestctl
cat > ~/.config/guestctl/config.json << 'EOF'
{
  "ssh_host": "my-relay-ssh-alias",
  "relay_addr": "YOUR_RELAY_IP_OR_DOMAIN:34434",
  "admin_sock": "/run/guest-relay/admin.sock",
  "admin_user": "guest-relay"
}
EOF
chmod 600 ~/.config/guestctl/config.json
```

### 4. Pair & Troubleshoot

```bash
# 1. Run locally in your own terminal (keep pairing commands out of cloud chats)
guestctl pair                 # Linux x86_64 (default)
guestctl pair --os win        # Windows 10/11 PowerShell scriptblock
guestctl pair --os arm64      # Linux ARM64

# 2. Target owner runs the command and selects [1/2/3/q] in the local consent menu

# 3. Inspect and fix interactively from the controller host
guestctl status
guestctl sysinfo
guestctl ls --depth 2 /path/to/project
guestctl read --start 1 --end 120 /path/to/file
guestctl grep "ERROR" /path/to/logs
guestctl exec "nvidia-smi"
guestctl edit --old "batch_size = 64" --new "batch_size = 16" /path/to/train.py
guestctl screenshot

# 4. End session cleanly (or target owner presses Ctrl+C anytime)
guestctl close
```

---

## License

[MIT](./LICENSE)
