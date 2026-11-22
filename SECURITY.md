# Security Policy

## Threat Model & Honest Scope

`guest-bridge` is designed for **explicitly authorized, foreground interactive troubleshooting** on a secondary workstation without installing persistent SSH servers or placing personal helper credentials on the target machine.

- **Mandatory Local Consent Before Dialing**: When `guest-agent` starts, it requires an interactive local console (`/dev/tty` on Unix, `CONIN$`/`CONOUT$` on Windows) and displays a permission menu (`[1]` strict read-only, `[2]` read + per-change `[y/N]` approval, `[3]` directory-scoped file operations only + `[y/N]`, or `[q]` cancel) **before** opening its tunnel connection to the relay. (Note: downloading the binary via the pairing command occurs before `guest-agent` runs.)
- **Explicit `[y/N]` Confirmation & Zero-Leak Rejection**: Every file edit (`edit`/`write`), mutating or compound command (`exec`), sensitive credential file read (`~/.ssh`, `.env`, `*.pem`, `*.key`, `/etc/shadow`, `/proc/*/environ`), and desktop screenshot pauses for `[y/N]` on the target console. Rejected edits return zero file contents or diff bytes to the controller.
- **Atomic & Symlink-Safe Writes**: File edits verify regular-file status (`Lstat`), enforce file size limits before allocating replacements, re-check pre-confirmation SHA-256 integrity (TOCTOU guard), sanitize ANSI/control/BiDi escape sequences in terminal previews, and commit via same-directory temp file + atomic rename.
- **Directory-Scoped Mode (`[3]`)**: Resolves canonical paths (`EvalSymlinks`) to block `..` and symlink escapes outside the operator's starting working directory, and disables generic shell `exec` completely.
- **Transport & E2EE**:
  - Tunnel connections to `guest-relay` enforce TLS 1.3 leaf-certificate SHA-256 pinning. (The initial binary download command uses `curl -k` for self-signed relays and relies on the independent host-pinned `SHA-256` verification before execution; for public CA verification, host the binary on GitHub Releases or a CA-signed HTTPS endpoint.)
  - Host and guest perform mutual HMAC challenge-response and AES-256-GCM authenticated framing with monotonic sequence numbers; the relay forwards opaque ciphertext and never receives the 256-bit E2EE PSK.
- **Minimal-Privilege Relay**: `guest-relay` runs as an unprivileged user (`guest-relay`) with a `0600` Unix socket (`/run/guest-relay/admin.sock`) accessible only to that OS user/root, and enforces atomic pending/active session quotas, idle timeouts, and maximum tunnel lifetime.
- **Runtime Privacy & Best-Effort Cleanup**: Once connected, `guest-agent` sends the target's username, hostname, OS version, and starting working directory to the controller (archived locally under `~/.local/share/guestctl/sessions/`). Temporary files and binaries are cleaned up on a best-effort basis (`defer` / shell `trap` / PowerShell `finally`) and an on-screen operation summary is printed on exit without writing log files to the target. Keep pairing commands out of third-party/cloud chats and shell logs where possible.

## Reporting a Vulnerability

Please open a private security advisory on GitHub or report issues responsibly without publishing active credentials or exploits.
