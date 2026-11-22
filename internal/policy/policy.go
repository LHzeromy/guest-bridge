package policy

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

func getTrustedBinDirs() []string {
	if runtime.GOOS == "windows" {
		sysRoot := os.Getenv("SystemRoot")
		if sysRoot == "" {
			sysRoot = `C:\Windows`
		}
		progFiles := os.Getenv("ProgramFiles")
		if progFiles == "" {
			progFiles = `C:\Program Files`
		}
		return []string{
			filepath.Join(sysRoot, "System32"),
			filepath.Join(sysRoot, "SysWOW64"),
			filepath.Join(progFiles, "Git", "cmd"),
			filepath.Join(progFiles, "Git", "usr", "bin"),
			filepath.Join(progFiles, "NVIDIA Corporation", "NVSMI"),
		}
	}
	return []string{
		"/usr/local/sbin",
		"/usr/local/bin",
		"/usr/sbin",
		"/usr/bin",
		"/sbin",
		"/bin",
	}
}

// ClassifyCommand determines if a command is strictly read-only without invoking a shell.
// Returns (true, resolvedAbsBin, args) only when:
//   - No shell control/redirection/expansion metacharacters exist
//   - The executable resolves strictly inside trusted system directories (blocks /tmp/fake-ls)
//   - Subcommands and flags pass a tight read-only allowlist (blocks git -c, printenv, etc.)
func ClassifyCommand(cmd string) (readOnly bool, resolvedBin string, argv []string) {
	trimmed := strings.TrimSpace(cmd)
	if trimmed == "" {
		return false, "", nil
	}
	const forbidden = "|&;><`$()\n\r\x00{}*?"
	if strings.ContainsAny(trimmed, forbidden) {
		return false, "", nil
	}
	args, ok := splitArgs(trimmed)
	if !ok || len(args) == 0 {
		return false, "", nil
	}

	// Reject explicit paths outside trusted system directories.
	rawBin := args[0]
	if strings.ContainsAny(rawBin, `/\`) {
		cleanBin := filepath.Clean(rawBin)
		if !inTrustedDir(cleanBin) {
			return false, "", nil
		}
		resolvedBin = cleanBin
	} else {
		// Look up strictly inside trusted system directories (never honoring untrusted CWD/user PATH).
		found := lookupTrusted(rawBin)
		if found == "" {
			return false, "", nil
		}
		resolvedBin = found
	}

	bin := strings.ToLower(strings.TrimSuffix(filepath.Base(resolvedBin), ".exe"))
	rest := args[1:]

	if !isAllowedReadOnly(bin, rest) {
		return false, "", nil
	}
	return true, resolvedBin, args
}

// ClassifyCommandForTest exposes the syntactic + path rules without requiring host binaries to exist.
func isAllowedReadOnly(bin string, rest []string) bool {
	switch bin {
	case "uname", "whoami", "id", "uptime", "pwd",
		"ls", "stat", "file", "df", "du", "free", "lsblk", "lscpu", "lspci", "lsusb",
		"nproc", "arch", "lsb_release", "ps", "pgrep", "ss", "netstat",
		"dig", "nslookup", "wc", "md5sum", "sha256sum",
		"which", "whereis", "where", "readlink", "realpath", "ldd",
		"systeminfo", "tasklist":
		return true

	case "hostname":
		// Only allow read-only hostname queries (setting hostname takes a positional argument).
		if len(rest) == 0 {
			return true
		}
		if len(rest) == 1 {
			switch rest[0] {
			case "-f", "-s", "-i", "-I", "--fqdn", "--short":
				return true
			}
		}
		return false

	case "date":
		// Block date -s / --set / positional time setting.
		for _, a := range rest {
			if a == "-u" || a == "--utc" || a == "-R" || a == "--rfc-email" || strings.HasPrefix(a, "+") || strings.HasPrefix(a, "--iso-8601") || strings.HasPrefix(a, "--rfc-3339") {
				continue
			}
			return false
		}
		return true

	case "ipconfig":
		return len(rest) == 0 || (len(rest) == 1 && strings.EqualFold(rest[0], "/all"))

	case "cat", "head", "tail":
		// Reject reading sensitive credential paths via auto-approved cat/head/tail.
		for _, a := range rest {
			if !strings.HasPrefix(a, "-") && IsSensitivePath(a) {
				return false
			}
		}
		return true

	case "ping":
		for _, a := range rest {
			if a == "-c" || strings.HasPrefix(a, "-c") || a == "-n" || strings.HasPrefix(a, "-n") {
				return true
			}
		}
		return false

	case "nvidia-smi":
		for _, a := range rest {
			al := strings.ToLower(a)
			for _, bad := range []string{"-pm", "--persistence-mode", "-pl", "--power-limit", "-ac", "-rac", "-lgc", "-rgc", "-lmc", "-rmc", "-r", "--gpu-reset", "-c", "--compute-mode", "-mig", "-f", "--filename"} {
				if al == bad || strings.HasPrefix(al, bad+"=") {
					return false
				}
			}
		}
		return true

	case "ip":
		return isReadOnlyIP(rest)

	case "systemctl":
		return isReadOnlySystemctl(rest)

	case "journalctl":
		for _, a := range rest {
			for _, bad := range []string{"--vacuum", "--rotate", "--flush", "--relinquish", "--sync", "--update"} {
				if strings.HasPrefix(a, bad) {
					return false
				}
			}
		}
		return true

	case "dmesg":
		for _, a := range rest {
			if a == "-c" || a == "-C" || a == "-D" || a == "-E" || a == "-n" ||
				strings.HasPrefix(a, "--clear") || strings.HasPrefix(a, "--read-clear") || strings.HasPrefix(a, "--console") {
				return false
			}
		}
		return true

	case "git":
		return isReadOnlyGit(rest)

	case "docker":
		return isReadOnlyDocker(rest)

	case "pip", "pip3":
		if len(rest) >= 1 {
			switch rest[0] {
			case "list", "show", "freeze", "check", "--version", "-V":
				return true
			}
		}
		return false

	case "conda":
		if len(rest) >= 1 {
			switch rest[0] {
			case "info", "list", "--version", "-V":
				return true
			case "env":
				return len(rest) >= 2 && rest[1] == "list"
			}
		}
		return false

	case "dpkg":
		if len(rest) >= 1 {
			switch rest[0] {
			case "-l", "-s", "-L", "-S", "--list", "--status":
				return true
			}
		}
		return false

	case "apt-cache":
		if len(rest) >= 1 {
			switch rest[0] {
			case "policy", "show", "search", "depends", "rdepends", "madison":
				return true
			}
		}
		return false

	case "python", "python3", "node", "npm", "gcc", "g++", "nvcc", "go", "cmake", "rustc", "cargo":
		return len(rest) == 1 && (rest[0] == "--version" || rest[0] == "-V" || rest[0] == "-v" || rest[0] == "version")

	case "rostopic", "rosnode", "rosservice", "rosparam":
		return len(rest) >= 1 && (rest[0] == "list" || rest[0] == "info" || rest[0] == "type")

	case "ros2":
		if len(rest) >= 2 {
			switch rest[0] {
			case "node", "topic", "service", "action", "param", "pkg":
				return rest[1] == "list" || rest[1] == "info" || rest[1] == "type"
			}
		}
		return false
	}
	return false
}

// IsSensitivePath flags high-risk credential/key paths so reading them requires [y/N] confirmation
// without restricting general Linux troubleshooting under /etc, /var/log, /opt, or projects.
func IsSensitivePath(p string) bool {
	clean := filepath.ToSlash(filepath.Clean(p))
	lower := strings.ToLower(clean)
	sensitiveSegments := []string{
		"/.ssh", "/.gnupg", "/.aws", "/.kube",
		"/.claude", "/.codex", "/.gemini",
		"/etc/shadow", "/etc/gshadow",
	}
	for _, seg := range sensitiveSegments {
		if lower == seg || strings.HasPrefix(lower, seg+"/") || strings.Contains(lower, seg+"/") || strings.HasSuffix(lower, seg) {
			return true
		}
	}
	if strings.HasPrefix(lower, "/proc/") && (strings.HasSuffix(lower, "/environ") || strings.HasSuffix(lower, "/mem")) {
		return true
	}
	base := filepath.Base(lower)
	if base == ".env" || strings.HasPrefix(base, "id_rsa") || strings.HasPrefix(base, "id_ed25519") || strings.HasSuffix(base, ".pem") || strings.HasSuffix(base, ".key") {
		return true
	}
	return false
}

func inTrustedDir(absPath string) bool {
	dir := filepath.Dir(absPath)
	for _, td := range getTrustedBinDirs() {
		if runtime.GOOS == "windows" {
			if strings.EqualFold(dir, td) {
				return true
			}
		} else if dir == td {
			return true
		}
	}
	return false
}

func lookupTrusted(name string) string {
	for _, td := range getTrustedBinDirs() {
		cand := filepath.Join(td, name)
		if p, err := exec.LookPath(cand); err == nil {
			return p
		}
		if runtime.GOOS == "windows" && !strings.HasSuffix(strings.ToLower(name), ".exe") {
			if p, err := exec.LookPath(cand + ".exe"); err == nil {
				return p
			}
		}
	}
	return ""
}

func isReadOnlyIP(rest []string) bool {
	i := 0
	for i < len(rest) && strings.HasPrefix(rest[i], "-") {
		i++
	}
	if i >= len(rest) {
		return false
	}
	switch rest[i] {
	case "a", "addr", "address", "r", "route", "l", "link", "n", "neigh", "neighbor", "rule":
		if i+1 < len(rest) {
			switch rest[i+1] {
			case "show", "list", "get":
				return true
			default:
				return false
			}
		}
		return true
	}
	return false
}

func isReadOnlySystemctl(rest []string) bool {
	i := 0
	for i < len(rest) && strings.HasPrefix(rest[i], "-") {
		// Reject flags that could specify remote host/root or edit units.
		if strings.HasPrefix(rest[i], "-H") || strings.HasPrefix(rest[i], "--host") || strings.HasPrefix(rest[i], "--root") {
			return false
		}
		i++
	}
	if i >= len(rest) {
		return false
	}
	switch rest[i] {
	case "status", "is-active", "is-enabled", "is-failed",
		"list-units", "list-unit-files", "list-timers", "list-sockets", "cat", "show":
		return true
	}
	return false
}

func isReadOnlyGit(rest []string) bool {
	i := 0
	for i < len(rest) {
		if rest[i] == "-C" && i+1 < len(rest) {
			i += 2
			continue
		}
		if rest[i] == "--no-pager" {
			i++
			continue
		}
		// Explicitly reject git global options like -c, --config-env, --exec-path, --git-dir, --work-tree.
		if strings.HasPrefix(rest[i], "-") {
			return false
		}
		break
	}
	if i >= len(rest) {
		return false
	}
	sub := rest[i]
	subArgs := rest[i+1:]
	// Reject external diff / pager / output flags across git subcommands.
	for _, a := range subArgs {
		if strings.HasPrefix(a, "--ext-diff") || strings.HasPrefix(a, "--output") || strings.HasPrefix(a, "-o") || strings.HasPrefix(a, "--exec") {
			return false
		}
	}
	switch sub {
	case "status", "diff", "log", "show", "rev-parse", "describe":
		return true
	case "branch":
		for _, a := range subArgs {
			switch a {
			case "-a", "-r", "-v", "-vv", "--all", "--remotes", "--list", "--show-current":
				continue
			default:
				return false
			}
		}
		return true
	case "remote":
		return len(subArgs) == 0 || (len(subArgs) == 1 && (subArgs[0] == "-v" || subArgs[0] == "--verbose"))
	}
	return false
}

func isReadOnlyDocker(rest []string) bool {
	if len(rest) == 0 {
		return false
	}
	// Reject global docker flags like -H/--host or --context before subcommand.
	if strings.HasPrefix(rest[0], "-") {
		return false
	}
	switch rest[0] {
	case "ps", "images", "logs", "inspect", "info", "version":
		return true
	case "stats":
		for _, a := range rest[1:] {
			if a == "--no-stream" {
				return true
			}
		}
		return false
	case "compose":
		if len(rest) >= 2 {
			switch rest[1] {
			case "ps", "logs", "ls", "images":
				return true
			}
		}
	case "network", "volume":
		if len(rest) >= 2 && (rest[1] == "ls" || rest[1] == "inspect") {
			return true
		}
	}
	return false
}

func splitArgs(s string) ([]string, bool) {
	var args []string
	var cur strings.Builder
	inSingle := false
	inDouble := false
	hasToken := false

	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case inSingle:
			if ch == '\'' {
				inSingle = false
			} else {
				cur.WriteByte(ch)
			}
		case inDouble:
			if ch == '"' {
				inDouble = false
			} else if ch == '\\' && i+1 < len(s) {
				i++
				cur.WriteByte(s[i])
			} else {
				cur.WriteByte(ch)
			}
		default:
			switch ch {
			case ' ', '\t':
				if hasToken {
					args = append(args, cur.String())
					cur.Reset()
					hasToken = false
				}
			case '\'':
				inSingle = true
				hasToken = true
			case '"':
				inDouble = true
				hasToken = true
			case '\\':
				if i+1 >= len(s) {
					return nil, false
				}
				i++
				cur.WriteByte(s[i])
				hasToken = true
			default:
				cur.WriteByte(ch)
				hasToken = true
			}
		}
	}
	if inSingle || inDouble {
		return nil, false
	}
	if hasToken {
		args = append(args, cur.String())
	}
	return args, true
}
