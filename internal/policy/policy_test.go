package policy

import "testing"

func TestClassifyCommand(t *testing.T) {
	allowed := []string{
		"uname -a",
		"/usr/bin/uname -a",
		"hostname",
		"hostname -f",
		"date",
		"date -u",
		"ls -la /tmp",
		"ps aux",
		"ss -tulnp",
		"ip -4 addr show",
		"ip route show",
		"systemctl status docker",
		"systemctl --user status demo-app",
		"journalctl -u demo-svc -n 50 --no-pager",
		"git status",
		"git -C /home/user/repo log -n 5",
		"git branch -a",
		"python3 --version",
		"ping -c 3 127.0.0.1",
		"cat /etc/os-release",
	}
	for _, cmd := range allowed {
		ok, bin, argv := ClassifyCommand(cmd)
		if !ok || bin == "" || len(argv) == 0 {
			t.Errorf("expected read-only ALLOWED for %q, got ok=%v bin=%q argv=%v", cmd, ok, bin, argv)
		}
	}

	mustConfirm := []string{
		// State-changing flags on otherwise common commands
		"hostname new-host",
		"date -s 2026-01-01",
		"date 010100002026",
		// Path basename bypasses
		"/tmp/evil/ls -la",
		"./ls",
		"/home/user/bin/git status",
		// Git config / external diff code execution
		"git -c core.pager=id log",
		"git diff --ext-diff",
		"git diff --output=/tmp/x",
		// Sensitive env/file reads
		"printenv",
		"cat /home/user/.ssh/id_ed25519",
		"cat /etc/shadow",
		"cat /proc/self/environ",
		"cat /app/.env",
		// Shell metachars & mutating commands (RFC 5737 doc IPs only)
		"rm -rf /tmp/foo",
		"ls -la; whoami",
		"ls -la && rm foo",
		"cat /etc/hosts > /tmp/x",
		"ps aux | grep python",
		"ls $(whoami)",
		"sudo ls",
		"nvidia-smi --gpu-reset",
		"nvidia-smi -f /tmp/out.txt",
		"ip addr add 192.0.2.10/24 dev eth0",
		"systemctl restart nginx",
		"systemctl -H root@other status sshd",
		"journalctl --vacuum-time=1d",
		"dmesg -C",
		"docker run alpine",
		"docker -H tcp://192.0.2.10:2375 ps",
		"git checkout main",
		"git branch -D old",
		"pip install numpy",
		"python3 train.py",
		"ping 192.0.2.1",
		"curl https://example.com",
	}
	for _, cmd := range mustConfirm {
		ok, bin, _ := ClassifyCommand(cmd)
		if ok {
			t.Errorf("SECURITY BUG: expected CONFIRM REQUIRED for %q, got read-only=true (bin=%q)", cmd, bin)
		}
	}
}
