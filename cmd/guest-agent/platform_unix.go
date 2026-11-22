//go:build !windows

package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"guest-bridge/internal/proto"
)

func openConfirmTTY() (inFile *os.File, outFile *os.File, reader *bufio.Reader, ok bool) {
	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, nil, nil, false
	}
	return f, f, bufio.NewReader(f), true
}

func shellExecCommand(ctx context.Context, command string) *exec.Cmd {
	return exec.CommandContext(ctx, "/bin/bash", "-c", command)
}

func gatherPlatformHello() (osPretty, kernel string) {
	osPretty = runtime.GOOS
	if b, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				osPretty = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
				break
			}
		}
	}
	if out, err := exec.Command("/usr/bin/uname", "-r").Output(); err == nil {
		kernel = strings.TrimSpace(string(out))
	} else if out, err := exec.Command("/bin/uname", "-r").Output(); err == nil {
		kernel = strings.TrimSpace(string(out))
	}
	return osPretty, kernel
}

func fillPlatformSysInfo(resp *proto.SysInfoResp) {
	if out, err := exec.Command("free", "-h").Output(); err == nil {
		resp.Memory = strings.TrimSpace(string(out))
	}
	if out, err := exec.Command("df", "-h", ".").Output(); err == nil {
		resp.Disk = strings.TrimSpace(string(out))
	}
	if out, err := exec.Command("nvidia-smi", "-L").Output(); err == nil {
		resp.GPU = strings.TrimSpace(string(out))
	}
}

func capturePlatformScreenshot(ctx context.Context, tmpPath string) (string, error) {
	env := os.Environ()
	if os.Getenv("DISPLAY") == "" {
		env = append(env, "DISPLAY=:0")
	}
	candidates := []struct {
		name string
		args []string
	}{
		{"gnome-screenshot", []string{"-f", tmpPath}},
		{"scrot", []string{"-o", tmpPath}},
		{"import", []string{"-window", "root", tmpPath}},
		{"xfce4-screenshooter", []string{"-f", "-s", tmpPath}},
	}
	var lastErr string
	for _, c := range candidates {
		if _, err := exec.LookPath(c.name); err != nil {
			continue
		}
		cmd := exec.CommandContext(ctx, c.name, c.args...)
		cmd.Env = env
		if out, err := cmd.CombinedOutput(); err == nil {
			return c.name, nil
		} else {
			lastErr = fmt.Sprintf("%s: %v (%s)", c.name, err, strings.TrimSpace(string(out)))
		}
	}
	if lastErr == "" {
		lastErr = "no screenshot tool found (gnome-screenshot / scrot / import)"
	}
	return "", fmt.Errorf("%s", lastErr)
}

func selfCleanPlatform(enable bool) bool {
	if !enable {
		return false
	}
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	base := filepath.Base(exe)
	if (strings.HasPrefix(exe, "/tmp/") || strings.HasPrefix(exe, os.TempDir()+string(os.PathSeparator))) && strings.HasPrefix(base, "guest-agent-") {
		return os.Remove(exe) == nil
	}
	return false
}
