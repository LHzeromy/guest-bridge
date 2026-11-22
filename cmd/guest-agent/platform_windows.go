//go:build windows

package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"guest-bridge/internal/proto"
)

func openConfirmTTY() (inFile *os.File, outFile *os.File, reader *bufio.Reader, ok bool) {
	inF, err := os.OpenFile("CONIN$", os.O_RDONLY, 0)
	if err != nil {
		return nil, nil, nil, false
	}
	outF, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0)
	if err != nil {
		_ = inF.Close()
		return nil, nil, nil, false
	}
	return inF, outF, bufio.NewReader(inF), true
}

func shellExecCommand(ctx context.Context, command string) *exec.Cmd {
	// Ensure UTF-8 stdout/stderr encoding on Windows PowerShell.
	script := "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; $OutputEncoding = [System.Text.Encoding]::UTF8; " + command
	return exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
}

func gatherPlatformHello() (osPretty, kernel string) {
	osPretty = "Windows"
	if out, err := exec.Command("cmd.exe", "/c", "ver").Output(); err == nil {
		v := strings.TrimSpace(string(out))
		if v != "" {
			osPretty = v
			kernel = v
		}
	}
	return osPretty, kernel
}

func fillPlatformSysInfo(resp *proto.SysInfoResp) {
	ps := `
$os = Get-CimInstance Win32_OperatingSystem
$freeGB = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
$totGB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
Write-Output ("RAM: {0} GB free / {1} GB total" -f $freeGB, $totGB)
`
	if out, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps).Output(); err == nil {
		resp.Memory = strings.TrimSpace(string(out))
	}
	diskPS := `Get-PSDrive -PSProvider FileSystem | ForEach-Object { "{0}: {1:N1} GB free / {2:N1} GB used" -f $_.Name, ($_.Free/1GB), ($_.Used/1GB) }`
	if out, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", diskPS).Output(); err == nil {
		resp.Disk = strings.TrimSpace(string(out))
	}
	if out, err := exec.Command("nvidia-smi.exe", "-L").Output(); err == nil {
		resp.GPU = strings.TrimSpace(string(out))
	}
}

func capturePlatformScreenshot(ctx context.Context, tmpPath string) (string, error) {
	// Pass output path via environment variable instead of string interpolation into PowerShell code.
	ps := `
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$bounds = [System.Windows.Forms.SystemInformation]::VirtualScreen
$bmp = New-Object System.Drawing.Bitmap $bounds.Width, $bounds.Height
$gfx = [System.Drawing.Graphics]::FromImage($bmp)
$gfx.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size)
$bmp.Save($env:GB_SHOT_PATH, [System.Drawing.Imaging.ImageFormat]::Png)
$gfx.Dispose()
$bmp.Dispose()
`
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps)
	cmd.Env = append(os.Environ(), "GB_SHOT_PATH="+tmpPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("powershell screenshot: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	return "powershell-dotnet", nil
}

func selfCleanPlatform(enable bool) bool {
	// Windows locks running .exe files; outer PowerShell `finally { Remove-Item ... }` removes it cleanly on exit.
	return false
}
