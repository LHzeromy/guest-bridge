package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	e2ee "guest-bridge/internal/crypto"
	"guest-bridge/internal/diff"
	"guest-bridge/internal/policy"
	"guest-bridge/internal/proto"
)

const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiRed    = "\033[31m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiCyan   = "\033[36m"
	ansiDim    = "\033[2m"

	maxEditFileBytes = 2 * 1024 * 1024 // 2 MiB max target file size for edit/write preview
)

type sessionStats struct {
	mu            sync.Mutex
	startedAt     time.Time
	readFiles     []string
	readSeen      map[string]bool
	roQueries     int
	approvedEdits []string
	approvedExecs int
	screenshots   int
	rejectedOps   int
}

func newSessionStats() *sessionStats {
	return &sessionStats{
		startedAt: time.Now(),
		readSeen:  make(map[string]bool),
	}
}

func (s *sessionStats) addRead(p string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.readSeen[p] {
		s.readSeen[p] = true
		s.readFiles = append(s.readFiles, p)
	}
}

func (s *sessionStats) addROQuery() {
	s.mu.Lock()
	s.roQueries++
	s.mu.Unlock()
}

func (s *sessionStats) addEdit(p string) {
	s.mu.Lock()
	s.approvedEdits = append(s.approvedEdits, p)
	s.mu.Unlock()
}

func (s *sessionStats) addApprovedExec() {
	s.mu.Lock()
	s.approvedExecs++
	s.mu.Unlock()
}

func (s *sessionStats) addScreenshot() {
	s.mu.Lock()
	s.screenshots++
	s.mu.Unlock()
}

func (s *sessionStats) addReject() {
	s.mu.Lock()
	s.rejectedOps++
	s.mu.Unlock()
}

func (s *sessionStats) printReceipt(w io.Writer, cleaned bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	dur := time.Since(s.startedAt).Round(time.Second)

	fmt.Fprintf(w, "\n%s================ 本次协助操作摘要（仅屏幕展示，未写盘）================%s\n", ansiCyan+ansiBold, ansiReset)
	fmt.Fprintf(w, "  会话时长: %s\n", dur)
	fmt.Fprintf(w, "  只读文件: %d 个", len(s.readFiles))
	if len(s.readFiles) > 0 {
		limit := len(s.readFiles)
		if limit > 8 {
			limit = 8
		}
		var safeNames []string
		for _, rf := range s.readFiles[:limit] {
			safeNames = append(safeNames, sanitizeSingleLine(rf))
		}
		fmt.Fprintf(w, "（%s", strings.Join(safeNames, ", "))
		if len(s.readFiles) > limit {
			fmt.Fprintf(w, " 等共 %d 个", len(s.readFiles))
		}
		fmt.Fprint(w, "）")
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  只读查询: %d 次\n", s.roQueries)
	fmt.Fprintf(w, "  批准命令: %d 次\n", s.approvedExecs)
	fmt.Fprintf(w, "  批准修改: %d 次", len(s.approvedEdits))
	if len(s.approvedEdits) > 0 {
		var safeEdits []string
		for _, ef := range s.approvedEdits {
			safeEdits = append(safeEdits, sanitizeSingleLine(ef))
		}
		fmt.Fprintf(w, "（%s）", strings.Join(safeEdits, ", "))
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  批准截屏: %d 次\n", s.screenshots)
	fmt.Fprintf(w, "  已拒操作: %d 次\n", s.rejectedOps)
	if cleaned {
		fmt.Fprintf(w, "  退出状态: %s加密通道已断开，临时可执行文件已尝试删除%s\n", ansiGreen, ansiReset)
	} else {
		fmt.Fprintf(w, "  退出状态: %s加密通道已断开（外层命令会尽力删除临时文件）%s\n", ansiGreen, ansiReset)
	}
	fmt.Fprintf(w, "%s======================================================================%s\n", ansiCyan+ansiBold, ansiReset)
}

type agent struct {
	mode       string // "confirm" or "ro" (strictly chosen by local operator)
	rootScope  string // optional resolved directory boundary (set when operator picks [3])
	conn       *e2ee.Conn
	promptMu   sync.Mutex
	ttyLines   <-chan string
	ttyOutFile *os.File
	hasTTY     bool
	stats      *sessionStats
	ctx        context.Context
	cancel     context.CancelFunc
	stopOnce   sync.Once
}

func newAgent(mode, rootScope string, conn *e2ee.Conn, outF *os.File, ttyLines <-chan string, hasTTY bool) *agent {
	ctx, cancel := context.WithCancel(context.Background())
	return &agent{
		mode:       mode,
		rootScope:  rootScope,
		conn:       conn,
		ttyOutFile: outF,
		ttyLines:   ttyLines,
		hasTTY:     hasTTY,
		stats:      newSessionStats(),
		ctx:        ctx,
		cancel:     cancel,
	}
}

func (a *agent) stop() {
	a.stopOnce.Do(func() {
		a.cancel()
	})
}

func (a *agent) isStopped() bool {
	select {
	case <-a.ctx.Done():
		return true
	default:
		return false
	}
}

// sanitizeTTY escapes raw terminal escape sequences, C0 controls, and Unicode BiDi overrides
// to prevent prompt or diff spoofing on the target console.
func sanitizeTTY(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == 0x1b:
			b.WriteString("\\x1b")
		case r < 0x20 && r != '\n' && r != '\t':
			b.WriteString(fmt.Sprintf("\\x%02x", r))
		case r == 0x7f || (r >= 0x80 && r <= 0x9f):
			b.WriteString(fmt.Sprintf("\\u%04x", r))
		case (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069):
			b.WriteString(fmt.Sprintf("\\u%04x", r))
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// sanitizeSingleLine additionally escapes newlines and tabs so paths/headers cannot spoof new lines.
func sanitizeSingleLine(s string) string {
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")
	s = strings.ReplaceAll(s, "\t", "\\t")
	return sanitizeTTY(s)
}

func (a *agent) logRO(format string, args ...any) {
	ts := time.Now().Format("15:04:05")
	msg := sanitizeSingleLine(fmt.Sprintf(format, args...))
	fmt.Fprintf(os.Stderr, "%s[%s]%s %s[只读]%s %s\n", ansiDim, ts, ansiReset, ansiCyan, ansiReset, msg)
}

// startTTYReader starts a single dedicated console reader goroutine so timeouts never leave competing readers.
func startTTYReader(rd *bufio.Reader) <-chan string {
	ch := make(chan string, 1)
	go func() {
		for {
			line, err := rd.ReadString('\n')
			if err != nil {
				close(ch)
				return
			}
			ch <- line
		}
	}()
	return ch
}

func (a *agent) askConfirm(header, body, question string) bool {
	if a.isStopped() {
		return false
	}
	if a.mode == "ro" {
		fmt.Fprintf(os.Stderr, "%s[只读模式已拒绝]%s %s\n", ansiRed, ansiReset, sanitizeSingleLine(header))
		a.stats.addReject()
		return false
	}
	if !a.hasTTY || a.ttyOutFile == nil || a.ttyLines == nil {
		fmt.Fprintf(os.Stderr, "%s[无交互控制台，默认拒绝]%s %s\n", ansiRed, ansiReset, sanitizeSingleLine(header))
		a.stats.addReject()
		return false
	}

	a.promptMu.Lock()
	defer a.promptMu.Unlock()

	if a.isStopped() {
		return false
	}

	// Drain any stale keystrokes buffered before this prompt appeared.
	for {
		select {
		case _, ok := <-a.ttyLines:
			if !ok {
				return false
			}
		default:
			goto prompted
		}
	}
prompted:

	fmt.Fprintf(a.ttyOutFile, "\n%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n", ansiYellow, ansiReset)
	fmt.Fprintf(a.ttyOutFile, "%s%s%s\n", ansiBold+ansiYellow, sanitizeSingleLine(header), ansiReset)
	if body != "" {
		fmt.Fprintln(a.ttyOutFile, body)
	}
	fmt.Fprintf(a.ttyOutFile, "%s%s [y/N]: %s", ansiBold+ansiYellow, sanitizeSingleLine(question), ansiReset)

	select {
	case <-a.ctx.Done():
		fmt.Fprintf(a.ttyOutFile, "\n%s[会话已断开，自动取消待确认操作]%s\n", ansiRed, ansiReset)
		a.stats.addReject()
		return false
	case <-time.After(4 * time.Minute):
		fmt.Fprintf(a.ttyOutFile, "\n%s[确认超时，默认拒绝]%s\n", ansiRed, ansiReset)
		a.stats.addReject()
		return false
	case line, ok := <-a.ttyLines:
		if !ok || a.isStopped() {
			fmt.Fprintf(a.ttyOutFile, "\n%s[输入中断，默认拒绝]%s\n", ansiRed, ansiReset)
			a.stats.addReject()
			return false
		}
		ans := strings.ToLower(strings.TrimSpace(line))
		approved := ans == "y" || ans == "yes"
		if approved {
			fmt.Fprintf(a.ttyOutFile, "%s✓ 已批准%s\n", ansiGreen, ansiReset)
		} else {
			fmt.Fprintf(a.ttyOutFile, "%s✗ 已拒绝%s\n", ansiRed, ansiReset)
			a.stats.addReject()
		}
		fmt.Fprintf(a.ttyOutFile, "%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n", ansiYellow, ansiReset)
		return approved
	}
}

// resolveScoped resolves p to an absolute, symlink-resolved canonical path and enforces rootScope when set.
func (a *agent) resolveScoped(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", fmt.Errorf("invalid path: %w", err)
	}
	resolved := abs
	if ev, err := filepath.EvalSymlinks(abs); err == nil {
		resolved = ev
	} else if os.IsNotExist(err) {
		// Allow non-existent target leaf only if its existing parent resolves cleanly.
		parent := filepath.Dir(abs)
		evParent, perr := filepath.EvalSymlinks(parent)
		if perr != nil {
			if a.rootScope != "" {
				return "", fmt.Errorf("refused: cannot verify parent directory of %q: %w", p, perr)
			}
			resolved = abs
		} else {
			resolved = filepath.Join(evParent, filepath.Base(abs))
		}
	} else if a.rootScope != "" {
		return "", fmt.Errorf("refused: cannot resolve path %q: %w", p, err)
	}

	if a.rootScope != "" {
		rel, err := filepath.Rel(a.rootScope, resolved)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			return "", fmt.Errorf("refused: path %q is outside operator-approved directory %q", p, a.rootScope)
		}
		if runtime.GOOS == "windows" {
			// Guard case-insensitive volume/prefix consistency on Windows.
			if !strings.EqualFold(filepath.VolumeName(resolved), filepath.VolumeName(a.rootScope)) {
				return "", fmt.Errorf("refused: path %q is on a different volume than %q", p, a.rootScope)
			}
		}
	}
	return resolved, nil
}

func (a *agent) sendResp(id, action string, ok bool, errMsg string, payload any) error {
	var raw json.RawMessage
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		raw = b
	}
	return a.conn.WriteJSON(proto.Message{
		ID:      id,
		Kind:    "resp",
		Action:  action,
		OK:      ok,
		Error:   errMsg,
		Payload: raw,
	})
}

func (a *agent) sendHello() error {
	hello := gatherHello(a.mode, a.rootScope)
	raw, _ := json.Marshal(hello)
	return a.conn.WriteJSON(proto.Message{
		Kind:    "event",
		Action:  "hello",
		OK:      true,
		Payload: raw,
	})
}

func (a *agent) serveLoop() error {
	for {
		var msg proto.Message
		if err := a.conn.ReadJSON(&msg); err != nil {
			a.stop()
			return err
		}
		if msg.Kind != "req" {
			continue
		}
		switch msg.Action {
		case "ping":
			_ = a.sendResp(msg.ID, "pong", true, "", nil)
		case "close":
			fmt.Fprintf(os.Stderr, "\n%s[协助端已结束本次会话]%s 正在退出...\n", ansiCyan, ansiReset)
			_ = a.sendResp(msg.ID, "close", true, "", nil)
			a.stop()
			return nil
		case "sysinfo":
			a.handleSysInfo(msg)
		case "read_file":
			a.handleReadFile(msg)
		case "list_dir":
			a.handleListDir(msg)
		case "grep":
			a.handleGrep(msg)
		case "exec":
			a.handleExec(msg)
		case "edit_file":
			a.handleEditFile(msg)
		case "write_file":
			a.handleWriteFile(msg)
		case "screenshot":
			a.handleScreenshot(msg)
		default:
			_ = a.sendResp(msg.ID, msg.Action, false, "unknown action: "+msg.Action, nil)
		}
	}
}

func gatherHello(mode, rootScope string) proto.GuestHello {
	hn, _ := os.Hostname()
	cwd, _ := os.Getwd()
	uname := ""
	if u, err := user.Current(); err == nil {
		uname = u.Username
	}
	osPretty, kern := gatherPlatformHello()
	modeDesc := mode
	if rootScope != "" {
		modeDesc = mode + " (scoped:" + rootScope + ")"
	}
	return proto.GuestHello{
		Hostname: hn,
		User:     uname,
		OSPretty: osPretty,
		Kernel:   kern,
		Arch:     runtime.GOARCH,
		Cwd:      cwd,
		Mode:     modeDesc,
	}
}

func (a *agent) handleSysInfo(msg proto.Message) {
	a.logRO("获取系统基础概览 (OS / 内存 / 磁盘 / GPU)")
	a.stats.addROQuery()
	h := gatherHello(a.mode, a.rootScope)
	resp := proto.SysInfoResp{
		Hostname: h.Hostname,
		User:     h.User,
		OSPretty: h.OSPretty,
		Kernel:   h.Kernel,
		Arch:     h.Arch,
		Cwd:      h.Cwd,
	}
	fillPlatformSysInfo(&resp)
	_ = a.sendResp(msg.ID, msg.Action, true, "", resp)
}

func expandPath(p string) string {
	if strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, p[2:])
		}
	}
	return p
}

func (a *agent) handleReadFile(msg proto.Message) {
	var req proto.ReadFileReq
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		_ = a.sendResp(msg.ID, msg.Action, false, "bad payload: "+err.Error(), nil)
		return
	}
	p, err := a.resolveScoped(expandPath(req.Path))
	if err != nil {
		a.stats.addReject()
		_ = a.sendResp(msg.ID, msg.Action, false, err.Error(), nil)
		return
	}
	if req.EndLine > 0 && req.StartLine > req.EndLine {
		_ = a.sendResp(msg.ID, msg.Action, false, fmt.Sprintf("invalid line range: start=%d > end=%d", req.StartLine, req.EndLine), nil)
		return
	}
	if policy.IsSensitivePath(p) {
		if !a.askConfirm("🔐 请求读取敏感凭证路径", "  文件路径: "+sanitizeSingleLine(p), "是否允许读取该敏感文件?") {
			_ = a.sendResp(msg.ID, msg.Action, false, "rejected: sensitive file read denied by operator", nil)
			return
		}
	} else {
		a.logRO("读取文件: %s (L%d-L%d)", p, req.StartLine, req.EndLine)
	}

	fi, err := os.Stat(p)
	if err != nil {
		_ = a.sendResp(msg.ID, msg.Action, false, err.Error(), nil)
		return
	}
	if !fi.Mode().IsRegular() {
		_ = a.sendResp(msg.ID, msg.Action, false, "refused: target is not a regular file", nil)
		return
	}

	f, err := os.Open(p)
	if err != nil {
		_ = a.sendResp(msg.ID, msg.Action, false, err.Error(), nil)
		return
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, 4*1024*1024))
	if err != nil {
		_ = a.sendResp(msg.ID, msg.Action, false, err.Error(), nil)
		return
	}
	a.stats.addRead(p)
	lines := strings.Split(string(data), "\n")
	total := len(lines)
	start := req.StartLine
	if start <= 0 {
		start = 1
	}
	end := req.EndLine
	if end <= 0 || end > total {
		end = total
	}
	if start > total {
		_ = a.sendResp(msg.ID, msg.Action, true, "", proto.ReadFileResp{
			Path: p, StartLine: start, EndLine: start, TotalLines: total,
		})
		return
	}
	const maxLines = 800
	const maxBytes = 256 * 1024
	truncated := false
	if end-start+1 > maxLines {
		end = start + maxLines - 1
		truncated = true
	}
	content := strings.Join(lines[start-1:end], "\n")
	if len(content) > maxBytes {
		content = content[:maxBytes]
		truncated = true
	}
	_ = a.sendResp(msg.ID, msg.Action, true, "", proto.ReadFileResp{
		Path:       p,
		Content:    content,
		StartLine:  start,
		EndLine:    end,
		TotalLines: total,
		Truncated:  truncated,
	})
}

func (a *agent) handleListDir(msg proto.Message) {
	var req proto.ListDirReq
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		_ = a.sendResp(msg.ID, msg.Action, false, "bad payload: "+err.Error(), nil)
		return
	}
	root := expandPath(req.Path)
	if root == "" {
		root = "."
	}
	var scopeErr error
	root, scopeErr = a.resolveScoped(root)
	if scopeErr != nil {
		a.stats.addReject()
		_ = a.sendResp(msg.ID, msg.Action, false, scopeErr.Error(), nil)
		return
	}
	depth := req.Depth
	if depth <= 0 {
		depth = 1
	}
	if depth > 3 {
		depth = 3
	}
	a.logRO("列目录: %s (depth=%d)", root, depth)
	a.stats.addROQuery()

	var entries []proto.DirEntry
	truncated := false
	baseClean := filepath.Clean(root)
	err := filepath.WalkDir(baseClean, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if p == baseClean {
			return nil
		}
		rel, _ := filepath.Rel(baseClean, p)
		curDepth := strings.Count(rel, string(os.PathSeparator)) + 1
		if curDepth > depth {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		info, ierr := d.Info()
		var sz int64
		var mod, modeStr string
		if ierr == nil {
			sz = info.Size()
			modeStr = info.Mode().String()
			mod = info.ModTime().Format("2006-01-02 15:04:05")
		}
		entries = append(entries, proto.DirEntry{
			Path:    rel,
			IsDir:   d.IsDir(),
			Size:    sz,
			Mode:    modeStr,
			ModTime: mod,
		})
		if len(entries) >= 500 {
			truncated = true
			return errors.New("stop")
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "node_modules" || d.Name() == "__pycache__") {
			return filepath.SkipDir
		}
		return nil
	})
	if err != nil && err.Error() != "stop" {
		_ = a.sendResp(msg.ID, msg.Action, false, err.Error(), nil)
		return
	}
	_ = a.sendResp(msg.ID, msg.Action, true, "", proto.ListDirResp{
		Path:      baseClean,
		Entries:   entries,
		Truncated: truncated,
	})
}

func (a *agent) handleGrep(msg proto.Message) {
	var req proto.GrepReq
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		_ = a.sendResp(msg.ID, msg.Action, false, "bad payload: "+err.Error(), nil)
		return
	}
	root := expandPath(req.Path)
	if root == "" {
		root = "."
	}
	var scopeErr error
	root, scopeErr = a.resolveScoped(root)
	if scopeErr != nil {
		a.stats.addReject()
		_ = a.sendResp(msg.ID, msg.Action, false, scopeErr.Error(), nil)
		return
	}
	if policy.IsSensitivePath(root) {
		a.stats.addReject()
		_ = a.sendResp(msg.ID, msg.Action, false, "refused: grep skips sensitive credential directories", nil)
		return
	}
	maxM := req.MaxMatches
	if maxM <= 0 || maxM > 200 {
		maxM = 100
	}
	re, err := regexp.Compile(req.Pattern)
	if err != nil {
		_ = a.sendResp(msg.ID, msg.Action, false, "invalid regex: "+err.Error(), nil)
		return
	}
	a.logRO("搜索文本: %q @ %s", req.Pattern, root)
	a.stats.addROQuery()

	var matches []proto.GrepMatch
	truncated := false
	filesScanned := 0
	const maxFiles = 5000

	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if rp, serr := a.resolveScoped(p); serr != nil || policy.IsSensitivePath(rp) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == "node_modules" || name == "__pycache__" || name == ".venv" {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		filesScanned++
		if filesScanned > maxFiles {
			truncated = true
			return errors.New("stop")
		}
		info, err := d.Info()
		if err != nil || info.Size() > 2*1024*1024 {
			return nil
		}
		f, err := os.Open(p)
		if err != nil {
			return nil
		}
		data, rerr := io.ReadAll(io.LimitReader(f, 2*1024*1024))
		_ = f.Close()
		if rerr != nil {
			return nil
		}
		chk := data
		if len(chk) > 512 {
			chk = chk[:512]
		}
		if bytes.IndexByte(chk, 0) >= 0 {
			return nil
		}
		for idx, line := range strings.Split(string(data), "\n") {
			if re.MatchString(line) {
				if len(line) > 300 {
					line = line[:300] + "..."
				}
				matches = append(matches, proto.GrepMatch{File: p, Line: idx + 1, Text: line})
				if len(matches) >= maxM {
					truncated = true
					return errors.New("stop")
				}
			}
		}
		return nil
	})
	_ = a.sendResp(msg.ID, msg.Action, true, "", proto.GrepResp{
		Matches:   matches,
		Truncated: truncated,
	})
}

func (a *agent) handleExec(msg proto.Message) {
	var req proto.ExecReq
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		_ = a.sendResp(msg.ID, msg.Action, false, "bad payload: "+err.Error(), nil)
		return
	}
	cwd := expandPath(req.Cwd)
	if cwd == "" {
		cwd, _ = os.Getwd()
	}
	if a.mode == "ro" {
		a.stats.addReject()
		_ = a.sendResp(msg.ID, msg.Action, true, "", proto.ExecResp{
			Command: req.Command, Cwd: cwd, ReadOnly: false, Approved: false,
			Stderr: "rejected: generic exec disabled in read-only mode (use sysinfo/ls/read/grep)", ExitCode: -1,
		})
		return
	}
	// In strictly directory-scoped mode ([3]), disable generic shell exec so commands cannot access outside rootScope.
	if a.rootScope != "" {
		a.stats.addReject()
		_ = a.sendResp(msg.ID, msg.Action, true, "", proto.ExecResp{
			Command: req.Command, Cwd: cwd, ReadOnly: false, Approved: false,
			Stderr: "rejected: generic shell exec disabled in directory-scoped mode (only file/dir ops inside approved dir are permitted)", ExitCode: -1,
		})
		return
	}

	timeout := time.Duration(req.TimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	if timeout > 600*time.Second {
		timeout = 600 * time.Second
	}

	ro, resolvedBin, argv := policy.ClassifyCommand(req.Command)
	if ro {
		a.logRO("执行查询命令: %s (目录: %s)", req.Command, cwd)
		a.stats.addROQuery()
	} else {
		body := fmt.Sprintf("  工作目录: %s\n  命令内容: %s%s%s", sanitizeSingleLine(cwd), ansiBold, sanitizeTTY(req.Command), ansiReset)
		if !a.askConfirm("⚠️  请求执行命令", body, "是否允许在本机执行?") {
			_ = a.sendResp(msg.ID, msg.Action, true, "", proto.ExecResp{
				Command: req.Command, Cwd: cwd, ReadOnly: false, Approved: false,
				Stderr: "rejected by operator on target machine", ExitCode: -1,
			})
			return
		}
		a.stats.addApprovedExec()
	}

	ctx, cancel := context.WithTimeout(a.ctx, timeout)
	defer cancel()

	var cmd *exec.Cmd
	if ro {
		cmd = exec.CommandContext(ctx, resolvedBin, argv[1:]...)
	} else {
		cmd = shellExecCommand(ctx, req.Command)
	}
	cmd.Dir = cwd
	var outBuf, errBuf limitedBuffer
	outBuf.limit = 512 * 1024
	errBuf.limit = 512 * 1024
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	err := cmd.Run()
	exitCode := 0
	timedOut := errors.Is(ctx.Err(), context.DeadlineExceeded)
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			exitCode = ee.ExitCode()
		} else {
			exitCode = -1
			if errBuf.buf.Len() == 0 {
				errBuf.buf.WriteString(err.Error())
			}
		}
	}
	_ = a.sendResp(msg.ID, msg.Action, true, "", proto.ExecResp{
		Command:  req.Command,
		Cwd:      cwd,
		Stdout:   outBuf.buf.String(),
		Stderr:   errBuf.buf.String(),
		ExitCode: exitCode,
		ReadOnly: ro,
		Approved: true,
		TimedOut: timedOut,
	})
}

func atomicWriteFile(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".guest-write-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func (a *agent) handleEditFile(msg proto.Message) {
	var req proto.EditFileReq
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		_ = a.sendResp(msg.ID, msg.Action, false, "bad payload: "+err.Error(), nil)
		return
	}
	rawPath := expandPath(req.Path)
	if a.mode == "ro" {
		a.stats.addReject()
		_ = a.sendResp(msg.ID, msg.Action, true, "", proto.ModifyFileResp{Path: rawPath, Approved: false})
		return
	}
	// Reject direct symlink before resolving, then verify canonical scoped path.
	if lfi0, err := os.Lstat(rawPath); err == nil && (lfi0.Mode()&os.ModeSymlink != 0 || !lfi0.Mode().IsRegular()) {
		_ = a.sendResp(msg.ID, msg.Action, false, "refused: target is a symlink or non-regular file", nil)
		return
	}
	p, err := a.resolveScoped(rawPath)
	if err != nil {
		a.stats.addReject()
		_ = a.sendResp(msg.ID, msg.Action, false, err.Error(), nil)
		return
	}

	lfi, err := os.Lstat(p)
	if err != nil {
		_ = a.sendResp(msg.ID, msg.Action, false, err.Error(), nil)
		return
	}
	if lfi.Mode()&os.ModeSymlink != 0 || !lfi.Mode().IsRegular() {
		_ = a.sendResp(msg.ID, msg.Action, false, "refused: target is a symlink or non-regular file", nil)
		return
	}
	if lfi.Size() > maxEditFileBytes {
		_ = a.sendResp(msg.ID, msg.Action, false, fmt.Sprintf("refused: file exceeds %d bytes", maxEditFileBytes), nil)
		return
	}

	oldBytes, err := os.ReadFile(p)
	if err != nil {
		_ = a.sendResp(msg.ID, msg.Action, false, err.Error(), nil)
		return
	}
	preHash := sha256.Sum256(oldBytes)
	oldText := string(oldBytes)
	count := strings.Count(oldText, req.OldText)
	if req.OldText == "" || count == 0 {
		_ = a.sendResp(msg.ID, msg.Action, false, "target old_text not found in "+p, nil)
		return
	}
	if !req.ReplaceAll && count > 1 {
		_ = a.sendResp(msg.ID, msg.Action, false, fmt.Sprintf("old_text matched %d times; specify more context or --all", count), nil)
		return
	}

	reps := 1
	if req.ReplaceAll {
		reps = count
	}
	// Check resulting size BEFORE allocating replaced string or computing diff (prevents ReplaceAll OOM).
	projectedSize := int64(len(oldText)) + int64(reps)*int64(len(req.NewText)-len(req.OldText))
	if projectedSize > maxEditFileBytes {
		_ = a.sendResp(msg.ID, msg.Action, false, fmt.Sprintf("refused: edited content (%d bytes) would exceed %d bytes", projectedSize, maxEditFileBytes), nil)
		return
	}

	var newText string
	if req.ReplaceAll {
		newText = strings.ReplaceAll(oldText, req.OldText, req.NewText)
	} else {
		newText = strings.Replace(oldText, req.OldText, req.NewText, 1)
	}

	uDiff := diff.Unified(p, oldText, newText)
	if uDiff == "" {
		_ = a.sendResp(msg.ID, msg.Action, false, "no effective change", nil)
		return
	}

	safePreview := diff.Colorize(sanitizeTTY(uDiff))
	header := fmt.Sprintf("✏️  请求修改文件: %s (%d 处替换)", p, reps)
	if !a.askConfirm(header, safePreview, "是否允许写入以上修改?") {
		_ = a.sendResp(msg.ID, msg.Action, true, "", proto.ModifyFileResp{
			Path:     p,
			Approved: false,
		})
		return
	}

	curLfi, err := os.Lstat(p)
	if err != nil || curLfi.Mode()&os.ModeSymlink != 0 || !curLfi.Mode().IsRegular() {
		_ = a.sendResp(msg.ID, msg.Action, false, "aborted: target file changed type during confirmation", nil)
		return
	}
	curBytes, err := os.ReadFile(p)
	if err != nil || sha256.Sum256(curBytes) != preHash {
		_ = a.sendResp(msg.ID, msg.Action, false, "aborted: target file modified concurrently during confirmation", nil)
		return
	}

	if err := atomicWriteFile(p, []byte(newText), curLfi.Mode().Perm()); err != nil {
		_ = a.sendResp(msg.ID, msg.Action, false, "atomic write failed: "+err.Error(), nil)
		return
	}
	a.stats.addEdit(p)
	before := oldText
	if len(before) > 1024*1024 {
		before = before[:1024*1024] + "\n...[truncated]..."
	}
	_ = a.sendResp(msg.ID, msg.Action, true, "", proto.ModifyFileResp{
		Path:          p,
		Diff:          uDiff,
		BeforeContent: before,
		Approved:      true,
		BytesWritten:  len(newText),
		Replacements:  reps,
	})
}

func (a *agent) handleWriteFile(msg proto.Message) {
	var req proto.WriteFileReq
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		_ = a.sendResp(msg.ID, msg.Action, false, "bad payload: "+err.Error(), nil)
		return
	}
	rawPath := expandPath(req.Path)
	if a.mode == "ro" {
		a.stats.addReject()
		_ = a.sendResp(msg.ID, msg.Action, true, "", proto.ModifyFileResp{Path: rawPath, Approved: false})
		return
	}
	if lfi0, err := os.Lstat(rawPath); err == nil && (lfi0.Mode()&os.ModeSymlink != 0 || !lfi0.Mode().IsRegular()) {
		_ = a.sendResp(msg.ID, msg.Action, false, "refused: target is a symlink or non-regular file", nil)
		return
	}
	p, err := a.resolveScoped(rawPath)
	if err != nil {
		a.stats.addReject()
		_ = a.sendResp(msg.ID, msg.Action, false, err.Error(), nil)
		return
	}
	if len(req.Content) > maxEditFileBytes {
		_ = a.sendResp(msg.ID, msg.Action, false, fmt.Sprintf("refused: content exceeds %d bytes", maxEditFileBytes), nil)
		return
	}

	var oldText string
	var preHash [32]byte
	created := false
	mode := os.FileMode(0600)

	lfi, err := os.Lstat(p)
	if os.IsNotExist(err) {
		created = true
	} else if err != nil {
		_ = a.sendResp(msg.ID, msg.Action, false, "stat failed: "+err.Error(), nil)
		return
	} else {
		if lfi.Mode()&os.ModeSymlink != 0 || !lfi.Mode().IsRegular() {
			_ = a.sendResp(msg.ID, msg.Action, false, "refused: target is a symlink or non-regular file", nil)
			return
		}
		if lfi.Size() > maxEditFileBytes {
			_ = a.sendResp(msg.ID, msg.Action, false, fmt.Sprintf("refused: existing file exceeds %d bytes", maxEditFileBytes), nil)
			return
		}
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			_ = a.sendResp(msg.ID, msg.Action, false, "read existing failed: "+rerr.Error(), nil)
			return
		}
		oldText = string(b)
		preHash = sha256.Sum256(b)
		mode = lfi.Mode().Perm()
	}

	uDiff := diff.Unified(p, oldText, req.Content)
	preview := diff.Colorize(sanitizeTTY(uDiff))
	if len(preview) > 12000 {
		preview = preview[:12000] + "\n... [diff 预览已截断] ...\n"
	}
	header := fmt.Sprintf("📝 请求写入文件: %s (新建=%v, 权限=%04o, %d 字节)", p, created, mode, len(req.Content))
	if !a.askConfirm(header, preview, "是否允许写入该文件?") {
		_ = a.sendResp(msg.ID, msg.Action, true, "", proto.ModifyFileResp{
			Path:     p,
			Approved: false,
			Created:  created,
		})
		return
	}

	if !created {
		curLfi, err := os.Lstat(p)
		if err != nil || curLfi.Mode()&os.ModeSymlink != 0 || !curLfi.Mode().IsRegular() {
			_ = a.sendResp(msg.ID, msg.Action, false, "aborted: target file changed type during confirmation", nil)
			return
		}
		curB, err := os.ReadFile(p)
		if err != nil || sha256.Sum256(curB) != preHash {
			_ = a.sendResp(msg.ID, msg.Action, false, "aborted: target file changed concurrently during confirmation", nil)
			return
		}
	} else {
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			_ = a.sendResp(msg.ID, msg.Action, false, err.Error(), nil)
			return
		}
	}

	if err := atomicWriteFile(p, []byte(req.Content), mode); err != nil {
		_ = a.sendResp(msg.ID, msg.Action, false, err.Error(), nil)
		return
	}
	a.stats.addEdit(p)
	before := oldText
	if len(before) > 1024*1024 {
		before = before[:1024*1024] + "\n...[truncated]..."
	}
	_ = a.sendResp(msg.ID, msg.Action, true, "", proto.ModifyFileResp{
		Path:          p,
		Diff:          uDiff,
		BeforeContent: before,
		Approved:      true,
		Created:       created,
		BytesWritten:  len(req.Content),
	})
}

func (a *agent) handleScreenshot(msg proto.Message) {
	if !a.askConfirm("📷 请求截取当前桌面屏幕", "  截图将加密回传至主控机，本机临时图片传输后立即删除。", "是否允许截屏?") {
		_ = a.sendResp(msg.ID, msg.Action, true, "", proto.ScreenshotResp{Approved: false})
		return
	}
	tmpDir, err := os.MkdirTemp("", "guest-shot-*")
	if err != nil {
		_ = a.sendResp(msg.ID, msg.Action, false, err.Error(), nil)
		return
	}
	defer os.RemoveAll(tmpDir)
	tmpPath := filepath.Join(tmpDir, "screen.png")

	ctx, cancel := context.WithTimeout(a.ctx, 15*time.Second)
	defer cancel()

	usedTool, err := capturePlatformScreenshot(ctx, tmpPath)
	if err != nil {
		_ = a.sendResp(msg.ID, msg.Action, false, err.Error(), nil)
		return
	}
	pngBytes, err := os.ReadFile(tmpPath)
	if err != nil || len(pngBytes) == 0 {
		_ = a.sendResp(msg.ID, msg.Action, false, "failed to read screenshot", nil)
		return
	}
	if len(pngBytes) > 10*1024*1024 {
		_ = a.sendResp(msg.ID, msg.Action, false, "screenshot too large (>10MB)", nil)
		return
	}
	a.stats.addScreenshot()
	_ = a.sendResp(msg.ID, msg.Action, true, "", proto.ScreenshotResp{
		PNGBase64: base64.StdEncoding.EncodeToString(pngBytes),
		Tool:      usedTool,
		Approved:  true,
	})
}

type limitedBuffer struct {
	buf   bytes.Buffer
	limit int
}

func (lb *limitedBuffer) Write(p []byte) (int, error) {
	if lb.buf.Len() < lb.limit {
		rem := lb.limit - lb.buf.Len()
		if len(p) > rem {
			lb.buf.Write(p[:rem])
			lb.buf.WriteString("\n...[output truncated]...")
		} else {
			lb.buf.Write(p)
		}
	}
	return len(p), nil
}

type bufferedConn struct {
	net.Conn
	r io.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.r.Read(p) }

func dialRelayStream(relayAddr, certPin, role, token string) (io.ReadWriteCloser, error) {
	tlsCfg, err := e2ee.PinnedTLSConfig(certPin)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: 15 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", relayAddr, tlsCfg)
	if err != nil {
		return nil, err
	}
	reqLine := fmt.Sprintf("GET /tunnel/%s/%s HTTP/1.1\r\nHost: %s\r\nUpgrade: guest-bridge\r\nConnection: Upgrade\r\n\r\n", role, token, relayAddr)
	if _, err := conn.Write([]byte(reqLine)); err != nil {
		_ = conn.Close()
		return nil, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		_ = conn.Close()
		return nil, fmt.Errorf("relay rejected tunnel: HTTP %d (口令无效或已过期)", resp.StatusCode)
	}
	for {
		b, err := br.ReadByte()
		if err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("waiting for host peer: %w", err)
		}
		if b == '.' {
			continue
		}
		if b == 'R' {
			return &bufferedConn{Conn: conn, r: br}, nil
		}
		_ = conn.Close()
		return nil, fmt.Errorf("unexpected relay byte: 0x%02x", b)
	}
}

// promptConsentMenu lets the target machine owner choose their own permission level BEFORE connecting.
func promptConsentMenu(outF *os.File, ttyLines <-chan string, defaultMode string) (mode string, rootScope string, ok bool) {
	cwd, _ := os.Getwd()
	resolvedCwd := cwd
	if ev, err := filepath.EvalSymlinks(cwd); err == nil {
		resolvedCwd = ev
	}
	defChoice := "2"
	if defaultMode == "ro" {
		defChoice = "1"
	}

	fmt.Fprintf(outF, "\n%s============================================================%s\n", ansiCyan+ansiBold, ansiReset)
	fmt.Fprintf(outF, "%s  临时远程协助准备就绪（尚未建立网络连接，未放行任何访问）%s\n", ansiBold, ansiReset)
	fmt.Fprintf(outF, "  · 免管理员权限 · 每条操作实时可见 · 随时按 %sCtrl+C%s 断开退出\n", ansiBold, ansiReset)
	fmt.Fprintf(outF, "  · 注意：连接后会将本机用户名、主机名与当前目录告知协助端用于排查\n")
	fmt.Fprintf(outF, "%s============================================================%s\n", ansiCyan+ansiBold, ansiReset)
	fmt.Fprintf(outF, "请由本机所有者选择本次授予的权限级别：\n")
	fmt.Fprintf(outF, "  %s[1]%s 纯只读诊断（仅查文件/日志，禁止一切改文件和命令执行）\n", ansiBold, ansiReset)
	fmt.Fprintf(outF, "  %s[2]%s 自由只读排查 + 逐次审批修改（改文件先看 Diff，按 y 才写；密钥路径也需确认）\n", ansiBold, ansiReset)
	fmt.Fprintf(outF, "  %s[3]%s 仅限当前目录内文件排查 + 逐次审批（锁定在 %s，禁用通用命令，越界拒绝）\n", ansiBold, ansiReset, sanitizeSingleLine(resolvedCwd))
	fmt.Fprintf(outF, "  %s[q]%s 取消并立即退出\n", ansiBold, ansiReset)

	for {
		fmt.Fprintf(outF, "%s请选择 [1/2/3/q]（直接回车默认 %s）: %s", ansiYellow+ansiBold, defChoice, ansiReset)
		line, okRead := <-ttyLines
		if !okRead {
			return "", "", false
		}
		ch := strings.ToLower(strings.TrimSpace(line))
		if ch == "" {
			ch = defChoice
		}
		switch ch {
		case "1":
			return "ro", "", true
		case "2":
			return "confirm", "", true
		case "3":
			return "confirm", resolvedCwd, true
		case "q", "quit", "exit":
			return "", "", false
		default:
			fmt.Fprintf(outF, "%s请输入 1、2、3 或 q%s\n", ansiRed, ansiReset)
		}
	}
}

func main() {
	relayAddr := flag.String("relay", "", "relay TLS address (host:port)")
	certPin := flag.String("pin", "", "relay TLS cert SHA-256 hex")
	token := flag.String("token", "", "one-time guest token (or GB_TOKEN env)")
	keyHex := flag.String("key", "", "one-time 256-bit E2EE key hex (or GB_KEY env)")
	mode := flag.String("mode", "confirm", "suggested default permission mode in local menu: confirm | ro")
	selfDelete := flag.Bool("self-delete", true, "attempt to remove temporary binary in temp dir on exit")
	flag.Parse()

	if *token == "" {
		*token = os.Getenv("GB_TOKEN")
		_ = os.Unsetenv("GB_TOKEN")
	}
	if *keyHex == "" {
		*keyHex = os.Getenv("GB_KEY")
		_ = os.Unsetenv("GB_KEY")
	}

	if *relayAddr == "" || *certPin == "" || *token == "" || *keyHex == "" {
		fmt.Fprintln(os.Stderr, "missing required flags (-relay, -pin, -token, -key)")
		selfCleanPlatform(*selfDelete)
		os.Exit(2)
	}
	psk, err := hex.DecodeString(strings.TrimSpace(*keyHex))
	if err != nil || len(psk) != 32 {
		fmt.Fprintln(os.Stderr, "invalid E2EE key")
		selfCleanPlatform(*selfDelete)
		os.Exit(2)
	}

	inF, outF, rd, hasTTY := openConfirmTTY()
	defer func() {
		if inF != nil {
			_ = inF.Close()
		}
		if outF != nil && outF != inF {
			_ = outF.Close()
		}
	}()

	// Interactive local consent menu is mandatory before any network connection is opened.
	if !hasTTY {
		fmt.Fprintln(os.Stderr, "未检测到交互式控制台，已取消连接（本工具必须由机主在交互终端亲自授权）。")
		selfCleanPlatform(*selfDelete)
		os.Exit(1)
	}
	ttyLines := startTTYReader(rd)
	chosenMode, rootScope, ok := promptConsentMenu(outF, ttyLines, *mode)
	if !ok {
		fmt.Fprintf(outF, "%s已取消协助，未建立任何网络连接。%s\n", ansiYellow, ansiReset)
		selfCleanPlatform(*selfDelete)
		os.Exit(0)
	}

	fmt.Fprintf(os.Stderr, "%s正在建立端到端加密联调会话...%s\n", ansiCyan, ansiReset)
	rawStream, err := dialRelayStream(*relayAddr, *certPin, "guest", *token)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s连接失败: %v%s\n", ansiRed, err, ansiReset)
		selfCleanPlatform(*selfDelete)
		os.Exit(1)
	}
	e2eeConn, err := e2ee.GuestHandshake(rawStream, psk)
	if err != nil {
		_ = rawStream.Close()
		fmt.Fprintf(os.Stderr, "%s端到端加密握手失败: %v%s\n", ansiRed, err, ansiReset)
		selfCleanPlatform(*selfDelete)
		os.Exit(1)
	}

	ag := newAgent(chosenMode, rootScope, e2eeConn, outF, ttyLines, hasTTY)
	if err := ag.sendHello(); err != nil {
		fmt.Fprintf(os.Stderr, "%s初始化失败: %v%s\n", ansiRed, err, ansiReset)
		_ = e2eeConn.Close()
		selfCleanPlatform(*selfDelete)
		os.Exit(1)
	}

	modeLabel := "自由只读排查（密钥路径需确认）+ 所有修改/写命令逐次 [y/N] 确认"
	if chosenMode == "ro" {
		modeLabel = "纯只读诊断（禁止一切修改与通用命令执行）"
	} else if rootScope != "" {
		modeLabel = fmt.Sprintf("仅限目录 %s 内文件排查 + 逐次 [y/N] 确认（禁用通用命令）", sanitizeSingleLine(rootScope))
	}
	fmt.Fprintf(os.Stderr, "%s✓ 已建立端到端加密联调通道！%s\n", ansiGreen+ansiBold, ansiReset)
	fmt.Fprintf(os.Stderr, "  当前权限: %s\n", modeLabel)
	fmt.Fprintf(os.Stderr, "  退出方式: 随时按 %sCtrl+C%s 断开并查看本次操作摘要\n\n", ansiBold, ansiReset)

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		select {
		case <-sigCh:
			fmt.Fprintf(os.Stderr, "\n%s[收到退出信号] 正在断开连接并汇总本次操作对账单...%s\n", ansiYellow, ansiReset)
			ag.stop()
			_ = e2eeConn.Close()
		case <-ag.ctx.Done():
		}
	}()

	err = ag.serveLoop()
	ag.stop()
	_ = e2eeConn.Close()
	if err != nil && !errors.Is(err, io.EOF) && !ag.isStopped() {
		fmt.Fprintf(os.Stderr, "\n%s[连接已断开]%s %v\n", ansiYellow, ansiReset, err)
	}
	cleaned := selfCleanPlatform(*selfDelete)
	ag.stats.printReceipt(os.Stderr, cleaned)
}
