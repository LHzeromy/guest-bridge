package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"guest-bridge/internal/policy"
	"guest-bridge/internal/proto"
)

const (
	maxTransferFileBytes = 200 * 1024 * 1024 // 200 MiB max transfer/uncompressed size for pull & push
	maxTransferChunkSize = 256 * 1024        // 256 KiB raw chunk per E2EE frame
	maxArchiveFiles      = 500               // max files per batch push/pull archive
	maxLiveExecLines     = 200               // max live console lines echoed on target terminal per command
	maxLiveLineBytes     = 512               // max UTF-8 bytes per live echoed line
)

// ---------------- LIVE CONSOLE ECHO FOR EXEC ----------------

type liveExecConsole struct {
	mu           sync.Mutex
	out          io.Writer
	maxLines     int
	maxLineBytes int
	linesPrinted int
	capped       bool
}

func newLiveExecConsole(out io.Writer) *liveExecConsole {
	if out == nil {
		out = os.Stderr
	}
	return &liveExecConsole{
		out:          out,
		maxLines:     maxLiveExecLines,
		maxLineBytes: maxLiveLineBytes,
	}
}

type liveExecStream struct {
	console       *liveExecConsole
	isErr         bool
	pending       bytes.Buffer
	pendingExcess bool
}

func (c *liveExecConsole) NewStream(isErr bool) *liveExecStream {
	return &liveExecStream{console: c, isErr: isErr}
}

func truncateUTF8Bytes(s string, maxBytes int) (string, bool) {
	if len(s) <= maxBytes {
		return s, false
	}
	// Step back to a valid UTF-8 rune boundary.
	n := maxBytes
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n], true
}

func (c *liveExecConsole) emitLineLocked(line string, isErr, alreadyExcess bool) {
	if c.capped {
		return
	}
	if c.linesPrinted >= c.maxLines {
		c.capped = true
		fmt.Fprintf(c.out, "  %s… [屏幕回显已达 %d 行上限，命令仍在继续执行，完整输出将回传主控机]%s\n", ansiDim, c.maxLines, ansiReset)
		return
	}
	c.linesPrinted++
	clipped, wasTrunc := truncateUTF8Bytes(line, c.maxLineBytes)
	safe := sanitizeSingleLine(clipped)
	if wasTrunc || alreadyExcess {
		safe += " …"
	}
	if isErr {
		fmt.Fprintf(c.out, "  %s│%s %s%s%s\n", ansiRed, ansiReset, ansiYellow, safe, ansiReset)
	} else {
		fmt.Fprintf(c.out, "  %s│%s %s\n", ansiDim+ansiCyan, ansiReset, safe)
	}
}

func (s *liveExecStream) Write(p []byte) (int, error) {
	s.console.mu.Lock()
	defer s.console.mu.Unlock()

	bufLimit := s.console.maxLineBytes + 32
	for i := 0; i < len(p); i++ {
		b := p[i]
		if b == '\n' || b == '\r' {
			// Collapse CRLF into a single break.
			if b == '\r' && i+1 < len(p) && p[i+1] == '\n' {
				i++
			}
			line := s.pending.String()
			excess := s.pendingExcess
			s.pending.Reset()
			s.pendingExcess = false
			// Skip empty bare-CR redraw lines so progress bars stay clean.
			if b == '\r' && strings.TrimSpace(line) == "" && !excess {
				continue
			}
			s.console.emitLineLocked(line, s.isErr, excess)
			continue
		}
		if s.pending.Len() < bufLimit {
			s.pending.WriteByte(b)
		} else {
			s.pendingExcess = true
		}
	}
	return len(p), nil
}

func (s *liveExecStream) Flush() {
	s.console.mu.Lock()
	defer s.console.mu.Unlock()
	if s.pending.Len() > 0 || s.pendingExcess {
		line := s.pending.String()
		excess := s.pendingExcess
		s.pending.Reset()
		s.pendingExcess = false
		s.console.emitLineLocked(line, s.isErr, excess)
	}
}

// ---------------- PATH & ARCHIVE SECURITY HELPERS ----------------

func isStrictHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func validateSingleFileName(name string) (string, error) {
	if name == "" || name == "." || name == ".." {
		return "", fmt.Errorf("invalid file name: %q", name)
	}
	if strings.ContainsAny(name, `/\:`) || strings.IndexByte(name, 0) >= 0 {
		return "", fmt.Errorf("invalid file name: %q", name)
	}
	return name, nil
}

// validateArchiveRelPath validates a POSIX relative path inside a push/pull tar archive.
func validateArchiveRelPath(rel string) (string, error) {
	if rel == "" || strings.IndexByte(rel, 0) >= 0 {
		return "", errors.New("refused: empty or NUL archive path")
	}
	if strings.Contains(rel, `\`) {
		return "", fmt.Errorf("refused: backslash in archive path %q", rel)
	}
	if strings.HasPrefix(rel, "/") || strings.HasPrefix(rel, "~") {
		return "", fmt.Errorf("refused: absolute archive path %q", rel)
	}
	if len(rel) >= 2 && rel[1] == ':' {
		return "", fmt.Errorf("refused: drive prefix in archive path %q", rel)
	}
	trimmed := strings.TrimPrefix(rel, "./")
	for _, seg := range strings.Split(trimmed, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return "", fmt.Errorf("refused: invalid path segment in %q", rel)
		}
	}
	cleaned := path.Clean(trimmed)
	if cleaned == "" || cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") || strings.HasPrefix(cleaned, "/") {
		return "", fmt.Errorf("refused: unsafe archive path %q", rel)
	}
	return cleaned, nil
}

func sanitizePushPerm(mode uint32, fallback os.FileMode) os.FileMode {
	if mode == 0 {
		return fallback
	}
	perm := os.FileMode(mode) & 0755
	perm |= 0600 // always readable/writable by owner; never SUID/SGID/sticky/group-or-world-writable
	return perm
}

// resolveScopedAllowMissing resolves p even when multiple trailing directories do not exist yet.
// It resolves the deepest existing ancestor via EvalSymlinks and enforces a.rootScope.
func (a *agent) resolveScopedAllowMissing(p string) (resolved string, existingBase string, err error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", "", fmt.Errorf("invalid path: %w", err)
	}
	abs = filepath.Clean(abs)

	var missing []string
	cur := abs
	for {
		_, lerr := os.Lstat(cur)
		if lerr == nil {
			ev, eerr := filepath.EvalSymlinks(cur)
			if eerr != nil {
				return "", "", fmt.Errorf("refused: cannot resolve %q: %w", cur, eerr)
			}
			existingBase = ev
			resolved = ev
			for i := len(missing) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, missing[i])
			}
			break
		}
		if !os.IsNotExist(lerr) {
			return "", "", fmt.Errorf("refused: stat %q failed: %w", cur, lerr)
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return "", "", fmt.Errorf("refused: cannot resolve ancestor of %q", p)
		}
		missing = append(missing, filepath.Base(cur))
		cur = parent
	}

	if a.rootScope != "" {
		rel, rerr := filepath.Rel(a.rootScope, resolved)
		if rerr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			return "", "", fmt.Errorf("refused: path %q is outside operator-approved directory %q", p, a.rootScope)
		}
		if runtime.GOOS == "windows" {
			if !strings.EqualFold(filepath.VolumeName(resolved), filepath.VolumeName(a.rootScope)) {
				return "", "", fmt.Errorf("refused: path %q is on a different volume than %q", p, a.rootScope)
			}
		}
	}
	return resolved, existingBase, nil
}

// ensureNoSymlinkBetween verifies no symlink or invalid file type exists between existingBase and dstPath.
// If leafIsDir is false, an existing leaf must be a regular file; if true, an existing leaf must be a directory.
func ensureNoSymlinkBetween(existingBase, dstPath string, leafIsDir bool) error {
	rel, err := filepath.Rel(existingBase, dstPath)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return fmt.Errorf("refused: destination %q escapes base %q", dstPath, existingBase)
	}
	// Verify existingBase itself is not a symlink.
	if fi, err := os.Lstat(existingBase); err != nil {
		return err
	} else if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refused: base path %q is a symlink", existingBase)
	}
	if rel == "." {
		fi, err := os.Lstat(existingBase)
		if err != nil {
			return err
		}
		if leafIsDir && !fi.IsDir() {
			return fmt.Errorf("refused: %q is not a directory", existingBase)
		}
		if !leafIsDir && !fi.Mode().IsRegular() {
			return fmt.Errorf("refused: %q is not a regular file", existingBase)
		}
		return nil
	}

	parts := strings.Split(rel, string(os.PathSeparator))
	cur := existingBase
	for i, part := range parts {
		cur = filepath.Join(cur, part)
		fi, err := os.Lstat(cur)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refused: symlink encountered at %q", cur)
		}
		isLeaf := i == len(parts)-1
		if !isLeaf || leafIsDir {
			if !fi.IsDir() {
				return fmt.Errorf("refused: non-directory component at %q", cur)
			}
		} else {
			if !fi.Mode().IsRegular() {
				return fmt.Errorf("refused: target %q is not a regular file", cur)
			}
		}
	}
	return nil
}

// mkdirAllNoSymlink creates dirPath inside existingBase component-by-component, refusing symlinks at every step.
func mkdirAllNoSymlink(existingBase, dirPath string) error {
	rel, err := filepath.Rel(existingBase, dirPath)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return fmt.Errorf("refused: directory %q escapes base %q", dirPath, existingBase)
	}
	if rel == "." {
		fi, err := os.Lstat(existingBase)
		if err != nil {
			return err
		}
		if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
			return fmt.Errorf("refused: base %q is not a real directory", existingBase)
		}
		return nil
	}
	cur := existingBase
	for _, part := range strings.Split(rel, string(os.PathSeparator)) {
		cur = filepath.Join(cur, part)
		fi, err := os.Lstat(cur)
		if os.IsNotExist(err) {
			if merr := os.Mkdir(cur, 0755); merr != nil && !os.IsExist(merr) {
				return merr
			}
			fi, err = os.Lstat(cur)
		}
		if err != nil {
			return err
		}
		if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
			return fmt.Errorf("refused: %q is a symlink or non-directory", cur)
		}
	}
	return nil
}

func atomicWriteFromReader(dst string, r io.Reader, expectedSize int64, mode os.FileMode) error {
	dir := filepath.Dir(dst)
	tmp, err := os.CreateTemp(dir, ".guest-push-*")
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
	n, err := io.Copy(tmp, io.LimitReader(r, expectedSize+1))
	if err != nil {
		_ = tmp.Close()
		return err
	}
	if n != expectedSize {
		_ = tmp.Close()
		return fmt.Errorf("size mismatch writing %s: expected %d got %d", dst, expectedSize, n)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// Final symlink guard right before rename.
	if lfi, lerr := os.Lstat(dst); lerr == nil && (lfi.Mode()&os.ModeSymlink != 0 || !lfi.Mode().IsRegular()) {
		return fmt.Errorf("aborted: destination %q changed to symlink or non-regular file", dst)
	}
	if err := os.Rename(tmpPath, dst); err != nil {
		return err
	}
	cleanup = false
	return nil
}

// ---------------- PUSH HANDLERS (CONTROLLER -> TARGET) ----------------

type activePush struct {
	id             string
	targetPath     string
	existingBase   string
	isArchive      bool
	expectedSize   int64
	expectedSHA256 string
	singlePerm     os.FileMode
	approvedFiles  map[string]int64
	totalRawSize   int64
	tmpFile        *os.File
	tmpPath        string
	received       int64
	hasher         hash.Hash
	lastProgressAt time.Time
}

func (a *agent) closeActivePush() {
	a.pushMu.Lock()
	defer a.pushMu.Unlock()
	if a.curPush != nil {
		if a.curPush.tmpFile != nil {
			_ = a.curPush.tmpFile.Close()
		}
		if a.curPush.tmpPath != "" {
			_ = os.Remove(a.curPush.tmpPath)
		}
		a.curPush = nil
	}
}

func (a *agent) handlePushInit(msg proto.Message) {
	var req proto.PushInitReq
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		_ = a.sendResp(msg.ID, msg.Action, false, "bad payload: "+err.Error(), nil)
		return
	}
	rawTarget := expandPath(strings.TrimSpace(req.RemotePath))
	if rawTarget == "" {
		_ = a.sendResp(msg.ID, msg.Action, false, "remote_path is required", nil)
		return
	}
	if a.mode == "ro" {
		a.stats.addReject()
		_ = a.sendResp(msg.ID, msg.Action, true, "", proto.PushInitResp{RemotePath: rawTarget, Approved: false})
		return
	}
	if req.TransferSize < 0 || req.TransferSize > maxTransferFileBytes {
		_ = a.sendResp(msg.ID, msg.Action, false, fmt.Sprintf("refused: transfer size (%d bytes) exceeds %d MB limit", req.TransferSize, maxTransferFileBytes/(1024*1024)), nil)
		return
	}
	wantSHA := strings.ToLower(strings.TrimSpace(req.SHA256))
	if !isStrictHex64(wantSHA) {
		_ = a.sendResp(msg.ID, msg.Action, false, "invalid sha256 digest", nil)
		return
	}

	if !req.IsArchive {
		a.handlePushInitSingle(msg, req, rawTarget, wantSHA)
		return
	}
	a.handlePushInitArchive(msg, req, rawTarget, wantSHA)
}

func (a *agent) handlePushInitSingle(msg proto.Message, req proto.PushInitReq, rawTarget, wantSHA string) {
	// If remote path ends with a slash or points to an existing directory, place FileName inside it.
	isDirHint := strings.HasSuffix(rawTarget, "/") || strings.HasSuffix(rawTarget, `\`)
	if !isDirHint {
		if fi, err := os.Lstat(rawTarget); err == nil && fi.IsDir() {
			isDirHint = true
		}
	}
	if isDirHint {
		fname, err := validateSingleFileName(req.FileName)
		if err != nil {
			_ = a.sendResp(msg.ID, msg.Action, false, "destination is a directory but file_name is invalid: "+err.Error(), nil)
			return
		}
		rawTarget = filepath.Join(rawTarget, fname)
	}
	if lfi0, err := os.Lstat(rawTarget); err == nil && (lfi0.Mode()&os.ModeSymlink != 0 || !lfi0.Mode().IsRegular()) {
		_ = a.sendResp(msg.ID, msg.Action, false, "refused: target is a symlink or non-regular file", nil)
		return
	}
	dst, existingBase, err := a.resolveScopedAllowMissing(rawTarget)
	if err != nil {
		a.stats.addReject()
		_ = a.sendResp(msg.ID, msg.Action, false, err.Error(), nil)
		return
	}
	if err := ensureNoSymlinkBetween(existingBase, dst, false); err != nil {
		a.stats.addReject()
		_ = a.sendResp(msg.ID, msg.Action, false, err.Error(), nil)
		return
	}

	overwrite := 0
	create := 1
	opLabel := "新建文件"
	perm := sanitizePushPerm(req.Mode, 0644)
	if fi, err := os.Lstat(dst); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
			_ = a.sendResp(msg.ID, msg.Action, false, "refused: target is a symlink or non-regular file", nil)
			return
		}
		overwrite = 1
		create = 0
		opLabel = fmt.Sprintf("覆盖已有文件（原大小 %s）", formatBytesHuman(fi.Size()))
		perm = fi.Mode().Perm()
	}

	var body strings.Builder
	fmt.Fprintf(&body, "  目标路径: %s\n", sanitizeSingleLine(dst))
	fmt.Fprintf(&body, "  操作类型: %s\n", opLabel)
	fmt.Fprintf(&body, "  文件大小: %s\n", formatBytesHuman(req.TransferSize))
	fmt.Fprintf(&body, "  校验摘要: sha256:%s…", wantSHA[:16])
	if policy.IsSensitivePath(dst) {
		fmt.Fprintf(&body, "\n  %s⚠️ 警告: 目标位于敏感系统/凭证路径！%s", ansiRed+ansiBold, ansiReset)
	}
	if !a.askConfirm("📥 请求推送文件至本机", body.String(), "是否允许接收并写入该文件?") {
		_ = a.sendResp(msg.ID, msg.Action, true, "", proto.PushInitResp{
			RemotePath: dst, Approved: false, Overwrite: overwrite, Create: create,
		})
		return
	}

	tmpF, err := os.CreateTemp("", "guest-push-file-*")
	if err != nil {
		_ = a.sendResp(msg.ID, msg.Action, false, err.Error(), nil)
		return
	}
	_ = tmpF.Chmod(0600)

	var idBytes [12]byte
	_, _ = io.ReadFull(rand.Reader, idBytes[:])
	pushID := hex.EncodeToString(idBytes[:])

	a.pushMu.Lock()
	if a.curPush != nil {
		_ = a.curPush.tmpFile.Close()
		_ = os.Remove(a.curPush.tmpPath)
	}
	a.curPush = &activePush{
		id:             pushID,
		targetPath:     dst,
		existingBase:   existingBase,
		isArchive:      false,
		expectedSize:   req.TransferSize,
		expectedSHA256: wantSHA,
		singlePerm:     perm,
		tmpFile:        tmpF,
		tmpPath:        tmpF.Name(),
		hasher:         sha256.New(),
		lastProgressAt: time.Now(),
	}
	a.pushMu.Unlock()

	_ = a.sendResp(msg.ID, msg.Action, true, "", proto.PushInitResp{
		PushID:     pushID,
		RemotePath: dst,
		Approved:   true,
		Overwrite:  overwrite,
		Create:     create,
	})
}

func (a *agent) handlePushInitArchive(msg proto.Message, req proto.PushInitReq, rawTarget, wantSHA string) {
	if len(req.Files) == 0 || len(req.Files) > maxArchiveFiles {
		_ = a.sendResp(msg.ID, msg.Action, false, fmt.Sprintf("refused: file count %d out of allowed range [1, %d]", len(req.Files), maxArchiveFiles), nil)
		return
	}
	if req.TotalRawSize < 0 || req.TotalRawSize > maxTransferFileBytes {
		_ = a.sendResp(msg.ID, msg.Action, false, fmt.Sprintf("refused: total uncompressed size (%d bytes) exceeds %d MB limit", req.TotalRawSize, maxTransferFileBytes/(1024*1024)), nil)
		return
	}

	dstDir, existingBase, err := a.resolveScopedAllowMissing(rawTarget)
	if err != nil {
		a.stats.addReject()
		_ = a.sendResp(msg.ID, msg.Action, false, err.Error(), nil)
		return
	}
	if err := ensureNoSymlinkBetween(existingBase, dstDir, true); err != nil {
		a.stats.addReject()
		_ = a.sendResp(msg.ID, msg.Action, false, err.Error(), nil)
		return
	}

	approvedFiles := make(map[string]int64, len(req.Files))
	var sumRaw int64
	overwrite := 0
	create := 0
	hasSensitive := false

	type previewRow struct {
		rel       string
		size      int64
		overwrite bool
	}
	rows := make([]previewRow, 0, len(req.Files))

	for _, item := range req.Files {
		rel, verr := validateArchiveRelPath(item.RelPath)
		if verr != nil {
			a.stats.addReject()
			_ = a.sendResp(msg.ID, msg.Action, false, verr.Error(), nil)
			return
		}
		if item.Size < 0 {
			_ = a.sendResp(msg.ID, msg.Action, false, "refused: negative file size in manifest", nil)
			return
		}
		if _, dup := approvedFiles[rel]; dup {
			_ = a.sendResp(msg.ID, msg.Action, false, "refused: duplicate manifest path: "+rel, nil)
			return
		}
		sumRaw += item.Size
		if sumRaw > maxTransferFileBytes {
			_ = a.sendResp(msg.ID, msg.Action, false, fmt.Sprintf("refused: manifest total exceeds %d MB limit", maxTransferFileBytes/(1024*1024)), nil)
			return
		}
		fullDst := filepath.Join(dstDir, filepath.FromSlash(rel))
		if _, _, serr := a.resolveScopedAllowMissing(fullDst); serr != nil {
			a.stats.addReject()
			_ = a.sendResp(msg.ID, msg.Action, false, serr.Error(), nil)
			return
		}
		if err := ensureNoSymlinkBetween(existingBase, fullDst, false); err != nil {
			a.stats.addReject()
			_ = a.sendResp(msg.ID, msg.Action, false, err.Error(), nil)
			return
		}
		if policy.IsSensitivePath(fullDst) {
			hasSensitive = true
		}
		isOver := false
		if fi, serr := os.Lstat(fullDst); serr == nil {
			if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
				_ = a.sendResp(msg.ID, msg.Action, false, fmt.Sprintf("refused: destination %q is a symlink or non-regular file", fullDst), nil)
				return
			}
			isOver = true
			overwrite++
		} else {
			create++
		}
		approvedFiles[rel] = item.Size
		rows = append(rows, previewRow{rel: rel, size: item.Size, overwrite: isOver})
	}

	sort.Slice(rows, func(i, j int) bool { return rows[i].rel < rows[j].rel })

	var body strings.Builder
	fmt.Fprintf(&body, "  目标目录: %s\n", sanitizeSingleLine(dstDir))
	fmt.Fprintf(&body, "  文件数量: 共 %d 个文件（新建 %d 个，覆盖 %d 个）\n", len(rows), create, overwrite)
	fmt.Fprintf(&body, "  数据大小: 原始 %s / 压缩传输 %s\n", formatBytesHuman(sumRaw), formatBytesHuman(req.TransferSize))
	if hasSensitive {
		fmt.Fprintf(&body, "  %s⚠️ 警告: 清单中包含敏感系统/凭证路径！%s\n", ansiRed+ansiBold, ansiReset)
	}
	fmt.Fprintf(&body, "  文件清单:\n")
	previewLimit := len(rows)
	if previewLimit > 20 {
		previewLimit = 20
	}
	for _, r := range rows[:previewLimit] {
		tag := ansiGreen + "[新建]" + ansiReset
		if r.overwrite {
			tag = ansiYellow + "[覆盖]" + ansiReset
		}
		fmt.Fprintf(&body, "    %s %s (%s)\n", tag, sanitizeSingleLine(r.rel), formatBytesHuman(r.size))
	}
	if len(rows) > previewLimit {
		fmt.Fprintf(&body, "    … 另有 %d 个文件未展开", len(rows)-previewLimit)
	}

	if !a.askConfirm("📥 请求批量推送文件至本机", strings.TrimRight(body.String(), "\n"), "是否允许一次性接收并写入以上文件?") {
		_ = a.sendResp(msg.ID, msg.Action, true, "", proto.PushInitResp{
			RemotePath: dstDir, Approved: false, Overwrite: overwrite, Create: create,
		})
		return
	}

	tmpF, err := os.CreateTemp("", "guest-push-bundle-*.tar.gz")
	if err != nil {
		_ = a.sendResp(msg.ID, msg.Action, false, err.Error(), nil)
		return
	}
	_ = tmpF.Chmod(0600)

	var idBytes [12]byte
	_, _ = io.ReadFull(rand.Reader, idBytes[:])
	pushID := hex.EncodeToString(idBytes[:])

	a.pushMu.Lock()
	if a.curPush != nil {
		_ = a.curPush.tmpFile.Close()
		_ = os.Remove(a.curPush.tmpPath)
	}
	a.curPush = &activePush{
		id:             pushID,
		targetPath:     dstDir,
		existingBase:   existingBase,
		isArchive:      true,
		expectedSize:   req.TransferSize,
		expectedSHA256: wantSHA,
		approvedFiles:  approvedFiles,
		totalRawSize:   sumRaw,
		tmpFile:        tmpF,
		tmpPath:        tmpF.Name(),
		hasher:         sha256.New(),
		lastProgressAt: time.Now(),
	}
	a.pushMu.Unlock()

	_ = a.sendResp(msg.ID, msg.Action, true, "", proto.PushInitResp{
		PushID:     pushID,
		RemotePath: dstDir,
		Approved:   true,
		Overwrite:  overwrite,
		Create:     create,
	})
}

func (a *agent) handlePushChunk(msg proto.Message) {
	var req proto.PushChunkReq
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		_ = a.sendResp(msg.ID, msg.Action, false, "bad payload: "+err.Error(), nil)
		return
	}

	a.pushMu.Lock()
	ap := a.curPush
	if ap == nil || ap.id != req.PushID {
		a.pushMu.Unlock()
		_ = a.sendResp(msg.ID, msg.Action, false, "no active push session matching push_id", nil)
		return
	}
	abortPush := func(reason string) {
		_ = ap.tmpFile.Close()
		_ = os.Remove(ap.tmpPath)
		a.curPush = nil
		a.pushMu.Unlock()
		_ = a.sendResp(msg.ID, msg.Action, false, reason, nil)
	}

	if req.Offset != ap.received {
		abortPush(fmt.Sprintf("push offset mismatch: expected %d got %d", ap.received, req.Offset))
		return
	}
	if req.DataBase64 != "" {
		raw, err := base64.StdEncoding.DecodeString(req.DataBase64)
		if err != nil {
			abortPush("invalid base64 chunk: " + err.Error())
			return
		}
		if len(raw) > maxTransferChunkSize {
			abortPush(fmt.Sprintf("chunk size %d exceeds %d limit", len(raw), maxTransferChunkSize))
			return
		}
		if ap.received+int64(len(raw)) > ap.expectedSize {
			abortPush("received bytes exceeded approved transfer_size")
			return
		}
		if _, err := ap.tmpFile.Write(raw); err != nil {
			abortPush("write temp push file: " + err.Error())
			return
		}
		_, _ = ap.hasher.Write(raw)
		ap.received += int64(len(raw))
	}

	if !req.EOF {
		if ap.expectedSize >= 512*1024 && time.Since(ap.lastProgressAt) >= time.Second {
			pct := int(ap.received * 100 / ap.expectedSize)
			fmt.Fprintf(os.Stderr, "  %s[推送接收]%s %s / %s (%d%%)\n", ansiDim, ansiReset, formatBytesHuman(ap.received), formatBytesHuman(ap.expectedSize), pct)
			ap.lastProgressAt = time.Now()
		}
		recv := ap.received
		a.pushMu.Unlock()
		_ = a.sendResp(msg.ID, msg.Action, true, "", proto.PushChunkResp{ReceivedBytes: recv})
		return
	}

	// EOF reached: detach active push and finalize.
	a.curPush = nil
	a.pushMu.Unlock()

	defer func() {
		if ap.tmpFile != nil {
			_ = ap.tmpFile.Close()
		}
		if ap.tmpPath != "" {
			_ = os.Remove(ap.tmpPath)
		}
	}()

	if ap.received != ap.expectedSize {
		_ = a.sendResp(msg.ID, msg.Action, false, fmt.Sprintf("transfer size mismatch: expected %d got %d", ap.expectedSize, ap.received), nil)
		return
	}
	actualSHA := hex.EncodeToString(ap.hasher.Sum(nil))
	if actualSHA != ap.expectedSHA256 {
		_ = a.sendResp(msg.ID, msg.Action, false, fmt.Sprintf("sha256 mismatch: expected %s got %s", ap.expectedSHA256, actualSHA), nil)
		return
	}
	if err := ap.tmpFile.Sync(); err != nil {
		_ = a.sendResp(msg.ID, msg.Action, false, "sync temp push file: "+err.Error(), nil)
		return
	}

	if !ap.isArchive {
		if _, err := ap.tmpFile.Seek(0, io.SeekStart); err != nil {
			_ = a.sendResp(msg.ID, msg.Action, false, err.Error(), nil)
			return
		}
		if err := ensureNoSymlinkBetween(ap.existingBase, ap.targetPath, false); err != nil {
			_ = a.sendResp(msg.ID, msg.Action, false, err.Error(), nil)
			return
		}
		if err := mkdirAllNoSymlink(ap.existingBase, filepath.Dir(ap.targetPath)); err != nil {
			_ = a.sendResp(msg.ID, msg.Action, false, err.Error(), nil)
			return
		}
		perm := ap.singlePerm
		if fi, serr := os.Lstat(ap.targetPath); serr == nil {
			if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
				_ = a.sendResp(msg.ID, msg.Action, false, "aborted: destination changed to symlink or non-regular file", nil)
				return
			}
			perm = fi.Mode().Perm()
		}
		if err := atomicWriteFromReader(ap.targetPath, ap.tmpFile, ap.expectedSize, perm); err != nil {
			_ = a.sendResp(msg.ID, msg.Action, false, err.Error(), nil)
			return
		}
		a.stats.addPush(ap.targetPath)
		fmt.Fprintf(os.Stderr, "%s✓ 推送写入完成:%s %s (%s, SHA-256 校验通过)\n", ansiGreen, ansiReset, sanitizeSingleLine(ap.targetPath), formatBytesHuman(ap.expectedSize))
		_ = a.sendResp(msg.ID, msg.Action, true, "", proto.PushChunkResp{
			ReceivedBytes: ap.received,
			Committed:     true,
			SHA256:        actualSHA,
			FilesWritten:  1,
			WrittenPaths:  []string{ap.targetPath},
		})
		return
	}

	writtenPaths, err := a.commitPushArchive(ap)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s✗ 批量推送校验/写入失败:%s %v\n", ansiRed, ansiReset, err)
		_ = a.sendResp(msg.ID, msg.Action, false, err.Error(), nil)
		return
	}
	a.stats.addPush(fmt.Sprintf("%s (%d个文件)", ap.targetPath, len(writtenPaths)))
	fmt.Fprintf(os.Stderr, "%s✓ 批量推送完成:%s 已写入 %d 个文件至 %s (原始 %s, SHA-256 校验通过)\n",
		ansiGreen, ansiReset, len(writtenPaths), sanitizeSingleLine(ap.targetPath), formatBytesHuman(ap.totalRawSize))
	_ = a.sendResp(msg.ID, msg.Action, true, "", proto.PushChunkResp{
		ReceivedBytes: ap.received,
		Committed:     true,
		SHA256:        actualSHA,
		FilesWritten:  len(writtenPaths),
		WrittenPaths:  writtenPaths,
	})
}

// commitPushArchive validates the entire tar.gz against the operator-approved manifest in Pass 1
// before atomically extracting every approved file in Pass 2.
func (a *agent) commitPushArchive(ap *activePush) ([]string, error) {
	// Pass 1: zero-write validation against manifest, zip-bomb limits, and symlink/scope safety.
	if _, err := ap.tmpFile.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	gz1, err := gzip.NewReader(ap.tmpFile)
	if err != nil {
		return nil, fmt.Errorf("invalid gzip archive: %w", err)
	}
	tr1 := tar.NewReader(io.LimitReader(gz1, maxTransferFileBytes+1))
	seen := make(map[string]bool, len(ap.approvedFiles))
	var totalUncompressed int64

	for {
		hdr, err := tr1.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			_ = gz1.Close()
			return nil, fmt.Errorf("invalid tar archive: %w", err)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if hdr.Name == "." || hdr.Name == "./" {
				continue
			}
			rel, verr := validateArchiveRelPath(strings.TrimSuffix(hdr.Name, "/"))
			if verr != nil {
				_ = gz1.Close()
				return nil, verr
			}
			fullDir := filepath.Join(ap.targetPath, filepath.FromSlash(rel))
			if err := ensureNoSymlinkBetween(ap.existingBase, fullDir, true); err != nil {
				_ = gz1.Close()
				return nil, err
			}
		case tar.TypeReg, tar.TypeRegA:
			rel, verr := validateArchiveRelPath(hdr.Name)
			if verr != nil {
				_ = gz1.Close()
				return nil, verr
			}
			wantSize, ok := ap.approvedFiles[rel]
			if !ok {
				_ = gz1.Close()
				return nil, fmt.Errorf("refused: archive contains unapproved file %q", rel)
			}
			if seen[rel] {
				_ = gz1.Close()
				return nil, fmt.Errorf("refused: duplicate file %q in archive", rel)
			}
			if hdr.Size != wantSize {
				_ = gz1.Close()
				return nil, fmt.Errorf("refused: file %q size mismatch (manifest=%d archive=%d)", rel, wantSize, hdr.Size)
			}
			totalUncompressed += hdr.Size
			if totalUncompressed > maxTransferFileBytes {
				_ = gz1.Close()
				return nil, fmt.Errorf("refused: uncompressed archive exceeds %d MB limit", maxTransferFileBytes/(1024*1024))
			}
			fullDst := filepath.Join(ap.targetPath, filepath.FromSlash(rel))
			if _, _, serr := a.resolveScopedAllowMissing(fullDst); serr != nil {
				_ = gz1.Close()
				return nil, serr
			}
			if err := ensureNoSymlinkBetween(ap.existingBase, fullDst, false); err != nil {
				_ = gz1.Close()
				return nil, err
			}
			n, cerr := io.Copy(io.Discard, io.LimitReader(tr1, wantSize+1))
			if cerr != nil {
				_ = gz1.Close()
				return nil, fmt.Errorf("corrupted archive entry %q: %w", rel, cerr)
			}
			if n != wantSize {
				_ = gz1.Close()
				return nil, fmt.Errorf("truncated archive entry %q: expected %d got %d", rel, wantSize, n)
			}
			seen[rel] = true
		default:
			_ = gz1.Close()
			return nil, fmt.Errorf("refused: unsupported tar entry type %q for %q (symlinks/hardlinks/devices are forbidden)", string(hdr.Typeflag), hdr.Name)
		}
	}
	if err := gz1.Close(); err != nil {
		return nil, fmt.Errorf("gzip integrity check failed: %w", err)
	}
	if len(seen) != len(ap.approvedFiles) {
		return nil, fmt.Errorf("refused: archive missing %d approved file(s)", len(ap.approvedFiles)-len(seen))
	}

	// Pass 2: create destination directories and atomically extract every verified file.
	if err := mkdirAllNoSymlink(ap.existingBase, ap.targetPath); err != nil {
		return nil, err
	}
	if _, err := ap.tmpFile.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	gz2, err := gzip.NewReader(ap.tmpFile)
	if err != nil {
		return nil, err
	}
	defer gz2.Close()
	tr2 := tar.NewReader(io.LimitReader(gz2, maxTransferFileBytes+1))

	written := make([]string, 0, len(ap.approvedFiles))
	for {
		hdr, err := tr2.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return written, err
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			continue
		}
		rel, err := validateArchiveRelPath(hdr.Name)
		if err != nil {
			return written, err
		}
		dst := filepath.Join(ap.targetPath, filepath.FromSlash(rel))
		if err := mkdirAllNoSymlink(ap.existingBase, filepath.Dir(dst)); err != nil {
			return written, err
		}
		perm := sanitizePushPerm(uint32(hdr.Mode), 0644)
		if fi, serr := os.Lstat(dst); serr == nil {
			if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
				return written, fmt.Errorf("aborted: %q changed to symlink or non-regular file", dst)
			}
			perm = fi.Mode().Perm()
		}
		if err := atomicWriteFromReader(dst, tr2, hdr.Size, perm); err != nil {
			return written, err
		}
		written = append(written, dst)
	}
	sort.Strings(written)
	return written, nil
}

// ---------------- DIRECTORY PULL HELPER (TARGET -> CONTROLLER) ----------------

func (a *agent) handlePullDirInit(msg proto.Message, dirPath string) {
	if policy.IsSensitivePath(dirPath) {
		a.stats.addReject()
		_ = a.sendResp(msg.ID, msg.Action, false, "refused: directory pull skips sensitive credential paths", nil)
		return
	}

	type pullItem struct {
		absPath string
		relPath string
		size    int64
		mode    os.FileMode
		modTime time.Time
	}
	var items []pullItem
	var totalRaw int64
	skippedSymlinks := 0
	skippedSensitive := 0

	walkErr := filepath.WalkDir(dirPath, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if p == dirPath {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			skippedSymlinks++
			return nil
		}
		rp, serr := a.resolveScoped(p)
		if serr != nil || policy.IsSensitivePath(rp) {
			skippedSensitive++
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == "__pycache__" || name == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			return nil
		}
		if len(items) >= maxArchiveFiles {
			return fmt.Errorf("refused: directory exceeds %d file limit (specify a subdirectory or single file)", maxArchiveFiles)
		}
		totalRaw += info.Size()
		if totalRaw > maxTransferFileBytes {
			return fmt.Errorf("refused: directory total exceeds %d MB limit", maxTransferFileBytes/(1024*1024))
		}
		rel, rerr := filepath.Rel(dirPath, p)
		if rerr != nil {
			return rerr
		}
		items = append(items, pullItem{
			absPath: p,
			relPath: filepath.ToSlash(rel),
			size:    info.Size(),
			mode:    info.Mode().Perm(),
			modTime: info.ModTime(),
		})
		return nil
	})
	if walkErr != nil {
		_ = a.sendResp(msg.ID, msg.Action, false, walkErr.Error(), nil)
		return
	}
	if len(items) == 0 {
		_ = a.sendResp(msg.ID, msg.Action, false, "refused: directory contains no transferable regular files", nil)
		return
	}
	sort.Slice(items, func(i, j int) bool { return items[i].relPath < items[j].relPath })

	var body strings.Builder
	fmt.Fprintf(&body, "  目标目录: %s\n", sanitizeSingleLine(dirPath))
	fmt.Fprintf(&body, "  文件数量: 共 %d 个文件（原始大小 %s，将打包为 .tar.gz 加密回传）\n", len(items), formatBytesHuman(totalRaw))
	if skippedSymlinks > 0 || skippedSensitive > 0 {
		fmt.Fprintf(&body, "  安全跳过: 符号链接 %d 个，敏感路径 %d 个\n", skippedSymlinks, skippedSensitive)
	}
	fmt.Fprintf(&body, "  文件预览:\n")
	previewLimit := len(items)
	if previewLimit > 15 {
		previewLimit = 15
	}
	for _, it := range items[:previewLimit] {
		fmt.Fprintf(&body, "    - %s (%s)\n", sanitizeSingleLine(it.relPath), formatBytesHuman(it.size))
	}
	if len(items) > previewLimit {
		fmt.Fprintf(&body, "    … 另有 %d 个文件未展开\n", len(items)-previewLimit)
	}
	fmt.Fprintf(&body, "  说明: 仅端到端加密回传至主控机，不会修改或删除本机原文件")

	if !a.askConfirm("📦 请求打包回传目录至主控机", body.String(), "是否允许打包回传该目录?") {
		_ = a.sendResp(msg.ID, msg.Action, true, "", proto.PullInitResp{
			Path: dirPath, Size: totalRaw, Approved: false, IsArchive: true, FileCount: len(items),
		})
		return
	}

	tmpF, err := os.CreateTemp("", "guest-pull-dir-*.tar.gz")
	if err != nil {
		_ = a.sendResp(msg.ID, msg.Action, false, err.Error(), nil)
		return
	}
	tmpPath := tmpF.Name()
	_ = tmpF.Chmod(0600)
	cleanupTmp := true
	defer func() {
		if cleanupTmp {
			_ = tmpF.Close()
			_ = os.Remove(tmpPath)
		}
	}()

	gzw := gzip.NewWriter(tmpF)
	tw := tar.NewWriter(gzw)
	packedCount := 0
	var packedRaw int64
	for _, it := range items {
		lfi, lerr := os.Lstat(it.absPath)
		if lerr != nil || lfi.Mode()&os.ModeSymlink != 0 || !lfi.Mode().IsRegular() {
			continue
		}
		if _, serr := a.resolveScoped(it.absPath); serr != nil {
			continue
		}
		if packedRaw+lfi.Size() > maxTransferFileBytes {
			_ = tw.Close()
			_ = gzw.Close()
			_ = a.sendResp(msg.ID, msg.Action, false, "aborted: directory grew beyond size limit while packing", nil)
			return
		}
		src, oerr := os.Open(it.absPath)
		if oerr != nil {
			continue
		}
		fi2, ferr := src.Stat()
		if ferr != nil || !os.SameFile(lfi, fi2) || !fi2.Mode().IsRegular() {
			_ = src.Close()
			continue
		}
		if packedRaw+fi2.Size() > maxTransferFileBytes {
			_ = src.Close()
			_ = tw.Close()
			_ = gzw.Close()
			_ = a.sendResp(msg.ID, msg.Action, false, "aborted: directory grew beyond size limit while packing", nil)
			return
		}
		hdr := &tar.Header{
			Name:    it.relPath,
			Size:    fi2.Size(),
			Mode:    int64(fi2.Mode().Perm()),
			ModTime: fi2.ModTime(),
		}
		if werr := tw.WriteHeader(hdr); werr != nil {
			_ = src.Close()
			_ = tw.Close()
			_ = gzw.Close()
			_ = a.sendResp(msg.ID, msg.Action, false, werr.Error(), nil)
			return
		}
		n, cerr := io.Copy(tw, io.LimitReader(src, fi2.Size()))
		_ = src.Close()
		if cerr != nil || n != fi2.Size() {
			_ = tw.Close()
			_ = gzw.Close()
			_ = a.sendResp(msg.ID, msg.Action, false, "aborted: file modified while packing: "+it.relPath, nil)
			return
		}
		packedRaw += n
		packedCount++
	}
	if err := tw.Close(); err != nil {
		_ = gzw.Close()
		_ = a.sendResp(msg.ID, msg.Action, false, err.Error(), nil)
		return
	}
	if err := gzw.Close(); err != nil {
		_ = a.sendResp(msg.ID, msg.Action, false, err.Error(), nil)
		return
	}
	fi, err := tmpF.Stat()
	if err != nil || fi.Size() > maxTransferFileBytes {
		_ = a.sendResp(msg.ID, msg.Action, false, "aborted: packed archive exceeds transfer size limit", nil)
		return
	}
	if _, err := tmpF.Seek(0, io.SeekStart); err != nil {
		_ = a.sendResp(msg.ID, msg.Action, false, err.Error(), nil)
		return
	}

	var idBytes [12]byte
	_, _ = io.ReadFull(rand.Reader, idBytes[:])
	pullID := hex.EncodeToString(idBytes[:])

	a.pullMu.Lock()
	if a.curPull != nil {
		_ = a.curPull.file.Close()
		if a.curPull.removeOnClose && a.curPull.tmpPath != "" {
			_ = os.Remove(a.curPull.tmpPath)
		}
	}
	a.curPull = &activePull{
		id:            pullID,
		path:          dirPath,
		file:          tmpF,
		tmpPath:       tmpPath,
		removeOnClose: true,
		size:          fi.Size(),
		offset:        0,
		hasher:        sha256.New(),
	}
	a.pullMu.Unlock()
	cleanupTmp = false

	a.stats.addPull(fmt.Sprintf("%s (%d个文件)", dirPath, packedCount))
	_ = a.sendResp(msg.ID, msg.Action, true, "", proto.PullInitResp{
		PullID:    pullID,
		Path:      dirPath,
		Size:      fi.Size(),
		Approved:  true,
		IsArchive: true,
		FileCount: packedCount,
	})
}
