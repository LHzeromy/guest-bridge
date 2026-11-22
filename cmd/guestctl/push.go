package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"guest-bridge/internal/proto"
)

const (
	maxTransferBytes        = 200 * 1024 * 1024 // 200 MiB
	maxTransferChunkBytes   = 256 * 1024        // 256 KiB
	maxTransferArchiveFiles = 500
)

var defaultPushExcludeNames = map[string]bool{
	".git":          true,
	"__pycache__":   true,
	"node_modules":  true,
	".venv":         true,
	"venv":          true,
	".DS_Store":     true,
	".mypy_cache":   true,
	".pytest_cache": true,
}

var defaultPushExcludeGlobs = []string{"*.pyc", "*.pyo"}

type multiStringFlag []string

func (m *multiStringFlag) String() string { return strings.Join(*m, ",") }
func (m *multiStringFlag) Set(v string) error {
	for _, part := range strings.Split(v, ",") {
		p := strings.TrimSpace(part)
		if p != "" {
			*m = append(*m, p)
		}
	}
	return nil
}

func matchesPushExclude(relPOSIX, name string, isDir bool, custom []string, noDefaults bool) bool {
	if !noDefaults {
		if defaultPushExcludeNames[name] {
			return true
		}
		if !isDir {
			for _, g := range defaultPushExcludeGlobs {
				if ok, _ := path.Match(g, name); ok {
					return true
				}
			}
		}
	}
	for _, pat := range custom {
		if pat == name || pat == relPOSIX {
			return true
		}
		if ok, _ := path.Match(pat, name); ok {
			return true
		}
		if ok, _ := path.Match(pat, relPOSIX); ok {
			return true
		}
	}
	return false
}

type pushBundleResult struct {
	bundlePath      string
	manifest        []proto.PushManifestItem
	transferSize    int64
	totalRawSize    int64
	sha256Hex       string
	skippedSymlinks int
}

func buildPushBundle(sources []string, customExcludes []string, noDefaults bool) (*pushBundleResult, error) {
	if len(sources) == 0 {
		return nil, errors.New("at least one local source path is required")
	}

	type entry struct {
		absPath string
		relPath string
		size    int64
		mode    os.FileMode
		modTime time.Time
	}
	var entries []entry
	seenRel := make(map[string]bool)
	var totalRaw int64
	skippedSymlinks := 0

	addRegular := func(absPath, relPOSIX string, info os.FileInfo) error {
		relPOSIX = path.Clean(strings.TrimPrefix(relPOSIX, "./"))
		if relPOSIX == "" || relPOSIX == "." || relPOSIX == ".." || strings.HasPrefix(relPOSIX, "../") || strings.HasPrefix(relPOSIX, "/") {
			return fmt.Errorf("invalid relative path %q", relPOSIX)
		}
		if seenRel[relPOSIX] {
			return fmt.Errorf("duplicate target relative path %q (rename or push separately)", relPOSIX)
		}
		if len(entries) >= maxTransferArchiveFiles {
			return fmt.Errorf("file count exceeds %d limit (use --exclude or split into batches)", maxTransferArchiveFiles)
		}
		totalRaw += info.Size()
		if totalRaw > maxTransferBytes {
			return fmt.Errorf("total size exceeds %d MB limit", maxTransferBytes/(1024*1024))
		}
		seenRel[relPOSIX] = true
		entries = append(entries, entry{
			absPath: absPath,
			relPath: relPOSIX,
			size:    info.Size(),
			mode:    info.Mode().Perm(),
			modTime: info.ModTime(),
		})
		return nil
	}

	singleDirMode := false
	if len(sources) == 1 {
		fi, err := os.Stat(sources[0])
		if err != nil {
			return nil, err
		}
		singleDirMode = fi.IsDir()
	}

	for _, src := range sources {
		fi, err := os.Stat(src)
		if err != nil {
			return nil, err
		}
		if fi.Mode().IsRegular() {
			if err := addRegular(src, filepath.Base(src), fi); err != nil {
				return nil, err
			}
			continue
		}
		if !fi.IsDir() {
			return nil, fmt.Errorf("unsupported local source type: %s", src)
		}
		rootClean := filepath.Clean(src)
		prefix := ""
		if !singleDirMode {
			prefix = filepath.Base(rootClean)
		}
		err = filepath.WalkDir(rootClean, func(p string, d fs.DirEntry, werr error) error {
			if werr != nil {
				return werr
			}
			if p == rootClean {
				return nil
			}
			if d.Type()&os.ModeSymlink != 0 {
				skippedSymlinks++
				return nil
			}
			rel, rerr := filepath.Rel(rootClean, p)
			if rerr != nil {
				return rerr
			}
			relPOSIX := filepath.ToSlash(rel)
			if prefix != "" {
				relPOSIX = prefix + "/" + relPOSIX
			}
			if matchesPushExclude(relPOSIX, d.Name(), d.IsDir(), customExcludes, noDefaults) {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if d.IsDir() {
				return nil
			}
			if !d.Type().IsRegular() {
				return nil
			}
			info, ierr := d.Info()
			if ierr != nil {
				return ierr
			}
			return addRegular(p, relPOSIX, info)
		})
		if err != nil {
			return nil, err
		}
	}

	if len(entries) == 0 {
		return nil, errors.New("no regular files matched to push")
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].relPath < entries[j].relPath })

	tmpF, err := os.CreateTemp("", "guestctl-push-*.tar.gz")
	if err != nil {
		return nil, err
	}
	tmpPath := tmpF.Name()
	_ = tmpF.Chmod(0600)
	cleanup := true
	defer func() {
		if cleanup {
			_ = tmpF.Close()
			_ = os.Remove(tmpPath)
		}
	}()

	hasher := sha256.New()
	mw := io.MultiWriter(tmpF, hasher)
	gzw := gzip.NewWriter(mw)
	tw := tar.NewWriter(gzw)

	manifest := make([]proto.PushManifestItem, 0, len(entries))
	for _, e := range entries {
		f, err := os.Open(e.absPath)
		if err != nil {
			_ = tw.Close()
			_ = gzw.Close()
			return nil, err
		}
		fi, err := f.Stat()
		if err != nil || !fi.Mode().IsRegular() {
			_ = f.Close()
			_ = tw.Close()
			_ = gzw.Close()
			return nil, fmt.Errorf("local source changed during pack: %s", e.absPath)
		}
		hdr := &tar.Header{
			Name:    e.relPath,
			Size:    fi.Size(),
			Mode:    int64(fi.Mode().Perm()),
			ModTime: fi.ModTime(),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			_ = f.Close()
			_ = tw.Close()
			_ = gzw.Close()
			return nil, err
		}
		n, err := io.Copy(tw, io.LimitReader(f, fi.Size()))
		_ = f.Close()
		if err != nil || n != fi.Size() {
			_ = tw.Close()
			_ = gzw.Close()
			return nil, fmt.Errorf("local source modified while packing: %s", e.absPath)
		}
		manifest = append(manifest, proto.PushManifestItem{
			RelPath: e.relPath,
			Size:    fi.Size(),
			Mode:    uint32(fi.Mode().Perm()),
		})
	}
	if err := tw.Close(); err != nil {
		_ = gzw.Close()
		return nil, err
	}
	if err := gzw.Close(); err != nil {
		return nil, err
	}
	st, err := tmpF.Stat()
	if err != nil {
		return nil, err
	}
	if err := tmpF.Close(); err != nil {
		return nil, err
	}
	if st.Size() > maxTransferBytes {
		return nil, fmt.Errorf("compressed archive (%d bytes) exceeds %d MB limit", st.Size(), maxTransferBytes/(1024*1024))
	}

	cleanup = false
	return &pushBundleResult{
		bundlePath:      tmpPath,
		manifest:        manifest,
		transferSize:    st.Size(),
		totalRawSize:    totalRaw,
		sha256Hex:       hex.EncodeToString(hasher.Sum(nil)),
		skippedSymlinks: skippedSymlinks,
	}, nil
}

func sha256File(p string) (string, int64, os.FileMode, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", 0, 0, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return "", 0, 0, err
	}
	if !fi.Mode().IsRegular() {
		return "", 0, 0, fmt.Errorf("not a regular file: %s", p)
	}
	if fi.Size() > maxTransferBytes {
		return "", 0, 0, fmt.Errorf("file exceeds %d MB limit", maxTransferBytes/(1024*1024))
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, fi.Size()+1))
	if err != nil {
		return "", 0, 0, err
	}
	if n != fi.Size() {
		return "", 0, 0, fmt.Errorf("file size changed while hashing: %s", p)
	}
	return hex.EncodeToString(h.Sum(nil)), fi.Size(), fi.Mode().Perm(), nil
}

type localPushReq struct {
	LocalPaths        []string `json:"local_paths"`
	RemotePath        string   `json:"remote_path"`
	Excludes          []string `json:"excludes,omitempty"`
	NoDefaultExcludes bool     `json:"no_default_excludes,omitempty"`
}

func (d *bridgeDaemon) handleLocalPush(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	r.Body = http.MaxBytesReader(w, r.Body, 256*1024)
	var req localPushReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.LocalPaths) == 0 || strings.TrimSpace(req.RemotePath) == "" {
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "local_paths and remote_path are required"})
		return
	}

	isSingleFile := false
	if len(req.LocalPaths) == 1 {
		fi, err := os.Stat(req.LocalPaths[0])
		if err != nil {
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
			return
		}
		isSingleFile = fi.Mode().IsRegular()
	}

	var (
		streamFilePath  string
		cleanupBundle   string
		initReq         proto.PushInitReq
		rawBytes        int64
		skippedSymlinks int
	)
	defer func() {
		if cleanupBundle != "" {
			_ = os.Remove(cleanupBundle)
		}
	}()

	if isSingleFile {
		src := req.LocalPaths[0]
		shaHex, sz, mode, err := sha256File(src)
		if err != nil {
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
			return
		}
		streamFilePath = src
		rawBytes = sz
		initReq = proto.PushInitReq{
			RemotePath:   req.RemotePath,
			IsArchive:    false,
			FileName:     filepath.Base(src),
			TransferSize: sz,
			TotalRawSize: sz,
			SHA256:       shaHex,
			Mode:         uint32(mode),
		}
	} else {
		bundle, err := buildPushBundle(req.LocalPaths, req.Excludes, req.NoDefaultExcludes)
		if err != nil {
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
			return
		}
		cleanupBundle = bundle.bundlePath
		streamFilePath = bundle.bundlePath
		rawBytes = bundle.totalRawSize
		skippedSymlinks = bundle.skippedSymlinks
		initReq = proto.PushInitReq{
			RemotePath:   req.RemotePath,
			IsArchive:    true,
			TransferSize: bundle.transferSize,
			TotalRawSize: bundle.totalRawSize,
			SHA256:       bundle.sha256Hex,
			Files:        bundle.manifest,
		}
	}

	initMsg, err := d.sendRPC("push_init", initReq, 5*time.Minute)
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
		return
	}
	if !initMsg.OK {
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": initMsg.Error})
		return
	}
	var pr proto.PushInitResp
	if err := json.Unmarshal(initMsg.Payload, &pr); err != nil {
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "invalid push_init response"})
		return
	}
	if !pr.Approved {
		d.writeAudit(map[string]any{
			"action":      "push",
			"is_archive":  initReq.IsArchive,
			"remote_path": pr.RemotePath,
			"approved":    false,
		})
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":          true,
			"approved":    false,
			"remote_path": pr.RemotePath,
		})
		return
	}

	f, err := os.Open(streamFilePath)
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
		return
	}
	defer f.Close()

	var offset int64
	var finalResp proto.PushChunkResp
	buf := make([]byte, maxTransferChunkBytes)

	if initReq.TransferSize == 0 {
		chMsg, err := d.sendRPC("push_chunk", proto.PushChunkReq{
			PushID: pr.PushID, Offset: 0, EOF: true,
		}, 120*time.Second)
		if err != nil {
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
			return
		}
		if !chMsg.OK {
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": chMsg.Error})
			return
		}
		if err := json.Unmarshal(chMsg.Payload, &finalResp); err != nil {
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "invalid push_chunk response"})
			return
		}
	} else {
		for offset < initReq.TransferSize {
			toRead := int64(len(buf))
			if rem := initReq.TransferSize - offset; rem < toRead {
				toRead = rem
			}
			n, rerr := io.ReadFull(f, buf[:toRead])
			if rerr != nil {
				_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "read local source: " + rerr.Error()})
				return
			}
			isEOF := offset+int64(n) == initReq.TransferSize
			timeout := 60 * time.Second
			if isEOF {
				timeout = 5 * time.Minute // allow archive verification & atomic extraction
			}
			chMsg, err := d.sendRPC("push_chunk", proto.PushChunkReq{
				PushID:     pr.PushID,
				Offset:     offset,
				DataBase64: base64.StdEncoding.EncodeToString(buf[:n]),
				EOF:        isEOF,
			}, timeout)
			if err != nil {
				_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
				return
			}
			if !chMsg.OK {
				_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": chMsg.Error})
				return
			}
			if err := json.Unmarshal(chMsg.Payload, &finalResp); err != nil {
				_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "invalid push_chunk response"})
				return
			}
			offset += int64(n)
		}
	}

	if !finalResp.Committed || finalResp.SHA256 != initReq.SHA256 {
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "remote push did not commit cleanly or sha256 mismatch"})
		return
	}

	d.writeAudit(map[string]any{
		"action":         "push",
		"is_archive":     initReq.IsArchive,
		"remote_path":    pr.RemotePath,
		"files_written":  finalResp.FilesWritten,
		"transfer_bytes": initReq.TransferSize,
		"raw_bytes":      rawBytes,
		"sha256":         finalResp.SHA256,
		"approved":       true,
	})
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":               true,
		"approved":         true,
		"is_archive":       initReq.IsArchive,
		"remote_path":      pr.RemotePath,
		"files_written":    finalResp.FilesWritten,
		"overwrite":        pr.Overwrite,
		"create":           pr.Create,
		"transfer_bytes":   initReq.TransferSize,
		"raw_bytes":        rawBytes,
		"skipped_symlinks": skippedSymlinks,
		"sha256":           finalResp.SHA256,
		"written_paths":    finalResp.WrittenPaths,
	})
}

func cmdPush(args []string) {
	args = reorderFlags(args, map[string]bool{"exclude": true})
	fs := flag.NewFlagSet("push", flag.ExitOnError)
	var excludes multiStringFlag
	fs.Var(&excludes, "exclude", "exclude glob/name pattern for directory push (repeatable or comma-separated)")
	noDefaultExcludes := fs.Bool("no-default-excludes", false, "disable default excludes (.git, __pycache__, node_modules, .venv, *.pyc)")
	_ = fs.Parse(args)
	if fs.NArg() < 2 {
		fmt.Fprintln(os.Stderr, "usage: guestctl push [--exclude PAT] [--no-default-excludes] <local_file_or_dir...> <remote_dest>")
		os.Exit(2)
	}
	pos := fs.Args()
	localArgs := pos[:len(pos)-1]
	remoteDest := pos[len(pos)-1]

	absLocals := make([]string, 0, len(localArgs))
	for _, lp := range localArgs {
		abs, err := filepath.Abs(lp)
		if err != nil {
			fmt.Fprintf(os.Stderr, "无效本地路径 %q: %v\n", lp, err)
			os.Exit(2)
		}
		if _, err := os.Stat(abs); err != nil {
			fmt.Fprintf(os.Stderr, "本地路径不可访问 %q: %v\n", lp, err)
			os.Exit(2)
		}
		absLocals = append(absLocals, abs)
	}

	fmt.Fprintln(os.Stderr, "正在准备推送并等待目标机 [y/N] 确认...")
	body, _ := json.Marshal(localPushReq{
		LocalPaths:        absLocals,
		RemotePath:        remoteDest,
		Excludes:          excludes,
		NoDefaultExcludes: *noDefaultExcludes,
	})
	client := localClient()
	client.Timeout = 25 * time.Minute
	resp, err := client.Post("http://unix/push", "application/json", bytes.NewReader(body))
	if err != nil {
		fmt.Fprintf(os.Stderr, "错误: 未检测到活跃联调会话或传输中断: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	var r struct {
		OK              bool     `json:"ok"`
		Approved        bool     `json:"approved"`
		Error           string   `json:"error"`
		IsArchive       bool     `json:"is_archive"`
		RemotePath      string   `json:"remote_path"`
		FilesWritten    int      `json:"files_written"`
		Overwrite       int      `json:"overwrite"`
		Create          int      `json:"create"`
		TransferBytes   int64    `json:"transfer_bytes"`
		RawBytes        int64    `json:"raw_bytes"`
		SkippedSymlinks int      `json:"skipped_symlinks"`
		SHA256          string   `json:"sha256"`
		WrittenPaths    []string `json:"written_paths"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		fmt.Fprintln(os.Stderr, "解析响应失败:", err)
		os.Exit(1)
	}
	if !r.OK {
		fmt.Fprintln(os.Stderr, "推送失败:", r.Error)
		os.Exit(1)
	}
	if !r.Approved {
		fmt.Fprintln(os.Stderr, "[目标机操作者拒绝了该文件推送]")
		os.Exit(1)
	}

	if r.IsArchive {
		fmt.Printf("✓ 已批量端到端加密推送并校验 SHA-256 一致（共 %d 个文件：新建 %d，覆盖 %d）\n", r.FilesWritten, r.Create, r.Overwrite)
		fmt.Printf("  目标目录: %s\n", r.RemotePath)
		fmt.Printf("  原始大小: %d bytes | 压缩传输: %d bytes\n", r.RawBytes, r.TransferBytes)
		if r.SkippedSymlinks > 0 {
			fmt.Printf("  安全跳过: 符号链接 %d 个\n", r.SkippedSymlinks)
		}
	} else {
		fmt.Printf("✓ 已端到端加密推送并校验 SHA-256 一致 (%d bytes)\n", r.TransferBytes)
		fmt.Printf("  目标路径: %s\n", r.RemotePath)
	}
	fmt.Printf("  SHA-256:  %s\n", r.SHA256)
}

// safeExtractLocalTarGz extracts a pulled .tar.gz archive safely into destDir with strict traversal/symlink checks.
func safeExtractLocalTarGz(tarGzPath, destDir string) (int, error) {
	f, err := os.Open(tarGzPath)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	gzr, err := gzip.NewReader(f)
	if err != nil {
		return 0, err
	}
	defer gzr.Close()
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return 0, err
	}
	baseAbs, err := filepath.Abs(destDir)
	if err != nil {
		return 0, err
	}

	tr := tar.NewReader(io.LimitReader(gzr, maxTransferBytes+1))
	count := 0
	var total int64
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return count, err
		}
		if hdr.Typeflag == tar.TypeDir {
			continue
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			return count, fmt.Errorf("refused non-regular entry %q in pulled archive", hdr.Name)
		}
		clean := path.Clean(strings.TrimPrefix(hdr.Name, "./"))
		if clean == "" || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || strings.HasPrefix(clean, "/") || strings.Contains(clean, `\`) {
			return count, fmt.Errorf("refused unsafe entry path %q", hdr.Name)
		}
		dst := filepath.Join(baseAbs, filepath.FromSlash(clean))
		rel, rerr := filepath.Rel(baseAbs, dst)
		if rerr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			return count, fmt.Errorf("refused escaping entry path %q", hdr.Name)
		}
		total += hdr.Size
		if total > maxTransferBytes {
			return count, errors.New("refused: pulled archive exceeds uncompressed limit")
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
			return count, err
		}
		out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		if err != nil {
			return count, err
		}
		n, cerr := io.Copy(out, io.LimitReader(tr, hdr.Size+1))
		_ = out.Close()
		if cerr != nil || n != hdr.Size {
			return count, fmt.Errorf("extract %q failed", clean)
		}
		count++
	}
	return count, nil
}
