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
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	e2ee "guest-bridge/internal/crypto"
	"guest-bridge/internal/proto"
)

func TestLiveExecConsoleSanitizeAndCap(t *testing.T) {
	var buf bytes.Buffer
	con := newLiveExecConsole(&buf)
	con.maxLines = 5
	con.maxLineBytes = 24

	outS := con.NewStream(false)
	errS := con.NewStream(true)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = outS.Write([]byte("hello \x1b[31mred\x1b[0m world\n"))
		_, _ = outS.Write([]byte("中文字符测试截断边界一二三四五六七八九十\n"))
		_, _ = outS.Write([]byte("line3\r\nline4\nline5\nline6\nline7\n"))
		outS.Flush()
	}()
	go func() {
		defer wg.Done()
		_, _ = errS.Write([]byte("err line with bidi \u202eabc\npartial"))
		errS.Flush()
	}()
	wg.Wait()

	got := buf.String()
	if strings.Contains(got, "\x1b[31mred") {
		t.Fatalf("raw ANSI escape leaked into console output: %q", got)
	}
	if !strings.Contains(got, `\x1b[31mred`) {
		t.Fatalf("expected sanitized ANSI escape in console output, got: %q", got)
	}
	if strings.Contains(got, "\u202e") {
		t.Fatalf("BiDi override leaked into console output: %q", got)
	}
	if strings.Contains(got, "七八九十") {
		t.Fatalf("expected long single line to stay truncated on 1 line, got: %q", got)
	}
	if !strings.Contains(got, "屏幕回显已达 5 行上限") {
		t.Fatalf("expected line cap notice in output, got: %q", got)
	}
}

func TestValidateArchiveRelPath(t *testing.T) {
	good := []string{"a.txt", "sub/dir/file.yaml", "./nested/ok.bin"}
	for _, p := range good {
		if _, err := validateArchiveRelPath(p); err != nil {
			t.Errorf("expected valid path %q, got err: %v", p, err)
		}
	}
	bad := []string{
		"", ".", "..", "../etc/passwd", "a/../b", "/etc/passwd",
		`a\b.txt`, "C:foo.txt", "C:/foo.txt", "~/secret", "foo\x00bar", "dir/",
	}
	for _, p := range bad {
		if _, err := validateArchiveRelPath(p); err == nil {
			t.Errorf("expected invalid path %q to be rejected", p)
		}
	}
}

type testPair struct {
	hostConn  *e2ee.Conn
	ag        *agent
	ttyCh     chan string
	ttyOutW   *os.File
	ttyOutR   *os.File
	done      chan error
	hostReqID int
}

func startTestAgent(t *testing.T, mode, rootScope string) *testPair {
	t.Helper()
	c1, c2 := net.Pipe()
	psk := make([]byte, 32)
	_, _ = io.ReadFull(rand.Reader, psk)

	var hostConn, guestConn *e2ee.Conn
	var hErr, gErr error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		hostConn, hErr = e2ee.HostHandshake(c1, psk)
	}()
	go func() {
		defer wg.Done()
		guestConn, gErr = e2ee.GuestHandshake(c2, psk)
	}()
	wg.Wait()
	if hErr != nil || gErr != nil {
		t.Fatalf("handshake failed: host=%v guest=%v", hErr, gErr)
	}

	ttyOutR, ttyOutW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	ttyCh := make(chan string, 16)
	ag := newAgent(mode, rootScope, guestConn, ttyOutW, ttyCh, true)
	done := make(chan error, 1)
	go func() {
		done <- ag.serveLoop()
	}()

	// Deterministic prompt responder: waits until "[y/N]:" is actually printed on ttyOut
	// (after askConfirm's anti-stale-keystroke drain) before delivering the queued answer.
	answers := make(chan string, 16)
	go func() {
		var acc bytes.Buffer
		buf := make([]byte, 4096)
		for {
			n, rerr := ttyOutR.Read(buf)
			if n > 0 {
				acc.Write(buf[:n])
				for strings.Contains(acc.String(), "[y/N]:") {
					s := acc.String()
					idx := strings.Index(s, "[y/N]:")
					acc.Reset()
					acc.WriteString(s[idx+len("[y/N]:"):])
					select {
					case ans := <-answers:
						ttyCh <- ans
					case <-ag.ctx.Done():
						return
					}
				}
			}
			if rerr != nil {
				return
			}
		}
	}()

	tp := &testPair{
		hostConn: hostConn,
		ag:       ag,
		ttyCh:    answers,
		ttyOutW:  ttyOutW,
		ttyOutR:  ttyOutR,
		done:     done,
	}
	t.Cleanup(func() {
		ag.stop()
		_ = hostConn.Close()
		_ = guestConn.Close()
		_ = ttyOutW.Close()
		_ = ttyOutR.Close()
		<-done
	})
	return tp
}

func (tp *testPair) rpc(t *testing.T, action string, payload any) proto.Message {
	t.Helper()
	tp.hostReqID++
	var raw json.RawMessage
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		raw = b
	}
	if err := tp.hostConn.WriteJSON(proto.Message{
		ID:      "t" + string(rune('0'+tp.hostReqID)),
		Kind:    "req",
		Action:  action,
		Payload: raw,
	}); err != nil {
		t.Fatal(err)
	}
	var resp proto.Message
	if err := tp.hostConn.ReadJSON(&resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

func buildTarGzBytes(t *testing.T, entries []struct {
	name     string
	body     []byte
	typeflag byte
	linkname string
	mode     int64
}) ([]byte, string) {
	t.Helper()
	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gzw)
	for _, e := range entries {
		tf := e.typeflag
		if tf == 0 {
			tf = tar.TypeReg
		}
		m := e.mode
		if m == 0 {
			m = 0644
		}
		hdr := &tar.Header{
			Name:     e.name,
			Typeflag: tf,
			Size:     int64(len(e.body)),
			Linkname: e.linkname,
			Mode:     m,
		}
		if tf == tar.TypeSymlink || tf == tar.TypeLink {
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if len(e.body) > 0 && (tf == tar.TypeReg || tf == tar.TypeRegA) {
			if _, err := tw.Write(e.body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzw.Close(); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(buf.Bytes())
	return buf.Bytes(), hex.EncodeToString(sum[:])
}

func TestPushSingleBinaryAndArchive(t *testing.T) {
	tmp := t.TempDir()
	tp := startTestAgent(t, "confirm", tmp)

	// 1. Multi-chunk binary single-file push into a nested non-existent directory.
	binData := make([]byte, 300*1024+17) // > 1 chunk (256 KiB)
	for i := range binData {
		binData[i] = byte(i % 251)
	}
	sum := sha256.Sum256(binData)
	shaHex := hex.EncodeToString(sum[:])

	dstSingle := filepath.Join(tmp, "models", "policy.onnx")
	tp.ttyCh <- "y\n"
	initResp := tp.rpc(t, "push_init", proto.PushInitReq{
		RemotePath:   dstSingle,
		IsArchive:    false,
		FileName:     "policy.onnx",
		TransferSize: int64(len(binData)),
		SHA256:       shaHex,
		Mode:         0644,
	})
	if !initResp.OK {
		t.Fatalf("push_init failed: %s", initResp.Error)
	}
	var pr proto.PushInitResp
	_ = json.Unmarshal(initResp.Payload, &pr)
	if !pr.Approved || pr.PushID == "" {
		t.Fatalf("expected approved push_init, got: %+v", pr)
	}

	const chunk = 256 * 1024
	for off := 0; off < len(binData); off += chunk {
		end := off + chunk
		if end > len(binData) {
			end = len(binData)
		}
		chResp := tp.rpc(t, "push_chunk", proto.PushChunkReq{
			PushID:     pr.PushID,
			Offset:     int64(off),
			DataBase64: base64.StdEncoding.EncodeToString(binData[off:end]),
			EOF:        end == len(binData),
		})
		if !chResp.OK {
			t.Fatalf("push_chunk failed at offset %d: %s", off, chResp.Error)
		}
	}
	gotBytes, err := os.ReadFile(dstSingle)
	if err != nil || !bytes.Equal(gotBytes, binData) {
		t.Fatalf("pushed binary mismatch: err=%v len=%d", err, len(gotBytes))
	}

	// 2. Archive batch push with nested subdirectories.
	tarData, tarSHA := buildTarGzBytes(t, []struct {
		name     string
		body     []byte
		typeflag byte
		linkname string
		mode     int64
	}{
		{name: "cfg/a.yaml", body: []byte("kp: 25.0\n")},
		{name: "cfg/b.yaml", body: []byte("kd: 0.5\n")},
		{name: "run.sh", body: []byte("#!/bin/sh\necho ok\n"), mode: 0755},
	})
	dstDir := filepath.Join(tmp, "bundle")
	tp.ttyCh <- "y\n"
	initResp2 := tp.rpc(t, "push_init", proto.PushInitReq{
		RemotePath:   dstDir,
		IsArchive:    true,
		TransferSize: int64(len(tarData)),
		TotalRawSize: 9 + 8 + 18,
		SHA256:       tarSHA,
		Files: []proto.PushManifestItem{
			{RelPath: "cfg/a.yaml", Size: 9},
			{RelPath: "cfg/b.yaml", Size: 8},
			{RelPath: "run.sh", Size: 18},
		},
	})
	if !initResp2.OK {
		t.Fatalf("archive push_init failed: %s", initResp2.Error)
	}
	var pr2 proto.PushInitResp
	_ = json.Unmarshal(initResp2.Payload, &pr2)
	if !pr2.Approved {
		t.Fatalf("expected archive push approved")
	}
	chResp2 := tp.rpc(t, "push_chunk", proto.PushChunkReq{
		PushID:     pr2.PushID,
		Offset:     0,
		DataBase64: base64.StdEncoding.EncodeToString(tarData),
		EOF:        true,
	})
	if !chResp2.OK {
		t.Fatalf("archive push_chunk failed: %s", chResp2.Error)
	}
	var cr2 proto.PushChunkResp
	_ = json.Unmarshal(chResp2.Payload, &cr2)
	if !cr2.Committed || cr2.FilesWritten != 3 {
		t.Fatalf("unexpected archive commit resp: %+v", cr2)
	}
	if b, err := os.ReadFile(filepath.Join(dstDir, "cfg", "a.yaml")); err != nil || string(b) != "kp: 25.0\n" {
		t.Fatalf("extracted cfg/a.yaml mismatch: %v %q", err, string(b))
	}
}

func TestPushArchiveSecurityRejections(t *testing.T) {
	tmp := t.TempDir()
	tp := startTestAgent(t, "confirm", tmp)

	// Attack 1: Bait-and-switch (manifest claims "good.txt", tar actually contains extra "evil.txt").
	tarBait, shaBait := buildTarGzBytes(t, []struct {
		name     string
		body     []byte
		typeflag byte
		linkname string
		mode     int64
	}{
		{name: "good.txt", body: []byte("ok")},
		{name: "evil.txt", body: []byte("pwn")},
	})
	baitDir := filepath.Join(tmp, "bait")
	tp.ttyCh <- "y\n"
	initResp := tp.rpc(t, "push_init", proto.PushInitReq{
		RemotePath:   baitDir,
		IsArchive:    true,
		TransferSize: int64(len(tarBait)),
		TotalRawSize: 2,
		SHA256:       shaBait,
		Files:        []proto.PushManifestItem{{RelPath: "good.txt", Size: 2}},
	})
	if !initResp.OK {
		t.Fatalf("unexpected init error: %s", initResp.Error)
	}
	var pr proto.PushInitResp
	_ = json.Unmarshal(initResp.Payload, &pr)
	chResp := tp.rpc(t, "push_chunk", proto.PushChunkReq{
		PushID:     pr.PushID,
		Offset:     0,
		DataBase64: base64.StdEncoding.EncodeToString(tarBait),
		EOF:        true,
	})
	if chResp.OK {
		t.Fatalf("expected bait-and-switch archive to be rejected")
	}
	if _, err := os.Stat(filepath.Join(baitDir, "good.txt")); !os.IsNotExist(err) {
		t.Fatalf("Pass-1 failure must write ZERO files; found good.txt")
	}

	// Attack 2: Symlink inside tar.gz.
	tarSym, shaSym := buildTarGzBytes(t, []struct {
		name     string
		body     []byte
		typeflag byte
		linkname string
		mode     int64
	}{
		{name: "good.txt", body: []byte("ok")},
		{name: "escape", typeflag: tar.TypeSymlink, linkname: "/etc/passwd"},
	})
	symDir := filepath.Join(tmp, "sym")
	tp.ttyCh <- "y\n"
	initSym := tp.rpc(t, "push_init", proto.PushInitReq{
		RemotePath:   symDir,
		IsArchive:    true,
		TransferSize: int64(len(tarSym)),
		TotalRawSize: 2,
		SHA256:       shaSym,
		Files:        []proto.PushManifestItem{{RelPath: "good.txt", Size: 2}},
	})
	var prSym proto.PushInitResp
	_ = json.Unmarshal(initSym.Payload, &prSym)
	chSym := tp.rpc(t, "push_chunk", proto.PushChunkReq{
		PushID:     prSym.PushID,
		Offset:     0,
		DataBase64: base64.StdEncoding.EncodeToString(tarSym),
		EOF:        true,
	})
	if chSym.OK {
		t.Fatalf("expected symlink entry in tar to be rejected")
	}

	// Attack 3: Escape outside rootScope.
	outResp := tp.rpc(t, "push_init", proto.PushInitReq{
		RemotePath:   filepath.Join(filepath.Dir(tmp), "outside.txt"),
		IsArchive:    false,
		TransferSize: 2,
		SHA256:       shaBait,
	})
	if outResp.OK {
		t.Fatalf("expected push outside rootScope to fail")
	}
}

func TestPullDirectoryArchiveAndExecEcho(t *testing.T) {
	tmp := t.TempDir()
	srcDir := filepath.Join(tmp, "logs")
	if err := os.MkdirAll(filepath.Join(srcDir, "sub"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "a.log"), []byte("log-a\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "sub", "b.log"), []byte("log-b\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		_ = os.Symlink("/etc/hostname", filepath.Join(srcDir, "sneaky_link"))
	}

	tp := startTestAgent(t, "confirm", "")
	tp.ttyCh <- "y\n"
	initResp := tp.rpc(t, "pull_init", proto.PullInitReq{Path: srcDir})
	if !initResp.OK {
		t.Fatalf("pull_init dir failed: %s", initResp.Error)
	}
	var pr proto.PullInitResp
	_ = json.Unmarshal(initResp.Payload, &pr)
	if !pr.Approved || !pr.IsArchive || pr.FileCount != 2 {
		t.Fatalf("expected archive pull of 2 files (skipping symlink), got: %+v", pr)
	}

	var rawTarGz bytes.Buffer
	var off int64
	var remoteSHA string
	for {
		chResp := tp.rpc(t, "pull_chunk", proto.PullChunkReq{PullID: pr.PullID, Offset: off, Size: 64 * 1024})
		if !chResp.OK {
			t.Fatalf("pull_chunk failed: %s", chResp.Error)
		}
		var cr proto.PullChunkResp
		_ = json.Unmarshal(chResp.Payload, &cr)
		if cr.BytesRead > 0 {
			b, err := base64.StdEncoding.DecodeString(cr.DataBase64)
			if err != nil {
				t.Fatal(err)
			}
			rawTarGz.Write(b)
			off += int64(len(b))
		}
		if cr.EOF {
			remoteSHA = cr.SHA256
			break
		}
	}
	sum := sha256.Sum256(rawTarGz.Bytes())
	if hex.EncodeToString(sum[:]) != remoteSHA {
		t.Fatalf("pulled dir archive sha256 mismatch")
	}

	// Verify exec runs cleanly and records DurationMs.
	if runtime.GOOS != "windows" {
		tp.ttyCh <- "y\n"
		exResp := tp.rpc(t, "exec", proto.ExecReq{Command: "echo hello-stdout && echo hello-stderr >&2", Cwd: tmp})
		if !exResp.OK {
			t.Fatalf("exec failed: %s", exResp.Error)
		}
		var er proto.ExecResp
		_ = json.Unmarshal(exResp.Payload, &er)
		if !er.Approved || er.ExitCode != 0 || !strings.Contains(er.Stdout, "hello-stdout") || !strings.Contains(er.Stderr, "hello-stderr") {
			t.Fatalf("unexpected exec resp: %+v", er)
		}
	}
}
