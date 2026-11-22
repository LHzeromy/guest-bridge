package main

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

func TestBuildPushBundleAndExcludes(t *testing.T) {
	tmp := t.TempDir()
	mustWrite := func(rel, content string) {
		t.Helper()
		full := filepath.Join(tmp, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite("src/main.py", "print('ok')\n")
	mustWrite("src/cfg.yaml", "k: 1\n")
	mustWrite("src/__pycache__/main.cpython.pyc", "junk")
	mustWrite("src/.git/config", "secret")
	mustWrite("src/ignore_me.tmp", "tmp")

	bundle, err := buildPushBundle([]string{filepath.Join(tmp, "src")}, []string{"*.tmp"}, false)
	if err != nil {
		t.Fatalf("buildPushBundle failed: %v", err)
	}
	defer os.Remove(bundle.bundlePath)

	if len(bundle.manifest) != 2 {
		t.Fatalf("expected 2 files after excludes, got %d: %+v", len(bundle.manifest), bundle.manifest)
	}
	if bundle.manifest[0].RelPath != "cfg.yaml" || bundle.manifest[1].RelPath != "main.py" {
		t.Fatalf("unexpected manifest order/paths: %+v", bundle.manifest)
	}

	// Verify safeExtractLocalTarGz extracts those 2 files cleanly.
	extDir := filepath.Join(tmp, "extracted")
	cnt, err := safeExtractLocalTarGz(bundle.bundlePath, extDir)
	if err != nil || cnt != 2 {
		t.Fatalf("safeExtractLocalTarGz failed: cnt=%d err=%v", cnt, err)
	}
	if b, err := os.ReadFile(filepath.Join(extDir, "main.py")); err != nil || string(b) != "print('ok')\n" {
		t.Fatalf("extracted main.py mismatch: %v %q", err, string(b))
	}
}

func TestSafeExtractLocalTarGzRejectsTraversal(t *testing.T) {
	tmp := t.TempDir()
	evilPath := filepath.Join(tmp, "evil.tar.gz")
	f, err := os.Create(evilPath)
	if err != nil {
		t.Fatal(err)
	}
	gzw := gzip.NewWriter(f)
	tw := tar.NewWriter(gzw)
	_ = tw.WriteHeader(&tar.Header{Name: "../escape.txt", Mode: 0644, Size: 3})
	_, _ = tw.Write([]byte("bad"))
	_ = tw.Close()
	_ = gzw.Close()
	_ = f.Close()

	if _, err := safeExtractLocalTarGz(evilPath, filepath.Join(tmp, "out")); err == nil {
		t.Fatalf("expected traversal tar.gz to be rejected")
	}
}
