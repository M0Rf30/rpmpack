package main

import (
	"archive/tar"
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

func writeTar(t *testing.T, dir string) string {
	t.Helper()
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	body := []byte("hello\n")
	if err := w.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: "usr/share/hello", Mode: 0644, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "in.tar")
	if err := os.WriteFile(p, b.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func setFlags(t *testing.T, args ...string) {
	t.Helper()
	if err := flag.CommandLine.Parse(args); err != nil {
		t.Fatal(err)
	}
}

func TestRun(t *testing.T) {
	dir := t.TempDir()
	in := writeTar(t, dir)
	out := filepath.Join(dir, "out.rpm")

	setFlags(t, "-name", "x", "-version", "1", "-file", out, in)
	if err := run(); err != nil {
		t.Fatalf("run: %v", err)
	}
	fi, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() == 0 {
		t.Error("empty rpm")
	}
	if fi.Mode().Perm()&0o022 != 0 {
		t.Errorf("rpm is group or world writable: %v", fi.Mode())
	}
}

// prefixesIndex is the header index entry of the PREFIXES tag (1098) with the
// STRING_ARRAY type (8).
var prefixesIndex = []byte{0, 0, 0x04, 0x4a, 0, 0, 0, 8}

func TestRunPrefixes(t *testing.T) {
	dir := t.TempDir()
	in := writeTar(t, dir)
	for _, tc := range []struct {
		prefixes string
		want     bool
	}{{"", false}, {"/usr", true}} {
		out := filepath.Join(dir, "out.rpm")
		setFlags(t, "-name", "x", "-version", "1", "-prefixes", tc.prefixes, "-file", out, in)
		if err := run(); err != nil {
			t.Fatalf("run: %v", err)
		}
		// Without -prefixes the tag used to be written with a single empty prefix.
		if got := bytes.Contains(readFile(t, out), prefixesIndex); got != tc.want {
			t.Errorf("-prefixes=%q: PREFIXES tag present = %v, want %v", tc.prefixes, got, tc.want)
		}
	}
}

func readFile(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRunRemovesPartialOutput(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.tar")
	if err := os.WriteFile(bad, bytes.Repeat([]byte{0xff}, 1024), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out.rpm")
	setFlags(t, "-name", "x", "-version", "1", "-file", out, bad)
	if err := run(); err == nil {
		t.Fatal("want an error for a corrupt tar")
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Errorf("partial output was left behind: %v", err)
	}
}

func TestRunMissingInput(t *testing.T) {
	setFlags(t, "-name", "x", "-version", "1", filepath.Join(t.TempDir(), "missing.tar"))
	if err := run(); err == nil {
		t.Fatal("want an error for a missing tar")
	}
}
