// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package rpmpack

import (
	"archive/tar"
	"bytes"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

// create a test tar file
func createTar(t *testing.T) io.Reader {
	t.Helper()
	b := &bytes.Buffer{}
	ta := tar.NewWriter(b)
	entries := []struct {
		hdr  *tar.Header
		body []byte
	}{{
		hdr: &tar.Header{
			Name: "dir1/",
			Mode: 0755,
		},
	}, {
		hdr: &tar.Header{
			Typeflag: tar.TypeSymlink,
			Name:     "dir1/symlink1",
			Linkname: "../symtarget",
		},
	}, {
		hdr: &tar.Header{
			Name: "dir1/testfile1.txt",
			Mode: 0644,
			Size: int64(len("content1")),
		},
		body: []byte("content1"),
	}}

	for _, e := range entries {
		if err := ta.WriteHeader(e.hdr); err != nil {
			t.Errorf("failed to write header %s: %v", e.hdr.Name, err)
		}
		if e.hdr.Size != 0 {
			if _, err := ta.Write(e.body); err != nil {
				t.Errorf("failed to write body %s: %v", e.hdr.Name, err)
			}
		}

	}
	return b
}

func TestFromTar(t *testing.T) {
	testCases := []struct {
		name          string
		input         io.Reader
		wantBasenames []string
		wantFileModes []uint16
	}{{
		name:          "simple tar",
		input:         createTar(t),
		wantBasenames: []string{"dir1", "symlink1", "testfile1.txt"},
		wantFileModes: []uint16{040755, 0120000, 0100644},
	}}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := FromTar(tc.input, RPMMetaData{})
			if err != nil {
				t.Errorf("FromTar returned err: %v", err)
			}
			if err := r.Write(io.Discard); err != nil {
				t.Errorf("r.Write() returned err: %v", err)
			}
			if r == nil {
				t.Fatalf("FromTar returned nil pointer")
			}
			if d := cmp.Diff(tc.wantBasenames, r.basenames); d != "" {
				t.Errorf("FromTar basenames differs (want->got):\n%v", d)
			}
			if d := cmp.Diff(tc.wantFileModes, r.filemodes); d != "" {
				t.Errorf("FromTar filemodes differs (want->got):\n%v", d)
			}
		})
	}
}

func tarOf(t *testing.T, entries ...*tar.Header) *bytes.Buffer {
	t.Helper()
	b := &bytes.Buffer{}
	w := tar.NewWriter(b)
	for _, h := range entries {
		if err := w.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Size > 0 && h.Size < 1<<20 {
			if _, err := w.Write(make([]byte, h.Size)); err != nil {
				t.Fatal(err)
			}
		}
	}
	// No Close or Flush: a huge claimed size would be reported as a short write.
	// WriteHeader writes straight to b.
	return b
}

// The type of an rpm entry must come from the tar entry type, not from the
// untrusted mode bits: this regular file would otherwise become a symlink whose
// target is the file content.
func TestFromTarIgnoresModeTypeBits(t *testing.T) {
	b := tarOf(t,
		&tar.Header{Typeflag: tar.TypeReg, Name: "reg-as-symlink", Mode: 0120777, Size: 4},
		&tar.Header{Typeflag: tar.TypeReg, Name: "reg-as-dir", Mode: 040755, Size: 4},
		&tar.Header{Typeflag: tar.TypeDir, Name: "dir", Mode: 0100644},
		&tar.Header{Typeflag: tar.TypeReg, Name: "setuid", Mode: 04755, Size: 1},
		&tar.Header{Typeflag: tar.TypeReg, Name: "huge-mode", Mode: 1<<40 | 0644, Size: 1},
		&tar.Header{Typeflag: tar.TypeReg, Name: "negative-mode", Mode: -1, Size: 1},
	)
	r, err := FromTar(b, RPMMetaData{})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Write(io.Discard); err != nil {
		t.Fatal(err)
	}
	want := map[string]uint16{
		"reg-as-symlink": 0100777,
		"reg-as-dir":     0100755,
		"dir":            040644,
		"setuid":         0104755,
		"huge-mode":      0100644,
		"negative-mode":  0107777,
	}
	for i, name := range r.basenames {
		if r.filemodes[i] != want[name] {
			t.Errorf("%s: mode %o, want %o", name, r.filemodes[i], want[name])
		}
		if r.filelinktos[i] != "" {
			t.Errorf("%s: unexpected link target %q", name, r.filelinktos[i])
		}
	}
}

func TestFromTarSkipsGlobalHeader(t *testing.T) {
	b := tarOf(t,
		&tar.Header{Typeflag: tar.TypeXGlobalHeader, Name: "pax_global_header", PAXRecords: map[string]string{"comment": "abc"}},
		&tar.Header{Typeflag: tar.TypeReg, Name: "a", Mode: 0644, Size: 1},
	)
	r, err := FromTar(b, RPMMetaData{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.files) != 1 || r.files["/a"].Name == "" {
		t.Errorf("files = %v, want only /a", r.files)
	}
}

func TestFromTarNames(t *testing.T) {
	testCases := map[string]string{
		"../../etc/passwd":  "/etc/passwd",
		"a/../../b":         "/b",
		"./a//b":            "/a/b",
		"/abs/olute":        "/abs/olute",
		"a/./b/../c":        "/a/c",
		"x/" + "y/../../..": "",
	}
	for in, want := range testCases {
		t.Run(in, func(t *testing.T) {
			r, err := FromTar(tarOf(t, &tar.Header{Typeflag: tar.TypeReg, Name: in, Mode: 0644, Size: 1}), RPMMetaData{})
			if err != nil {
				t.Fatal(err)
			}
			if want == "" {
				if len(r.files) != 0 {
					t.Errorf("files = %v, want none (root)", r.files)
				}
				return
			}
			if _, ok := r.files[want]; !ok || len(r.files) != 1 {
				t.Errorf("files = %v, want only %q", r.files, want)
			}
			if err := r.Write(io.Discard); err != nil {
				t.Errorf("Write: %v", err)
			}
		})
	}
}

func TestFromTarRejects(t *testing.T) {
	testCases := []struct {
		name   string
		format int
		hdr    *tar.Header
		want   string
	}{
		{"hard link", 0, &tar.Header{Typeflag: tar.TypeLink, Name: "a", Linkname: "b"}, "unknown tar type"},
		{"fifo", 0, &tar.Header{Typeflag: tar.TypeFifo, Name: "a"}, "unknown tar type"},
		{"mtime before 1970", 0, &tar.Header{Typeflag: tar.TypeReg, Name: "a", ModTime: time.Unix(-5, 0), Format: tar.FormatPAX}, "modification time"},
		{"mtime after 2106", 0, &tar.Header{Typeflag: tar.TypeReg, Name: "a", ModTime: time.Unix(1<<33, 0), Format: tar.FormatPAX}, "modification time"},
		{"v4 file over 4 GiB", 0, &tar.Header{Typeflag: tar.TypeReg, Name: "a", Size: 1 << 33}, "4 GiB"},
		{"unsupported format", 5, &tar.Header{Typeflag: tar.TypeReg, Name: "a"}, "unsupported rpm format"},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := FromTar(tarOf(t, tc.hdr), RPMMetaData{Format: tc.format})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("FromTar error = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}

func TestFromTarTruncated(t *testing.T) {
	b := tarOf(t, &tar.Header{Typeflag: tar.TypeReg, Name: "a", Mode: 0644, Size: 1000})
	if _, err := FromTar(bytes.NewReader(b.Bytes()[:600]), RPMMetaData{}); err == nil {
		t.Error("want an error for a truncated tar")
	}
}
