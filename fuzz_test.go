package rpmpack

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"testing"

	"github.com/cavaliergopher/cpio"
)

// FuzzFromTar feeds arbitrary bytes to FromTar, the entry point that reads
// untrusted tars. Whatever it returns must write a well formed rpm or fail with an
// error; it must never panic or produce an unparsable package.
func FuzzFromTar(f *testing.F) {
	f.Add(fuzzTar(f, &tar.Header{Typeflag: tar.TypeReg, Name: "dir/file", Mode: 0644, Size: 2}, []byte("hi")), false)
	f.Add([]byte{}, false)
	f.Add(bytes.Repeat([]byte{0xff}, 1024), true)
	f.Add(fuzzTar(f, &tar.Header{Typeflag: tar.TypeReg, Name: "../../etc/passwd", Mode: 0120777, Size: 3}, []byte("abc")), true)
	f.Add(fuzzTar(f, &tar.Header{Typeflag: tar.TypeSymlink, Name: "a/b", Linkname: "../x"}, nil), false)
	f.Add(fuzzTar(f, &tar.Header{Typeflag: tar.TypeXGlobalHeader, Name: "g", PAXRecords: map[string]string{"a": "b"}}, nil), false)
	f.Fuzz(func(t *testing.T, data []byte, v6 bool) {
		md := RPMMetaData{Name: "fuzz", Version: "1", Compressor: "gzip:1"}
		if v6 {
			md.Format = FormatV6
		}
		r, err := FromTar(bytes.NewReader(data), md)
		if err != nil {
			return
		}
		var b bytes.Buffer
		if err := r.Write(&b); err != nil {
			// Tar names and strings can legitimately be unrepresentable.
			if errors.Is(err, ErrInvalidFile) || errors.Is(err, ErrInvalidMetadata) {
				return
			}
			t.Fatalf("Write: %v", err)
		}
		checkPackage(t, b.Bytes(), r.files, v6)
	})
}

func fuzzTar(f *testing.F, h *tar.Header, body []byte) []byte {
	f.Helper()
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	if err := w.WriteHeader(h); err != nil {
		f.Fatal(err)
	}
	if _, err := w.Write(body); err != nil {
		f.Fatal(err)
	}
	if err := w.Close(); err != nil {
		f.Fatal(err)
	}
	return b.Bytes()
}

// FuzzRoundTrip builds a package from arbitrary files, writes it, and parses the
// package back with an independent reader: the header file tables, the digests and
// (v4) the cpio payload have to describe exactly the files that were added.
func FuzzRoundTrip(f *testing.F) {
	f.Add("/a/b", "/a/c", []byte("body"), uint32(0644), uint32(0755), uint8(0), false)
	f.Add("/a", "/a/b", []byte{}, uint32(040755), uint32(0120777), uint8(1), true)
	f.Add("/x/../y", "//z", []byte("x"), uint32(1<<20), uint32(0), uint8(2), false)
	f.Add("/d", "/e", []byte("dir body"), uint32(040755), uint32(040700), uint8(0), false)
	f.Add("/ü/日本", "/a\x00b", []byte("x\x00"), uint32(0100600), uint32(0644), uint8(3), true)
	f.Fuzz(func(t *testing.T, n1, n2 string, body []byte, mode1, mode2 uint32, flags uint8, v6 bool) {
		md := RPMMetaData{Name: "fuzz", Version: "1", Release: "2", Epoch: NoEpoch, Compressor: "gzip:1"}
		if v6 {
			md.Format = FormatV6
		}
		r, err := NewRPM(md)
		if err != nil {
			t.Fatal(err)
		}
		typ := FileType(0)
		if flags&1 != 0 {
			typ = GhostFile
		}
		r.AddFile(RPMFile{Name: n1, Body: body, Mode: uint(mode1), Owner: "o", Group: "g", MTime: uint32(flags), Type: typ})
		r.AddFile(RPMFile{Name: n2, Body: body, Mode: uint(mode2), Owner: "o", Group: "g"})
		var b bytes.Buffer
		if err := r.Write(&b); err != nil {
			if errors.Is(err, ErrInvalidFile) {
				return // the file was rejected before anything was written
			}
			t.Fatalf("Write: %v", err)
		}
		checkPackage(t, b.Bytes(), r.files, v6)
	})
}

// checkPackage parses pkg and compares it with the files that were added.
func checkPackage(t *testing.T, pkg []byte, files map[string]RPMFile, v6 bool) {
	t.Helper()
	p := parseRPM(t, pkg)

	// The signature header digests the main header, the main header the payload.
	if got := p.sig.str(t, sigSHA256); got != fmt.Sprintf("%x", sha256.Sum256(p.main.raw)) {
		t.Errorf("header sha256 %s does not match the header", got)
	}
	if got := p.main.strs(t, tagPayloadDigest); len(got) != 1 || got[0] != fmt.Sprintf("%x", sha256.Sum256(p.payload)) {
		t.Errorf("payload digest %v does not match the payload", got)
	}

	if len(files) == 0 {
		if _, ok := p.main.entries[tagBasenames]; ok {
			t.Error("a package without files has file tags")
		}
		return
	}

	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)

	base := p.main.strs(t, tagBasenames)
	dirs := p.main.strs(t, tagDirnames)
	dirIdx := p.main.ints(t, tagDirindexes, typeInt32)
	modes := p.main.ints(t, tagFileModes, typeInt16)
	digests := p.main.strs(t, tagFileDigests)
	if len(base) != len(names) || len(dirIdx) != len(names) || len(modes) != len(names) || len(digests) != len(names) {
		t.Fatalf("file tables have %d/%d/%d/%d rows, want %d",
			len(base), len(dirIdx), len(modes), len(digests), len(names))
	}
	var sizes []uint64
	if v6 {
		sizes = p.main.ints(t, tagLongFileSizes, typeInt64)
	} else {
		sizes = p.main.ints(t, tagFileSizes, typeInt32)
	}

	var payloadNames []string
	for i, want := range names {
		f := files[want]
		if int(dirIdx[i]) >= len(dirs) {
			t.Fatalf("file %d: dirindex %d out of range (%d dirs)", i, dirIdx[i], len(dirs))
		}
		if got := dirs[dirIdx[i]] + base[i]; got != want {
			t.Errorf("file %d: header path %q, want %q", i, got, want)
		}
		if dir, _ := path.Split(want); dirs[dirIdx[i]] != dir || base[i] == "" {
			t.Errorf("file %d: dirname %q basename %q do not split %q", i, dirs[dirIdx[i]], base[i], want)
		}
		isDir := f.Mode&040000 != 0
		isLink := !isDir && f.Mode&0120000 == 0120000
		wantMode := uint64(uint16(f.Mode))
		if !isDir && !isLink {
			wantMode |= 0100000
		}
		if modes[i] != wantMode {
			t.Errorf("%s: mode %o, want %o", want, modes[i], wantMode)
		}
		wantDigest := ""
		if !isDir && !isLink {
			wantDigest = fmt.Sprintf("%x", sha256.Sum256(f.Body))
		}
		if digests[i] != wantDigest {
			t.Errorf("%s: digest %q, want %q", want, digests[i], wantDigest)
		}
		if !isDir && sizes[i] != uint64(len(f.Body)) {
			t.Errorf("%s: size %d, want %d", want, sizes[i], len(f.Body))
		}
		if f.Type != GhostFile {
			payloadNames = append(payloadNames, want)
		}
	}

	if v6 {
		return // the stripped cpio of v6 has no names: it is covered by the v6 tests
	}
	cr := cpio.NewReader(bytes.NewReader(decompress(t, "gzip", p.payload)))
	var got []string
	for {
		h, err := cr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("payload: %v", err)
		}
		b, err := io.ReadAll(cr)
		if err != nil {
			t.Fatalf("payload %s: %v", h.Name, err)
		}
		f := files[h.Name]
		switch {
		case f.Mode&040000 != 0: // a directory has no content
			if len(b) != 0 || h.Size != 0 {
				t.Errorf("payload directory %s has %d bytes of content", h.Name, h.Size)
			}
		case f.Mode&0120000 == 0120000: // the reader moves the symlink target to Linkname
			// The reader only does so for modes without setuid/setgid/sticky bits.
			got := h.Linkname
			if got == "" {
				got = string(b)
			}
			if got != string(f.Body) {
				t.Errorf("payload symlink %s -> %q, want %q", h.Name, got, f.Body)
			}
		case !bytes.Equal(b, f.Body):
			t.Errorf("payload %s: content differs", h.Name)
		}
		got = append(got, h.Name)
	}
	if fmt.Sprint(got) != fmt.Sprint(payloadNames) {
		t.Errorf("payload files %q, want %q", got, payloadNames)
	}
}

// FuzzNewRelation checks that parsing a dependency string never panics and that a
// parsed relation round-trips through its string form.
func FuzzNewRelation(f *testing.F) {
	for _, s := range []string{"", "python >= 3.7", "a=1", "(a or b)", "x <> y", "a b c", " ", "=", "\x00"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		rel, err := NewRelation(s)
		if err != nil {
			return
		}
		if rel == nil {
			t.Fatal("nil relation without error")
		}
		_ = rel.String()
		var rs Relations
		if err := rs.Set(s); err != nil {
			t.Fatalf("Set failed where NewRelation succeeded: %v", err)
		}
	})
}

// FuzzSetupCompressor feeds arbitrary compressor settings (typically a CLI flag).
func FuzzSetupCompressor(f *testing.F) {
	for _, s := range []string{"", "gzip", "gzip:9", "gzip:-1", "gzip:99999999999999999999", "zstd:fastest", "zstd:3", "xz", "xz:1", "lzma", "a:b:c", ":"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		wc, name, err := setupCompressor(s, io.Discard)
		if err != nil {
			return
		}
		if name == "" {
			t.Error("empty compressor name")
		}
		if err := wc.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
}
