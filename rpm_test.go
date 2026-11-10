package rpmpack

import (
	"bytes"
	"errors"
	"io"
	"math"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/klauspost/compress/zstd"
	gzip "github.com/klauspost/pgzip"
	"github.com/ulikunitz/xz"
	"github.com/ulikunitz/xz/lzma"
)

func TestFileOwner(t *testing.T) {
	r, err := NewRPM(RPMMetaData{})
	if err != nil {
		t.Fatalf("NewRPM returned error %v", err)
	}
	group := "testGroup"
	user := "testUser"

	r.AddFile(RPMFile{
		Name:  "/usr/local/hello",
		Body:  []byte("content of the file"),
		Group: group,
		Owner: user,
	})

	if err := r.Write(io.Discard); err != nil {
		t.Errorf("NewRPM returned error %v", err)
	}
	if r.fileowners[0] != user {
		t.Errorf("File owner shoud be %s but is %s", user, r.fileowners[0])
	}
	if r.filegroups[0] != group {
		t.Errorf("File owner shoud be %s but is %s", group, r.filegroups[0])
	}
}

// https://github.com/M0Rf30/rpmpack/issues/49
func Test100644(t *testing.T) {
	r, err := NewRPM(RPMMetaData{})
	if err != nil {
		t.Fatalf("NewRPM returned error %v", err)
	}
	r.AddFile(RPMFile{
		Name: "/usr/local/hello",
		Body: []byte("content of the file"),
		Mode: 0100644,
	})

	if err := r.Write(io.Discard); err != nil {
		t.Errorf("Write returned error %v", err)
	}
	if r.filemodes[0] != 0100644 {
		t.Errorf("file mode want 0100644, got %o", r.filemodes[0])
	}
	if r.filelinktos[0] != "" {
		t.Errorf("linktos want empty (not a symlink), got %q", r.filelinktos[0])
	}
}

func TestCompression(t *testing.T) {
	testCases := []struct {
		Type           string
		Compressors    []string
		ExpectedWriter io.Writer
	}{
		{
			Type: "gzip",
			Compressors: []string{
				"", "gzip", "gzip:1", "gzip:2", "gzip:3",
				"gzip:4", "gzip:5", "gzip:6", "gzip:7", "gzip:8", "gzip:9",
			},
			ExpectedWriter: &gzip.Writer{},
		},
		{
			Type:           "gzip",
			Compressors:    []string{"gzip:fast", "gzip:10"},
			ExpectedWriter: nil, // gzip requires an integer level from -2 to 9
		},
		{
			Type:           "lzma",
			Compressors:    []string{"lzma"},
			ExpectedWriter: &lzma.Writer{},
		},
		{
			Type:           "lzma",
			Compressors:    []string{"lzma:fast", "lzma:1"},
			ExpectedWriter: nil, // lzma does not support specifying the compression level
		},
		{
			Type:           "xz",
			Compressors:    []string{"xz"},
			ExpectedWriter: &xz.Writer{},
		},
		{
			Type:           "xz",
			Compressors:    []string{"xz:fast", "xz:1"},
			ExpectedWriter: nil, // xz does not support specifying the compression level
		},
		{
			Type: "zstd",
			Compressors: []string{
				"zstd", "zstd:fastest", "zstd:default", "zstd:better",
				"zstd:best", "zstd:BeSt", "zstd:0", "zstd:4", "zstd:8", "zstd:15",
			},
			ExpectedWriter: &zstd.Encoder{},
		},
		{
			Type:           "zstd",
			Compressors:    []string{"xz:worst"},
			ExpectedWriter: nil, // only integers levels or one of the pre-defined string values
		},
	}

	for _, testCase := range testCases {
		for _, compressor := range testCase.Compressors {
			t.Run(compressor, func(t *testing.T) {
				r, err := NewRPM(RPMMetaData{
					Compressor: compressor,
				})
				if err != nil {
					if testCase.ExpectedWriter == nil {
						return // an error is expected
					}

					t.Fatalf("NewRPM returned error %v", err)
				}

				if testCase.ExpectedWriter == nil {
					t.Fatalf("compressor %q should have produced an error", compressor)
				}

				if r.Compressor != testCase.Type {
					t.Fatalf("expected compressor %q, got %q", compressor,
						r.Compressor)
				}

				expectedWriterType := reflect.Indirect(reflect.ValueOf(
					testCase.ExpectedWriter)).String()
				actualWriterType := reflect.Indirect(reflect.ValueOf(
					r.compressedPayload)).String()

				if expectedWriterType != actualWriterType {
					t.Fatalf("expected writer to be %T, got %T instead",
						testCase.ExpectedWriter, r.compressedPayload)
				}
			})
		}
	}
}

func TestAllowListDirs(t *testing.T) {
	r, err := NewRPM(RPMMetaData{})
	if err != nil {
		t.Fatalf("NewRPM returned error %v", err)
	}

	r.AddFile(RPMFile{
		Name: "/usr/local/dir1",
		Mode: 040000,
	})
	r.AddFile(RPMFile{
		Name: "/usr/local/dir2",
		Mode: 040000,
	})

	r.AllowListDirs(map[string]bool{"/usr/local/dir1": true})

	if err := r.Write(io.Discard); err != nil {
		t.Errorf("NewRPM returned error %v", err)
	}
	expected := map[string]RPMFile{"/usr/local/dir1": {Name: "/usr/local/dir1", Mode: 040000}}
	if d := cmp.Diff(expected, r.files); d != "" {
		t.Errorf("Expected dirs differs (want->got):\n%v", d)
	}
}

func TestMinimalSpec(t *testing.T) {
	r, err := NewRPM(RPMMetaData{
		Name:        "test",
		Version:     "1.0",
		Release:     "1",
		Summary:     "test summary",
		Description: "test description",
		Licence:     "test license",
	})
	if err != nil {
		t.Fatalf("NewRPM returned error %v", err)
	}

	var b bytes.Buffer
	if err := r.Write(&b); err != nil {
		t.Errorf("Write returned error %v", err)
	}
}

func TestChangelog(t *testing.T) {
	r, err := NewRPM(RPMMetaData{
		Name:    "test",
		Version: "1.0",
		Release: "1",
		Changelog: []ChangelogEntry{
			{Time: time.Unix(1700000000, 0), Author: "Test User <test@example.com>", Text: "- Initial release"},
			{Time: time.Unix(1699000000, 0), Author: "Test User <test@example.com>", Text: "- Pre-release"},
		},
	})
	if err != nil {
		t.Fatalf("NewRPM returned error %v", err)
	}

	var b bytes.Buffer
	if err := r.Write(&b); err != nil {
		t.Errorf("Write returned error %v", err)
	}
}

func TestEnhancesSupplements(t *testing.T) {
	r, err := NewRPM(RPMMetaData{
		Name:    "test",
		Version: "1.0",
		Release: "1",
	})
	if err != nil {
		t.Fatalf("NewRPM returned error %v", err)
	}

	r.Enhances = append(r.Enhances, &Relation{
		Name:  "enhanced-package",
		Sense: SenseEqual,
	})
	r.Supplements = append(r.Supplements, &Relation{
		Name:  "supplemented-package",
		Sense: SenseEqual,
	})

	var b bytes.Buffer
	if err := r.Write(&b); err != nil {
		t.Errorf("Write returned error %v", err)
	}
}

func TestDistributionBugURL(t *testing.T) {
	r, err := NewRPM(RPMMetaData{
		Name:         "test",
		Version:      "1.0",
		Release:      "1",
		Distribution: "Fedora",
		BugURL:       "https://bugzilla.example.com",
	})
	if err != nil {
		t.Fatalf("NewRPM returned error %v", err)
	}

	var b bytes.Buffer
	if err := r.Write(&b); err != nil {
		t.Errorf("Write returned error %v", err)
	}
}

func TestWriteTwice(t *testing.T) {
	r, err := NewRPM(RPMMetaData{Name: "twice", Version: "1"})
	if err != nil {
		t.Fatal(err)
	}
	r.AddFile(RPMFile{Name: "/a", Body: []byte("a"), Mode: 0644})
	if err := r.Write(io.Discard); err != nil {
		t.Fatalf("first Write: %v", err)
	}
	if err := r.Write(io.Discard); !errors.Is(err, ErrWriteAfterClose) {
		t.Errorf("second Write error = %v, want ErrWriteAfterClose", err)
	}
}

func TestWriteRejectsInvalidFile(t *testing.T) {
	big := func() []byte {
		if strconv.IntSize < 64 {
			t.Skip("needs a 4 GiB slice")
		}
		// The pages are never touched, so this only reserves address space.
		return make([]byte, maxV4FileSize+1)
	}
	testCases := []struct {
		name   string
		file   func() RPMFile
		format int
		wantOK bool
	}{
		{name: "relative", file: func() RPMFile { return RPMFile{Name: "usr/bin/x"} }},
		{name: "empty", file: func() RPMFile { return RPMFile{Name: ""} }},
		{name: "dotdot", file: func() RPMFile { return RPMFile{Name: "/usr/../etc/passwd"} }},
		{name: "dot", file: func() RPMFile { return RPMFile{Name: "/usr/./bin"} }},
		{name: "double slash", file: func() RPMFile { return RPMFile{Name: "/usr//bin"} }},
		{name: "trailing slash", file: func() RPMFile { return RPMFile{Name: "/usr/bin/", Mode: 040755} }},
		{name: "NUL in name", file: func() RPMFile { return RPMFile{Name: "/usr/bin/x\x00y"} }},
		{name: "NUL in owner", file: func() RPMFile { return RPMFile{Name: "/x", Owner: "ro\x00ot"} }},
		{name: "NUL in group", file: func() RPMFile { return RPMFile{Name: "/x", Group: "ro\x00ot"} }},
		{name: "NUL in symlink target", file: func() RPMFile {
			return RPMFile{Name: "/x", Mode: 0120777, Body: []byte("a\x00b")}
		}},
		{name: "mode over 16 bits", file: func() RPMFile { return RPMFile{Name: "/x", Mode: 1 << 16} }},
		{name: "v4 file over 4 GiB", file: func() RPMFile { return RPMFile{Name: "/x", Mode: 0644, Body: big()} }},
		{name: "v4 ghost over 4 GiB", file: func() RPMFile {
			return RPMFile{Name: "/x", Mode: 0644, Body: big(), Type: GhostFile}
		}},
		{name: "v6 file over 4 GiB is allowed", format: FormatV6, wantOK: true, file: func() RPMFile {
			return RPMFile{Name: "/x", Mode: 0644, Body: big()}
		}},
		{name: "clean absolute", wantOK: true, file: func() RPMFile { return RPMFile{Name: "/usr/bin/x", Mode: 0755} }},
		{name: "NUL in regular file body is fine", wantOK: true, file: func() RPMFile {
			return RPMFile{Name: "/x", Mode: 0644, Body: []byte("a\x00b")}
		}},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := NewRPM(RPMMetaData{Name: "x", Version: "1", Format: tc.format})
			if err != nil {
				t.Fatal(err)
			}
			f := tc.file()
			r.AddFile(f)
			err = r.validateFile(f)
			if tc.wantOK {
				if err != nil {
					t.Errorf("validateFile: %v", err)
				}
				return
			}
			if !errors.Is(err, ErrInvalidFile) {
				t.Fatalf("validateFile error = %v, want ErrInvalidFile", err)
			}
			if err := r.Write(io.Discard); !errors.Is(err, ErrInvalidFile) {
				t.Errorf("Write error = %v, want ErrInvalidFile", err)
			}
			// A failed validation must not consume the rpm.
			delete(r.files, f.Name)
			if err := r.Write(io.Discard); err != nil {
				t.Errorf("Write after removing the invalid file: %v", err)
			}
		})
	}
}

func TestWriteRejectsInvalidMetadata(t *testing.T) {
	testCases := []struct {
		name string
		edit func(r *RPM)
	}{
		{name: "NUL in name", edit: func(r *RPM) { r.Name = "a\x00b" }},
		{name: "NUL in summary", edit: func(r *RPM) { r.Summary = "a\x00b" }},
		{name: "NUL in prefix", edit: func(r *RPM) { r.Prefixes = []string{"/a\x00b"} }},
		{name: "NUL in scriptlet", edit: func(r *RPM) { r.AddPostin("a\x00b") }},
		{name: "NUL in changelog", edit: func(r *RPM) {
			r.Changelog = []ChangelogEntry{{Time: time.Unix(1, 0), Author: "a", Text: "b\x00"}}
		}},
		{name: "NUL in relation", edit: func(r *RPM) { r.Requires = Relations{{Name: "a\x00b"}} }},
		{name: "nil relation", edit: func(r *RPM) { r.Conflicts = Relations{nil} }},
		{name: "build time before 1970", edit: func(r *RPM) { r.BuildTime = time.Unix(-1, 0) }},
		{name: "build time after 2106", edit: func(r *RPM) { r.BuildTime = time.Unix(math.MaxUint32+1, 0) }},
		{name: "changelog time before 1970", edit: func(r *RPM) {
			r.Changelog = []ChangelogEntry{{Time: time.Unix(-1, 0)}}
		}},
		{name: "zero changelog time", edit: func(r *RPM) { r.Changelog = []ChangelogEntry{{}} }},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := NewRPM(RPMMetaData{Name: "x", Version: "1"})
			if err != nil {
				t.Fatal(err)
			}
			tc.edit(r)
			if err := r.Write(io.Discard); !errors.Is(err, ErrInvalidMetadata) {
				t.Errorf("Write error = %v, want ErrInvalidMetadata", err)
			}
		})
	}
}

// Times past 2038 do not fit a signed 32 bit time, but rpm reads them as unsigned.
func TestWriteTimesPast2038(t *testing.T) {
	const ts = int64(1) << 31 // 2038-01-19
	r, err := NewRPM(RPMMetaData{
		Name: "x", Version: "1", BuildTime: time.Unix(ts, 0),
		Changelog: []ChangelogEntry{{Time: time.Unix(ts+1, 0), Author: "a", Text: "b"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := r.Write(&b); err != nil {
		t.Fatal(err)
	}
	p := parseRPM(t, b.Bytes())
	if got := p.main.ints(t, tagBuildTime, typeInt32); len(got) != 1 || got[0] != uint64(ts) {
		t.Errorf("build time = %v, want %d", got, ts)
	}
	if got := p.main.ints(t, tagChangelogTime, typeInt32); len(got) != 1 || got[0] != uint64(ts+1) {
		t.Errorf("changelog time = %v, want %d", got, ts+1)
	}
}

func TestSizeTags(t *testing.T) {
	const (
		small = 1 << 20
		over2 = 3 << 30 // does not fit int32: used to be written as a negative size
		over4 = 5 << 30 // does not fit uint32
	)
	testCases := []struct {
		name        string
		payloadSize uint64
		wantSize    bool // SIZE (32 bit) instead of LONGSIZE (64 bit)
	}{
		{"small", small, true},
		{"over 2 GiB", over2, true},
		{"max uint32", math.MaxUint32, true},
		{"over 4 GiB", over4, false},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := NewRPM(RPMMetaData{Name: "x", Version: "1", Epoch: NoEpoch})
			if err != nil {
				t.Fatal(err)
			}
			r.AddFile(RPMFile{Name: "/a", Body: []byte("a"), Mode: 0644})
			// Pretend the files are big: the sizes are only read when writing the headers.
			r.payloadSize = tc.payloadSize - 1 // the file adds 1
			var b bytes.Buffer
			if err := r.Write(&b); err != nil {
				t.Fatal(err)
			}
			p := parseRPM(t, b.Bytes())
			_, hasSize := p.main.entries[tagSize]
			_, hasLong := p.main.entries[tagLongSize]
			_, hasSigArchive := p.sig.entries[sigPayloadSize]
			_, hasSigLongArchive := p.sig.entries[sigLongArchiveSize]
			if hasSize != tc.wantSize || hasLong == tc.wantSize || hasSigArchive != tc.wantSize || hasSigLongArchive == tc.wantSize {
				t.Fatalf("tags: SIZE=%v LONGSIZE=%v SIG_PAYLOADSIZE=%v SIG_LONGARCHIVESIZE=%v, want 32 bit tags: %v",
					hasSize, hasLong, hasSigArchive, hasSigLongArchive, tc.wantSize)
			}
			if tc.wantSize {
				if got := p.main.ints(t, tagSize, typeInt32); got[0] != tc.payloadSize {
					t.Errorf("SIZE = %d, want %d", got[0], tc.payloadSize)
				}
				if got := p.sig.ints(t, sigPayloadSize, typeInt32); got[0] != tc.payloadSize {
					t.Errorf("SIG_PAYLOADSIZE = %d, want %d", got[0], tc.payloadSize)
				}
			} else {
				if got := p.main.ints(t, tagLongSize, typeInt64); got[0] != tc.payloadSize {
					t.Errorf("LONGSIZE = %d, want %d", got[0], tc.payloadSize)
				}
				if got := p.sig.ints(t, sigLongArchiveSize, typeInt64); got[0] != tc.payloadSize {
					t.Errorf("LONGARCHIVESIZE = %d, want %d", got[0], tc.payloadSize)
				}
			}
			// The sizes of header and payload are small here, so they stay 32 bit.
			if _, ok := p.sig.entries[sigSize]; !ok {
				t.Error("signature header lacks SIG_SIZE")
			}
			hasLargeFiles := false
			if _, ok := p.main.entries[tagRequires]; ok {
				for _, name := range p.main.strs(t, tagRequires) {
					hasLargeFiles = hasLargeFiles || name == "rpmlib(LargeFiles)"
				}
			}
			if hasLargeFiles == tc.wantSize {
				t.Errorf("rpmlib(LargeFiles) requirement = %v, want %v", hasLargeFiles, !tc.wantSize)
			}
		})
	}
}

func TestAddSignatureSizes(t *testing.T) {
	s := newIndex(signatures)
	addSignatureSizes(s, math.MaxUint32+1, math.MaxUint32)
	if _, ok := s.entries[sigLongSize]; !ok {
		t.Error("want LONGSIGSIZE for a size over 4 GiB")
	}
	if _, ok := s.entries[sigSize]; ok {
		t.Error("SIG_SIZE must not be set along with LONGSIGSIZE")
	}
	if _, ok := s.entries[sigPayloadSize]; !ok {
		t.Error("want SIG_PAYLOADSIZE for a size of 4 GiB - 1")
	}
}

func TestFileSize32(t *testing.T) {
	if got := fileSize32(7); got != 7 {
		t.Errorf("fileSize32(7) = %d", got)
	}
	if strconv.IntSize == 64 {
		if got := fileSize32(1 << 33); got != math.MaxUint32 {
			t.Errorf("fileSize32(1<<33) = %d, want saturation", got)
		}
	}
}
