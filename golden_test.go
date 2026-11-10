package rpmpack

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"testing"
	"time"
)

// goldenV4Sum is the goldenDigest of the package written by buildGoldenV4. It pins
// the v4 output (recorded with the code at v0.7.1 plus v6 support): any change to
// it needs to be a deliberate format change.
const goldenV4Sum = "fe1648f19d134819df218d99595fcd8eea11878c453c1e6d7491ae42b04a1e6b"

func buildGoldenV4(t *testing.T) []byte {
	t.Helper()
	r, err := NewRPM(RPMMetaData{
		Name: "golden", Version: "1.2.3", Release: "4", Epoch: 7,
		Summary: "summary", Description: "description", Licence: "MIT",
		Arch: "x86_64", BuildHost: "host", BuildTime: time.Unix(1700000000, 0),
		Prefixes:  []string{"/opt"},
		Changelog: []ChangelogEntry{{Time: time.Unix(1699000000, 0), Author: "a <a@b>", Text: "- x"}},
		Requires:  Relations{{Name: "bash", Version: "4", Sense: SenseGreater | SenseEqual}},
	})
	if err != nil {
		t.Fatal(err)
	}
	r.AddFile(RPMFile{Name: "/opt/golden", Mode: 040755, Owner: "root", Group: "root", MTime: 1700000001})
	r.AddFile(RPMFile{Name: "/opt/golden/a.txt", Body: []byte("hello\n"), Mode: 0644, Owner: "root", Group: "root", MTime: 1700000002})
	r.AddFile(RPMFile{Name: "/opt/golden/b.cfg", Body: []byte("cfg\n"), Mode: 0600, Owner: "u", Group: "g", MTime: 1700000003, Type: ConfigFile})
	r.AddFile(RPMFile{Name: "/opt/golden/link", Body: []byte("a.txt"), Mode: 0120777, Owner: "root", Group: "root", MTime: 1700000004})
	r.AddFile(RPMFile{Name: "/opt/golden/ghost", Mode: 0644, Owner: "root", Group: "root", Type: GhostFile})
	r.AddPostin("echo hi")
	r.SetPGPSigner(func(b []byte) ([]byte, error) {
		s := sha256.Sum256(b)
		return s[:], nil
	})
	var b bytes.Buffer
	if err := r.Write(&b); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// goldenDigest hashes everything in the package that is independent of the
// compressor implementation: the lead, all main header entries but the digest of
// the compressed payload, the tags of the signature header, and the uncompressed
// payload. The compressed bytes themselves are allowed to change with the
// compression libraries.
func goldenDigest(t *testing.T, pkg []byte) string {
	t.Helper()
	p := parseRPM(t, pkg)
	h := sha256.New()
	h.Write(p.lead)
	for _, tag := range p.main.tags() {
		if tag == tagPayloadDigest {
			continue
		}
		e := p.main.entries[tag]
		fmt.Fprintf(h, "%d/%d/%d/%x;", tag, e.typ, e.count, e.data)
	}
	fmt.Fprint(h, p.sig.tags())
	h.Write(decompress(t, "gzip", p.payload))
	return fmt.Sprintf("%x", h.Sum(nil))
}

func TestV4OutputIsStable(t *testing.T) {
	got := goldenDigest(t, buildGoldenV4(t))
	if got != goldenV4Sum {
		t.Errorf("v4 output changed: digest %s, want %s", got, goldenV4Sum)
	}
}
