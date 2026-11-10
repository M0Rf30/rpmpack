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
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"
	"io"
	"net/http"
	"strings"
)

const (
	// FormatV4 selects the classic RPM v4 package format. It is the default.
	FormatV4 = 4
	// FormatV6 selects the RPM v6 package format written by rpm >= 6.0.
	FormatV6 = 6
)

// v6SigReserved is the size of the reserved space in the signature header of an
// unsigned v6 package, as written by rpmbuild 6. Signatures shrink it so that the
// total signature header size stays the same, which lets rpmsign add signatures
// in place.
const v6SigReserved = 4128

// v6State holds the state needed to write a v6 package: the stripped cpio
// payload stream, the digests of its uncompressed bytes, and per file data
// that only exists in v6 headers.
type v6State struct {
	// out receives the uncompressed payload. It feeds the compressor and the
	// hashes below.
	out    io.Writer
	sha256 hash.Hash
	sha512 hash.Hash
	sha3   hash.Hash
	// size is the number of uncompressed payload bytes written.
	size int64

	filesizes []uint64
	mimeIdx   []uint32
	mimeDict  []string
	mimeLook  map[string]uint32
}

func newV6State(compressed io.Writer) *v6State {
	s := &v6State{
		sha256:   sha256.New(),
		sha512:   sha512.New(),
		sha3:     sha3.New256(),
		mimeLook: make(map[string]uint32),
	}
	s.out = io.MultiWriter(compressed, s.sha256, s.sha512, s.sha3)
	return s
}

func (s *v6State) write(b []byte) error {
	n, err := s.out.Write(b)
	s.size += int64(n)
	return err
}

// pad4 writes zero bytes to bring n (the number of bytes written since the
// start of the entry) to a multiple of four.
func (s *v6State) pad4(n int) error {
	if p := (4 - n%4) % 4; p > 0 {
		return s.write(make([]byte, p))
	}
	return nil
}

// writeEntry writes a stripped cpio entry: "07070X", the index of the file in
// the header file order as 8 hex digits, padding to 4 bytes, the content and
// padding again.
func (s *v6State) writeEntry(index int, content []byte) error {
	hdr := fmt.Sprintf("07070X%08x", index)
	if err := s.write([]byte(hdr)); err != nil {
		return err
	}
	if err := s.pad4(len(hdr)); err != nil {
		return err
	}
	if err := s.write(content); err != nil {
		return err
	}
	return s.pad4(len(content))
}

// writeTrailer writes the regular newc trailer which terminates the stripped cpio.
func (s *v6State) writeTrailer() error {
	const name = "TRAILER!!!\x00"
	// ino, mode, uid, gid, nlink, mtime, filesize, devmajor, devminor,
	// rdevmajor, rdevminor, namesize, check
	t := fmt.Sprintf("070701%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
		0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, len(name), 0)
	if err := s.write([]byte(t)); err != nil {
		return err
	}
	// the header is 110 bytes, which is not a multiple of 4: the name is
	// padded so that the header plus name is.
	if err := s.write([]byte(name)); err != nil {
		return err
	}
	return s.pad4(len(t) + len(name))
}

func (s *v6State) addFile(size uint64, mime string) {
	s.filesizes = append(s.filesizes, size)
	idx, ok := s.mimeLook[mime]
	if !ok {
		idx = uint32(len(s.mimeDict))
		s.mimeDict = append(s.mimeDict, mime)
		s.mimeLook[mime] = idx
	}
	s.mimeIdx = append(s.mimeIdx, idx)
}

// mimeType classifies a file for the MIMEDICT/FILEMIMEINDEX tags.
// rpm uses libmagic; to stay dependency free and deterministic we use:
// inode/directory and inode/symlink by file mode, inode/x-empty for empty
// files and ghost files (which have no content), and otherwise the sniffed
// type of net/http.DetectContentType (first 512 bytes) without parameters,
// which is one of text/plain, application/octet-stream or a well known
// binary format such as application/gzip.
func mimeType(f RPMFile) string {
	switch {
	case f.Mode&040000 != 0:
		return "inode/directory"
	case f.Mode&0120000 == 0120000:
		return "inode/symlink"
	case f.Type == GhostFile || len(f.Body) == 0:
		return "inode/x-empty"
	}
	ct, _, _ := strings.Cut(http.DetectContentType(f.Body), ";")
	return ct
}

// v6Requires returns the user requirements plus the rpmlib(...) requirements
// rpm 6 adds to a v6 package.
func (r *RPM) v6Requires() Relations {
	reqs := append(Relations{}, r.Requires...)
	reqs.addIfMissing(largeFilesRequire())

	var compressorDep *Relation
	switch r.Compressor {
	case "zstd":
		compressorDep = &Relation{Name: "rpmlib(PayloadIsZstd)", Version: "5.4.18-1"}
	case "xz":
		compressorDep = &Relation{Name: "rpmlib(PayloadIsXz)", Version: "5.2-1"}
	case "lzma":
		compressorDep = &Relation{Name: "rpmlib(PayloadIsLzma)", Version: "4.4.6-1"}
	}
	if compressorDep != nil {
		compressorDep.Sense = SenseRPMLIB | SenseLess | SenseEqual
		reqs.addIfMissing(compressorDep)
	}
	return reqs
}

// writeV6Indexes adds the main header tags that only exist in v6 packages.
func (r *RPM) writeV6Indexes(h *index) {
	h.Add(tagRPMFormat, EntryInt32([]int32{FormatV6}))
	h.Add(tagEncoding, EntryString("utf-8"))

	nevr := r.Name + "-" + r.FullVersion()
	if r.Epoch != NoEpoch {
		nevr = fmt.Sprintf("%s-%d:%s", r.Name, r.Epoch, r.FullVersion())
	}
	h.Add(tagSourceNEVR, EntryString(nevr))

	// Digests of the compressed payload, then of the uncompressed one (ALT).
	h.Add(tagPayloadDigestAlt, EntryStringSlice([]string{fmt.Sprintf("%x", r.v6.sha256.Sum(nil))}))
	h.Add(tagPayloadSHA512, EntryString(fmt.Sprintf("%x", sha512.Sum512(r.payload.Bytes()))))
	h.Add(tagPayloadSHA512Alt, EntryString(fmt.Sprintf("%x", r.v6.sha512.Sum(nil))))
	h.Add(tagPayloadSHA3256, EntryString(fmt.Sprintf("%x", sha3.Sum256(r.payload.Bytes()))))
	h.Add(tagPayloadSHA3256Alt, EntryString(fmt.Sprintf("%x", r.v6.sha3.Sum(nil))))
	h.Add(tagPayloadSize, EntryInt64([]int64{int64(r.payload.Len())}))
	h.Add(tagPayloadSizeAlt, EntryInt64([]int64{r.v6.size}))
	h.Add(tagLongSize, EntryUint64([]uint64{uint64(r.payloadSize)}))

	if len(r.basenames) > 0 {
		h.Add(tagLongFileSizes, EntryUint64(r.v6.filesizes))
		h.Add(tagFileMimeIndex, EntryUint32(r.v6.mimeIdx))
		h.Add(tagMimeDict, EntryStringSlice(r.v6.mimeDict))
	}
}

// signatureHeaderV6 builds the (8-byte padded) v6 signature header for the main header hb.
// It only holds tags <= 999: the SHA256 and SHA3-256 digests of the header, an OpenPGP
// signature of the header when a signer is set, and reserved space.
func (r *RPM) signatureHeaderV6(hb []byte) ([]byte, error) {
	s := newIndex(signatures)
	s.Add(sigSHA256, EntryString(fmt.Sprintf("%x", sha256.Sum256(hb))))
	s.Add(sigSHA3256, EntryString(fmt.Sprintf("%x", sha3.Sum256(hb))))
	// The reserved space is sized so that the total signature header length
	// is the one of an unsigned package, as rpm does.
	base, err := s.Bytes()
	if err != nil {
		return nil, err
	}
	total := len(base) + 16 + v6SigReserved

	if r.pgpSigner != nil {
		sig, err := r.pgpSigner(append([]byte{}, hb...))
		if err != nil {
			return nil, fmt.Errorf("call to signer failed: %w", err)
		}
		s.Add(sigOpenPGP, EntryStringSlice([]string{base64.StdEncoding.EncodeToString(sig)}))
	}
	s.AddEntries(r.customSigs)

	without, err := s.Bytes()
	if err != nil {
		return nil, err
	}
	if reserved := total - len(without) - 16; reserved > 0 {
		s.Add(sigReserved, EntryBytes(make([]byte, reserved)))
	}
	sb, err := s.Bytes()
	if err != nil {
		return nil, err
	}
	// Signatures are padded to 8-byte boundaries
	return append(sb, make([]byte, (8-len(sb)%8)%8)...), nil
}
