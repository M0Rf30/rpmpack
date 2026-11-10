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
	"errors"
	"fmt"
	"io"
	"math"
	"path"
)

// FromTar reads a tar file and creates an rpm struct.
//
// The tar is treated as untrusted. Regular files, directories and symlinks are
// supported; PAX global headers are skipped and any other entry type is an error.
// Entry names are resolved against "/" with path.Join, so "../" sequences cannot
// escape the root of the package. Only the permission bits (including setuid,
// setgid and sticky) of the tar mode are used: the file type comes from the tar
// entry type, never from mode bits. Symlink targets are stored as they are.
// The whole tar content is kept in memory.
func FromTar(inp io.Reader, md RPMMetaData) (*RPM, error) {
	r, err := NewRPM(md)
	if err != nil {
		return nil, fmt.Errorf("failed to create RPM structure: %w", err)
	}
	t := tar.NewReader(inp)
	for {
		h, err := t.Next()
		if errors.Is(err, io.EOF) {
			return r, nil
		} else if err != nil {
			return nil, fmt.Errorf("failed to read tar file: %w", err)
		}
		var body []byte
		// The type bits of the tar mode are untrusted: a regular file with the
		// symlink or directory bits set would change the type of the rpm entry.
		mode := uint(h.Mode & 07777)
		switch h.Typeflag {
		case tar.TypeXGlobalHeader:
			// Metadata of the archive as a whole, e.g. written by git archive.
			continue
		case tar.TypeDir:
			mode |= 040000
		case tar.TypeSymlink:
			body = []byte(h.Linkname)
			mode |= 0120000
		case tar.TypeReg:
			if md.Format != FormatV6 && h.Size > maxV4FileSize {
				return nil, fmt.Errorf("file %q is %d bytes, the v4 format supports files up to 4 GiB - 1 (use FormatV6)",
					h.Name, h.Size)
			}
			b, err := io.ReadAll(t)
			if err != nil {
				return nil, fmt.Errorf("failed to read file (%q): %w", h.Name, err)
			}
			body = b
		default:
			return nil, fmt.Errorf("unknown tar type: %d, (%q)", h.Typeflag, h.Name)
		}
		if u := h.ModTime.Unix(); u < 0 || u > math.MaxUint32 {
			return nil, fmt.Errorf("modification time %v of %q is outside 1970..2106, the range of a 32 bit rpm time",
				h.ModTime, h.Name)
		}
		mtime := uint32(h.ModTime.Unix())

		// Sometimes the tar has no uname and gname. RPM expects these to always exist.
		owner := h.Uname
		if owner == "" {
			owner = "root"
		}
		group := h.Gname
		if group == "" {
			group = "root"
		}

		r.AddFile(
			RPMFile{
				Name:  path.Join("/", h.Name), //nolint:gosec // path.Join sanitizes traversal sequences
				Body:  body,
				Mode:  mode,
				Owner: owner,
				Group: group,
				MTime: mtime,
			})
	}
}
