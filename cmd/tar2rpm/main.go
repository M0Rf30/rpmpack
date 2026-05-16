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

package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/rpmpack"
)

const (
	// DashStdinStdout is the pseudo-filename for stdin/stdout.
	DashStdinStdout = "-"
)

// changelogEntries is a custom flag type for parsing changelog entries.
// Each entry is in the format "TIMESTAMP|AUTHOR|TEXT" where TIMESTAMP is a Unix timestamp.
type changelogEntries []rpmpack.ChangelogEntry

func (c *changelogEntries) String() string {
	return fmt.Sprintf("%v", []rpmpack.ChangelogEntry(*c))
}

func (c *changelogEntries) Set(value string) error {
	parts := strings.SplitN(value, "|", 3)
	if len(parts) != 3 {
		return fmt.Errorf("changelog entry must be in format 'TIMESTAMP|AUTHOR|TEXT', got: %s", value)
	}

	timestamp, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return fmt.Errorf("invalid timestamp in changelog entry: %s", parts[0])
	}

	entry := rpmpack.ChangelogEntry{
		Time:   time.Unix(timestamp, 0),
		Author: parts[1],
		Text:   parts[2],
	}

	*c = append(*c, entry)
	return nil
}

var (
	provides,
	obsoletes,
	suggests,
	recommends,
	requires,
	conflicts,
	enhances,
	supplements rpmpack.Relations
	name        = flag.String("name", "", "the package name")
	version     = flag.String("version", "", "the package version")
	release     = flag.String("release", "", "the rpm release")
	epoch       = flag.Uint64("epoch", 0, "the rpm epoch")
	arch        = flag.String("arch", "noarch", "the rpm architecture")
	prefixes    = flag.String("prefixes", "", "comma separated prefixes for relocatable packages")
	buildTime   = flag.Int64("build_time", 0, "the build_time unix timestamp")
	compressor  = flag.String("compressor", "gzip", "the rpm compressor")
	osName      = flag.String("os", "linux", "the rpm os")
	summary     = flag.String("summary", "", "the rpm summary")
	description = flag.String("description", "", "the rpm description")
	vendor      = flag.String("vendor", "", "the rpm vendor")
	packager    = flag.String("packager", "", "the rpm packager")
	group       = flag.String("group", "", "the rpm group")
	url         = flag.String("url", "", "the rpm url")
	licence     = flag.String("licence", "", "the rpm licence name")
	distribution = flag.String("distribution", "", "the rpm distribution")
	bugurl      = flag.String("bugurl", "", "the rpm bug report URL")

	prein  = flag.String("prein", "", "prein scriptlet contents (not filename)")
	postin = flag.String("postin", "", "postin scriptlet contents (not filename)")
	preun  = flag.String("preun", "", "preun scriptlet contents (not filename)")
	postun = flag.String("postun", "", "postun scriptlet contents (not filename)")

	useDirAllowlist  = flag.Bool("use_dir_allowlist", false, "Only include dirs in the explicit allow list")
	dirAllowlistFile = flag.String("dir_allowlist_file", "", "A file with one directory per line to include from the tar to the rpm")

	outputfile = flag.String("file", "", "write rpm to `RPMFILE` instead of stdout")
	changelog  changelogEntries
)

func usage() {
	fmt.Fprintf(os.Stderr,
		`Usage:
  %s -name NAME -version VERSION [OPTION] [TARFILE]
        Read tar content from stdin, or TARFILE if present. Write rpm to stdout, or the file given
        by -file RPMFILE. If a filename is '%s' use stdin/stdout without printing a notice.
Options:
`, os.Args[0], DashStdinStdout)
	flag.PrintDefaults()
}

func main() {
	flag.Var(&provides, "provides", "rpm provides values, can be just name or in the form of name=version (eg. bla=1.2.3)")
	flag.Var(&obsoletes, "obsoletes", "rpm obsoletes values, can be just name or in the form of name=version (eg. bla=1.2.3)")
	flag.Var(&suggests, "suggests", "rpm suggests values, can be just name or in the form of name=version (eg. bla=1.2.3)")
	flag.Var(&recommends, "recommends", "rpm recommends values, can be just name or in the form of name=version (eg. bla=1.2.3)")
	flag.Var(&requires, "requires", "rpm requires values, can be just name or in the form of name=version (eg. bla=1.2.3)")
	flag.Var(&conflicts, "conflicts", "rpm provides values, can be just name or in the form of name=version (eg. bla=1.2.3)")
	flag.Var(&enhances, "enhances", "rpm enhances values, can be just name or in the form of name=version (eg. bla=1.2.3)")
	flag.Var(&supplements, "supplements", "rpm supplements values, can be just name or in the form of name=version (eg. bla=1.2.3)")
	flag.Var(&changelog, "changelog", "rpm changelog entry in format 'TIMESTAMP|AUTHOR|TEXT' where TIMESTAMP is a Unix timestamp")
	flag.Usage = usage
	flag.Parse()
	if *name == "" || *version == "" {
		fmt.Fprintln(os.Stderr, "name and version are required")
		flag.Usage()
		os.Exit(2)
	}
	if *epoch > math.MaxUint32 {
		fmt.Fprintf(os.Stderr, "epoch has to be less than %d\n", math.MaxUint32)
		flag.Usage()
		os.Exit(2)
	}
	var buildTimeStamp time.Time
	if *buildTime != 0 {
		buildTimeStamp = time.Unix(*buildTime, 0)
	}

	noticeStdinStdout := ""
	var i io.Reader
	switch flag.NArg() {
	case 0:
		// Only print notice if no explicit '-' is given:
		noticeStdinStdout = "reading tar content from stdin"
		i = os.Stdin
	case 1:
		if flag.Arg(0) == DashStdinStdout {
			i = os.Stdin
		} else {
			f, err := os.Open(flag.Arg(0))
			if err != nil {
				log.Fatalf("Failed to open file %s for reading\n", flag.Arg(0))
			}
			i = f
		}

	default:
		fmt.Fprintln(os.Stderr, "expecting 0 or 1 positional arguments")
		flag.Usage()
		os.Exit(2)
	}

	w := os.Stdout
	if *outputfile != DashStdinStdout {
		if *outputfile != "" {
			f, err := os.Create(*outputfile)
			if err != nil {
				log.Fatalf("Failed to open file %s for writing", *outputfile)
			}
			defer func() {
				if err := f.Close(); err != nil {
					log.Printf("failed to close file: %v", err)
				}
			}()
			w = f
		} else {
		        // Only print notice if no explicit '-' is given, merge with tar notice:
			if noticeStdinStdout != "" {
				noticeStdinStdout += ", "
			}
			noticeStdinStdout += "writing rpm to stdout"

		}
	}
	if noticeStdinStdout != "" {
		fmt.Fprintln(os.Stderr, "tar2rpm: "+noticeStdinStdout+".")
	}
	r, err := rpmpack.FromTar(
		i,
		rpmpack.RPMMetaData{
			Name:        *name,
			Version:     *version,
			Release:     *release,
			Epoch:       uint32(*epoch),
			BuildTime:   buildTimeStamp,
			Prefixes:    strings.Split(*prefixes, ","),
			Arch:        *arch,
			OS:          *osName,
			Vendor:      *vendor,
			Packager:    *packager,
			Group:       *group,
			URL:         *url,
			Licence:     *licence,
			Description: *description,
			Summary:     *summary,
			Compressor:  *compressor,
			Distribution: *distribution,
			BugURL:      *bugurl,
			Provides:    provides,
			Obsoletes:   obsoletes,
			Suggests:    suggests,
			Recommends:  recommends,
			Requires:    requires,
			Conflicts:   conflicts,
			Enhances:    enhances,
			Supplements: supplements,
			Changelog:   changelog,
		})
	if err != nil {
		fmt.Fprintf(os.Stderr, "tar2rpm error: %v\n", err)
		os.Exit(1)
	}
	if *useDirAllowlist {
		al := map[string]bool{}
		if *dirAllowlistFile != "" {
			f, err := os.Open(*dirAllowlistFile)
			if err != nil {
				log.Fatalf("Failed to open dir allowlist %q for reading\n: %s", *dirAllowlistFile, err)
			}
			defer func() {
				if err := f.Close(); err != nil {
					log.Printf("failed to close file: %v", err)
				}
			}()
			scan := bufio.NewScanner(f)
			for scan.Scan() {
				t := scan.Text()
				al[t] = true
			}
		}
		r.AllowListDirs(al)
	}

	r.AddPrein(*prein)
	r.AddPostin(*postin)
	r.AddPreun(*preun)
	r.AddPostun(*postun)

	if err := r.Write(w); err != nil {
		fmt.Fprintf(os.Stderr, "rpm write error: %v\n", err)
		os.Exit(1)
	}

}
