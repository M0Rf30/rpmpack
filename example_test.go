package rpmpack_test

import (
	"bytes"
	"fmt"
	"log"

	"github.com/M0Rf30/rpmpack"
)

// A minimal package with one file. Set Format: rpmpack.FormatV6 to write the RPM v6
// format instead of v4.
func ExampleNewRPM() {
	r, err := rpmpack.NewRPM(rpmpack.RPMMetaData{Name: "example", Version: "3", Release: "1"})
	if err != nil {
		log.Fatal(err)
	}
	r.AddFile(rpmpack.RPMFile{
		Name:  "/usr/local/hello",
		Body:  []byte("content of the file"),
		Mode:  0o644,
		Owner: "root",
		Group: "root",
	})

	var w bytes.Buffer // any io.Writer, for example an *os.File
	if err := r.Write(&w); err != nil {
		log.Fatal(err)
	}
	// Every rpm starts with the lead magic.
	fmt.Printf("% x\n", w.Bytes()[:4])
	// Output: ed ab ee db
}

func ExampleRPM_Write_invalidFile() {
	r, err := rpmpack.NewRPM(rpmpack.RPMMetaData{Name: "example", Version: "3"})
	if err != nil {
		log.Fatal(err)
	}
	// Names must be clean absolute paths.
	r.AddFile(rpmpack.RPMFile{Name: "usr/../etc/passwd", Body: []byte("x")})
	err = r.Write(&bytes.Buffer{})
	fmt.Println(err)
	// Output: invalid rpm file: name "usr/../etc/passwd" is not a clean absolute path
}
