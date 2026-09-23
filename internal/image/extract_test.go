package image

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func archive(t *testing.T, headers ...tar.Header) []byte {
	t.Helper()
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	for _, h := range headers {
		if err := w.WriteHeader(&h); err != nil {
			t.Fatal(err)
		}
		if h.Size > 0 {
			w.Write(bytes.Repeat([]byte("x"), int(h.Size)))
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}
func TestRejectArchiveEscapes(t *testing.T) {
	for _, p := range []string{"../outside", "/absolute", "a/../../outside"} {
		t.Run(p, func(t *testing.T) {
			err := Extract(t.TempDir(), bytes.NewReader(archive(t, tar.Header{Name: p, Typeflag: tar.TypeReg, Mode: 0644, Size: 1})))
			if err == nil {
				t.Fatal("accepted unsafe archive")
			}
		})
	}
}
func TestRejectSymlinkTraversal(t *testing.T) {
	outside := t.TempDir()
	b := archive(t, tar.Header{Name: "escape", Typeflag: tar.TypeSymlink, Linkname: outside}, tar.Header{Name: "escape/written", Typeflag: tar.TypeReg, Mode: 0644, Size: 1})
	if err := Extract(t.TempDir(), bytes.NewReader(b)); err == nil {
		t.Fatal("accepted symlink escape")
	}
	if _, err := os.Stat(filepath.Join(outside, "written")); !os.IsNotExist(err) {
		t.Fatal("outside write")
	}
}
func TestRejectDevices(t *testing.T) {
	b := archive(t, tar.Header{Name: "device", Typeflag: tar.TypeChar, Mode: 0666, Devmajor: 1, Devminor: 1})
	if err := Extract(t.TempDir(), bytes.NewReader(b)); err == nil {
		t.Fatal("accepted device")
	}
}
func TestRegularSymlinksAndHardlinks(t *testing.T) {
	b := archive(t, tar.Header{Name: "bin", Typeflag: tar.TypeDir, Mode: 0755}, tar.Header{Name: "bin/app", Typeflag: tar.TypeReg, Mode: 04755, Size: 3}, tar.Header{Name: "bin/link", Typeflag: tar.TypeSymlink, Linkname: "app"}, tar.Header{Name: "bin/hard", Typeflag: tar.TypeLink, Linkname: "bin/app"})
	d := t.TempDir()
	if err := Extract(d, bytes.NewReader(b)); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"app", "link", "hard"} {
		v, err := os.ReadFile(filepath.Join(d, "bin", p))
		if err != nil || string(v) != "xxx" {
			t.Fatal(p, err)
		}
	}
	st, _ := os.Stat(filepath.Join(d, "bin/app"))
	if st.Mode()&os.ModeSetuid != 0 {
		t.Fatal("setuid preserved")
	}
}
func TestChecksumAndImportDedup(t *testing.T) {
	store, err := New(filepath.Join(t.TempDir(), "store"))
	if err != nil {
		t.Fatal(err)
	}
	b := archive(t, tar.Header{Name: "a", Typeflag: tar.TypeReg, Mode: 0644, Size: 3})
	if _, err = store.ingest(bytes.NewReader(b), strings.Repeat("0", 64)); err == nil {
		t.Fatal("checksum mismatch accepted")
	}
	entries, _ := os.ReadDir(filepath.Join(store.Root, "layers"))
	if len(entries) != 0 {
		t.Fatal("published invalid layer")
	}
	a, err := store.ingest(bytes.NewReader(b), "")
	if err != nil {
		t.Fatal(err)
	}
	c, err := store.ingest(bytes.NewReader(b), "")
	if err != nil || a != c {
		t.Fatal("dedup", err)
	}
	entries, _ = os.ReadDir(filepath.Join(store.Root, "layers"))
	if len(entries) != 1 {
		t.Fatal("duplicate storage")
	}
}
