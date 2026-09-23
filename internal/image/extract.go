package image

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
)

func archivePath(p string) (string, error) {
	if strings.IndexByte(p, 0) >= 0 || strings.HasPrefix(p, "/") {
		return "", fmt.Errorf("unsafe archive path %q", p)
	}
	clean := path.Clean(p)
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("unsafe archive path %q", p)
	}
	return clean, nil
}

// Extract confines all archive writes using os.Root. It rejects devices, FIFOs,
// path escapes and oversized archives; OCI whiteouts are handled separately.
func Extract(dest string, r io.Reader) error {
	root, err := os.OpenRoot(dest)
	if err != nil {
		return err
	}
	defer root.Close()
	tr := tar.NewReader(r)
	type mode struct {
		p        string
		m        os.FileMode
		uid, gid int
	}
	dirs := []mode{}
	whiteouts := []string{}
	var total int64
	for count := 0; ; count++ {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if count >= 200000 {
			return fmt.Errorf("too many archive entries")
		}
		p, err := archivePath(h.Name)
		if err != nil {
			return err
		}
		if p == "." {
			continue
		}
		if h.Size < 0 || h.Size > 8<<30 || total > 8<<30-h.Size {
			return fmt.Errorf("archive exceeds 8 GiB")
		}
		total += h.Size
		if err = root.MkdirAll(path.Dir(p), 0755); err != nil {
			return err
		}
		if strings.HasPrefix(path.Base(p), ".wh.") {
			if h.Typeflag != tar.TypeReg || h.Size != 0 {
				return fmt.Errorf("invalid whiteout %s", p)
			}
			whiteouts = append(whiteouts, p)
			continue
		}
		perm := os.FileMode(h.Mode) & 0777 // setuid, setgid and sticky bits are not trusted
		switch h.Typeflag {
		case tar.TypeDir:
			if err = root.MkdirAll(p, 0755); err != nil {
				return err
			}
			dirs = append(dirs, mode{p, perm, h.Uid, h.Gid})
		case tar.TypeReg, tar.TypeRegA:
			// Unlink first: never overwrite through a symlink or a hardlink.
			if err = root.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			f, err := root.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err != nil {
				return err
			}
			_, err = io.CopyN(f, tr, h.Size)
			if err == nil && os.Geteuid() == 0 {
				err = f.Chown(h.Uid, h.Gid)
			}
			if err == nil {
				err = f.Chmod(perm)
			}
			ce := f.Close()
			if err != nil {
				return err
			}
			if ce != nil {
				return ce
			}
		case tar.TypeSymlink:
			if strings.IndexByte(h.Linkname, 0) >= 0 {
				return fmt.Errorf("NUL in link")
			}
			if err = root.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			if err = root.Symlink(h.Linkname, p); err != nil {
				return err
			}
		case tar.TypeLink:
			target, err := archivePath(h.Linkname)
			if err != nil {
				return err
			}
			info, err := root.Lstat(target)
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() {
				return fmt.Errorf("hardlink target must be regular")
			}
			if err = root.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			if err = root.Link(target, p); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported archive entry %s (type %d)", p, h.Typeflag)
		}
	}
	for _, p := range whiteouts {
		if err := whiteout(root, p); err != nil {
			return err
		}
	}
	for i := len(dirs) - 1; i >= 0; i-- {
		if os.Geteuid() == 0 {
			if err = root.Chown(dirs[i].p, dirs[i].uid, dirs[i].gid); err != nil {
				return err
			}
		}
		if err = root.Chmod(dirs[i].p, dirs[i].m); err != nil {
			return err
		}
	}
	return nil
}
