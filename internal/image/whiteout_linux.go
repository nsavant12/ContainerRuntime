package image

import (
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"path"
	"strings"
)

func whiteout(root *os.Root, p string) error {
	parent, err := root.Open(path.Dir(p))
	if err != nil {
		return err
	}
	defer parent.Close()
	base := path.Base(p)
	if base == ".wh..wh..opq" {
		return unix.Fsetxattr(int(parent.Fd()), "trusted.overlay.opaque", []byte("y"), 0)
	}
	target := strings.TrimPrefix(base, ".wh.")
	if target == "" || target == "." || target == ".." {
		return fmt.Errorf("invalid whiteout")
	}
	if _, err := root.Lstat(path.Join(path.Dir(p), target)); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return unix.Mknodat(int(parent.Fd()), target, unix.S_IFCHR, 0)
}
