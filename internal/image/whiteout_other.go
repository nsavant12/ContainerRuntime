//go:build !linux

package image

import (
	"fmt"
	"os"
)

func whiteout(root *os.Root, p string) error { return fmt.Errorf("OCI whiteouts require Linux: %s", p) }
