//go:build linux && amd64

package security

import "golang.org/x/sys/unix"

func extraDenied() []uint32 {
	return []uint32{unix.SYS_MKNOD, unix.SYS_IOPL, unix.SYS_IOPERM, unix.SYS_MODIFY_LDT}
}
