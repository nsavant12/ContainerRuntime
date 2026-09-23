package main

import (
	"golang.org/x/sys/unix"
)

func securityProbe() map[string]bool {
	mountErr := unix.Mount("none", "/tmp", "tmpfs", 0, "")
	unshareErr := unix.Unshare(unix.CLONE_NEWUSER)
	nodeErr := unix.Mknodat(unix.AT_FDCWD, "/tmp/evil", unix.S_IFCHR|0600, int(unix.Mkdev(1, 1)))
	var st unix.Stat_t
	procErr := unix.Stat("/proc/sysrq-trigger", &st)
	return map[string]bool{"mount_denied": mountErr == unix.EPERM, "unshare_denied": unshareErr == unix.EPERM, "mknod_denied": nodeErr == unix.EPERM, "sysrq_masked": procErr == nil && st.Rdev == unix.Mkdev(1, 3)}
}
