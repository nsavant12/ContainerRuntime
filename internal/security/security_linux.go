// Package security applies the default privilege and syscall restrictions.
package security

import (
	"fmt"
	"golang.org/x/sys/unix"
	"runtime"
	"syscall"
	"unsafe"
)

// Apply must be called on the locked thread that will spawn the workload.
func Apply(uid, gid int) error {
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return err
	}
	// SECURE_NOROOT|LOCKED prevents UID 0 from regaining capabilities at exec.
	if err := unix.Prctl(unix.PR_SET_SECUREBITS, 3, 0, 0, 0); err != nil {
		return err
	}
	for c := 0; c < 64; c++ {
		err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(c), 0, 0, 0)
		if err == unix.EINVAL {
			break
		}
		if err != nil {
			return err
		}
	}
	if err := syscall.Setgroups([]int{}); err != nil {
		return err
	}
	if err := syscall.Setgid(gid); err != nil {
		return err
	}
	if err := syscall.Setuid(uid); err != nil {
		return err
	}
	h := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	d := [2]unix.CapUserData{}
	if err := unix.Capset(&h, &d[0]); err != nil {
		return err
	}
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}); err != nil {
		return err
	}
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &unix.Rlimit{Cur: 1024, Max: 1024}); err != nil {
		return err
	}
	return filter()
}
func filter() error {
	arch := uint32(unix.AUDIT_ARCH_AARCH64)
	if runtime.GOARCH == "amd64" {
		arch = unix.AUDIT_ARCH_X86_64
	} else if runtime.GOARCH != "arm64" {
		return fmt.Errorf("seccomp supports only linux/amd64 and linux/arm64")
	}
	stmt := func(code uint16, k uint32) unix.SockFilter { return unix.SockFilter{Code: code, K: k} }
	jump := func(k uint32, jt, jf uint8) unix.SockFilter {
		return unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: k, Jt: jt, Jf: jf}
	}
	f := []unix.SockFilter{stmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, 4), jump(arch, 1, 0), stmt(unix.BPF_RET|unix.BPF_K, unix.SECCOMP_RET_KILL_PROCESS), stmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, 0)}
	// Reject x32 syscall numbers as well as unexpected audit architectures.
	f = append(f, unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K, K: 0x40000000, Jf: 1}, stmt(unix.BPF_RET|unix.BPF_K, unix.SECCOMP_RET_KILL_PROCESS))
	deny := []uint32{unix.SYS_MOUNT, unix.SYS_UMOUNT2, unix.SYS_PIVOT_ROOT, unix.SYS_CHROOT, unix.SYS_UNSHARE, unix.SYS_SETNS, unix.SYS_BPF, unix.SYS_PERF_EVENT_OPEN, unix.SYS_KEYCTL, unix.SYS_ADD_KEY, unix.SYS_REQUEST_KEY, unix.SYS_REBOOT, unix.SYS_KEXEC_LOAD, unix.SYS_KEXEC_FILE_LOAD, unix.SYS_INIT_MODULE, unix.SYS_FINIT_MODULE, unix.SYS_DELETE_MODULE, unix.SYS_PTRACE, unix.SYS_OPEN_BY_HANDLE_AT, unix.SYS_NAME_TO_HANDLE_AT, unix.SYS_PROCESS_VM_READV, unix.SYS_PROCESS_VM_WRITEV, unix.SYS_USERFAULTFD, unix.SYS_MKNODAT, unix.SYS_SWAPON, unix.SYS_SWAPOFF, unix.SYS_QUOTACTL, unix.SYS_ACCT, unix.SYS_IO_URING_SETUP, unix.SYS_IO_URING_ENTER, unix.SYS_IO_URING_REGISTER, unix.SYS_OPEN_TREE, unix.SYS_MOVE_MOUNT, unix.SYS_FSOPEN, unix.SYS_FSCONFIG, unix.SYS_FSMOUNT, unix.SYS_FSPICK, unix.SYS_MOUNT_SETATTR}
	deny = append(deny, extraDenied()...)
	for _, nr := range deny {
		f = append(f, jump(nr, 0, 1), stmt(unix.BPF_RET|unix.BPF_K, unix.SECCOMP_RET_ERRNO|uint32(unix.EPERM)))
	}
	// clone3 carries a pointer, so reject with ENOSYS to permit libc fallback.
	f = append(f, jump(unix.SYS_CLONE3, 0, 1), stmt(unix.BPF_RET|unix.BPF_K, unix.SECCOMP_RET_ERRNO|uint32(unix.ENOSYS)))
	// Traditional clone remains available for threads/fork, but no new namespaces.
	f = append(f, jump(unix.SYS_CLONE, 0, 3), stmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, 16), unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K, K: unix.CLONE_NEWNS | unix.CLONE_NEWUTS | unix.CLONE_NEWIPC | unix.CLONE_NEWUSER | unix.CLONE_NEWPID | unix.CLONE_NEWNET | unix.CLONE_NEWCGROUP, Jf: 1}, stmt(unix.BPF_RET|unix.BPF_K, unix.SECCOMP_RET_ERRNO|uint32(unix.EPERM)), stmt(unix.BPF_RET|unix.BPF_K, unix.SECCOMP_RET_ALLOW))
	p := unix.SockFprog{Len: uint16(len(f)), Filter: &f[0]}
	result, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(&p)))
	runtime.KeepAlive(f)
	if errno != 0 {
		return errno
	}
	if result != 0 {
		return fmt.Errorf("seccomp thread synchronization failed at TID %d", result)
	}
	return nil
}
