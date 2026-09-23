// probe is a static test workload. It does not invoke an installed host runtime.
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		panic("mode required")
	}
	switch os.Args[1] {
	case "exists":
		_, err := os.Stat(os.Args[2])
		if os.IsNotExist(err) {
			fmt.Println("absent")
		} else if err != nil {
			panic(err)
		} else {
			fmt.Println("present")
		}
	case "ready":
		fmt.Println("READY")
	case "inspect":
		inspect()
	case "sleep":
		fmt.Println("READY")
		time.Sleep(10 * time.Minute)
	case "cpu":
		end := time.Now().Add(3 * time.Second)
		var x uint64
		for time.Now().Before(end) {
			for i := 0; i < 10000; i++ {
				x = x*1664525 + 1013904223
			}
		}
		fmt.Println(x)
	case "memory":
		var chunks [][]byte
		for {
			b := make([]byte, 1<<20)
			for i := 0; i < len(b); i += 4096 {
				b[i] = 1
			}
			chunks = append(chunks, b)
			runtime.KeepAlive(chunks)
		}
	case "pids":
		var procs []*exec.Cmd
		for i := 0; i < 1000; i++ {
			c := exec.Command("/probe", "sleep")
			if err := c.Start(); err != nil {
				fmt.Printf("limited after %d: %v\n", len(procs), err)
				for _, c := range procs {
					c.Process.Kill()
					c.Wait()
				}
				return
			}
			procs = append(procs, c)
		}
		os.Exit(1)
	case "signal":
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGTERM)
		fmt.Println("READY")
		<-ch
		fmt.Println("TERM")
		os.Exit(42)
	case "ignore":
		signal.Ignore(syscall.SIGTERM)
		fmt.Println("READY")
		time.Sleep(time.Hour)
	case "orphan":
		if len(os.Args) > 2 {
			c := exec.Command("/probe", "short")
			if err := c.Start(); err != nil {
				panic(err)
			}
			return
		}
		c := exec.Command("/probe", "orphan", "child")
		if err := c.Run(); err != nil {
			panic(err)
		}
		time.Sleep(300 * time.Millisecond)
		entries, _ := os.ReadDir("/proc")
		z := 0
		for _, e := range entries {
			if _, err := strconv.Atoi(e.Name()); err == nil {
				b, _ := os.ReadFile("/proc/" + e.Name() + "/stat")
				if strings.Contains(string(b), ") Z ") {
					z++
				}
			}
		}
		fmt.Printf("zombies=%d\n", z)
		if z != 0 {
			os.Exit(1)
		}
	case "short":
		time.Sleep(50 * time.Millisecond)
	case "service":
		fmt.Println("READY")
		sc := bufio.NewScanner(os.Stdin)
		data := make([]byte, 4096)
		for sc.Scan() {
			for i := 0; i < 16; i++ {
				sum := sha256.Sum256(data)
				copy(data, sum[:])
			}
			fmt.Println("OK")
		}
	case "write-to":
		if err := os.WriteFile(os.Args[2], []byte("owned"), 0644); err != nil {
			panic(err)
		}
		fmt.Println("owned")
	case "write":
		if err := os.WriteFile("/shared", []byte("changed"), 0644); err != nil {
			panic(err)
		}
		fmt.Println("changed")
	case "exit":
		n, _ := strconv.Atoi(os.Args[2])
		os.Exit(n)
	default:
		panic("unknown mode")
	}
}
func inspect() {
	ns := map[string]string{}
	for _, n := range []string{"pid", "net", "mnt", "uts", "ipc", "cgroup"} {
		ns[n], _ = os.Readlink("/proc/self/ns/" + n)
	}
	status, _ := os.ReadFile("/proc/self/status")
	ifs, _ := net.Interfaces()
	names := []string{}
	for _, i := range ifs {
		names = append(names, i.Name)
	}
	root, _ := os.Readlink("/proc/self/root")
	sentinel := os.Getenv("HOST_SENTINEL")
	if sentinel == "" {
		sentinel = "/etc/isolate-host-sentinel"
	}
	_, hostErr := os.Stat(sentinel)
	hostname, _ := os.Hostname()
	security := securityProbe()
	fds := map[string]string{}
	entries, _ := os.ReadDir("/proc/self/fd")
	for _, e := range entries {
		n, _ := strconv.Atoi(e.Name())
		if n > 2 {
			if link, err := os.Readlink("/proc/self/fd/" + e.Name()); err == nil {
				fds[e.Name()] = link
			}
		}
	}
	json.NewEncoder(os.Stdout).Encode(map[string]any{"pid": os.Getpid(), "ppid": os.Getppid(), "uid": os.Getuid(), "gid": os.Getgid(), "namespaces": ns, "interfaces": names, "status": string(status), "root": root, "hostname": hostname, "host_hidden": os.IsNotExist(hostErr), "security": security, "extra_fds": fds})
}
