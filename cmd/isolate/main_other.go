//go:build !linux

package main

import "fmt"

func runCLI(args []string) (int, error) {
	return 125, fmt.Errorf("isolate requires Linux >=5.14 on amd64 or arm64; see docs/macos.md for the Lima VM workflow")
}
