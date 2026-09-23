package main

import (
	"fmt"
	"os"
)

func main() {
	code, err := runCLI(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "isolate:", err)
	}
	os.Exit(code)
}
