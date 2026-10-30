package main

import (
	"os"

	"github.com/drag-team/relayprobe/internal/cli"
)

func main() {
	ignoreBrokenPipe()
	st, err := os.Stdout.Stat()
	isTTY := err == nil && (st.Mode()&os.ModeCharDevice) != 0
	c := cli.CLI{Stdout: os.Stdout, Stderr: os.Stderr, Stdin: os.Stdin, IsTerminal: isTTY}
	os.Exit(c.Run(os.Args[1:]))
}
