package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/drag-team/relayprobe/internal/cli"
)

func main() {
	signal.Ignore(syscall.SIGPIPE)
	st, err := os.Stdout.Stat()
	isTTY := err == nil && (st.Mode()&os.ModeCharDevice) != 0
	c := cli.CLI{Stdout: os.Stdout, Stderr: os.Stderr, Stdin: os.Stdin, IsTerminal: isTTY}
	os.Exit(c.Run(os.Args[1:]))
}
