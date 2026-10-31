//go:build aix || android || darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd || solaris

package main

import (
	"os/signal"
	"syscall"
)

func ignoreBrokenPipe() { signal.Ignore(syscall.SIGPIPE) }
