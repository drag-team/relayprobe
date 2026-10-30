//go:build aix || android || darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd || solaris

package cli

import (
	"os"
	"syscall"
)

func fileDescriptorLimit() (uint64, uint64, bool) {
	var limit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &limit); err != nil {
		return 0, 0, false
	}
	return uint64(limit.Cur), uint64(limit.Max), true
}

func interruptSignals() []os.Signal { return []os.Signal{os.Interrupt, syscall.SIGTERM} }
