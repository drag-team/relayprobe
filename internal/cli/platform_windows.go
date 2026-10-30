//go:build windows

package cli

import "os"

func fileDescriptorLimit() (uint64, uint64, bool) { return 0, 0, false }

func interruptSignals() []os.Signal { return []os.Signal{os.Interrupt} }
