//go:build android || darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd

package store

import (
	"errors"
	"os"
	"syscall"
)

func openNoFollow(path string, flags int, mode os.FileMode) (*os.File, error) {
	fd, err := syscall.Open(path, flags|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, uint32(mode.Perm()))
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

func lockCheckpoint(file *os.File) error {
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return errCheckpointLocked
		}
		return err
	}
	return nil
}

func checkpointPrivate(info os.FileInfo) bool { return info.Mode().Perm()&0077 == 0 }
