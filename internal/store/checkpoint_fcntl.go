//go:build aix || (solaris && !illumos)

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
	lock := syscall.Flock_t{Type: syscall.F_WRLCK, Whence: 0, Start: 0, Len: 0}
	if err := syscall.FcntlFlock(file.Fd(), syscall.F_SETLK, &lock); err != nil {
		if errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EAGAIN) {
			return errCheckpointLocked
		}
		return err
	}
	return nil
}

func checkpointPrivate(info os.FileInfo) bool { return info.Mode().Perm()&0077 == 0 }
