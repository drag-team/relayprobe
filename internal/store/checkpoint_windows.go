//go:build windows

package store

import (
	"errors"
	"os"
	"syscall"
	"unsafe"
)

const (
	lockfileFailImmediately = 0x00000001
	lockfileExclusiveLock   = 0x00000002
	errorSharingViolation   = syscall.Errno(32)
	errorLockViolation      = syscall.Errno(33)
)

var lockFileEx = syscall.NewLazyDLL("kernel32.dll").NewProc("LockFileEx")

func openNoFollow(path string, flags int, mode os.FileMode) (*os.File, error) {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, errors.New("file must be regular and not a symbolic link")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	file, err := os.OpenFile(path, flags, mode)
	if err != nil {
		return nil, err
	}
	pathInfo, pathErr := os.Lstat(path)
	fileInfo, fileErr := file.Stat()
	if pathErr != nil || fileErr != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.Mode().IsRegular() || !fileInfo.Mode().IsRegular() || !os.SameFile(pathInfo, fileInfo) {
		_ = file.Close()
		if pathErr != nil {
			return nil, pathErr
		}
		if fileErr != nil {
			return nil, fileErr
		}
		return nil, errors.New("file identity changed while opening")
	}
	return file, nil
}

func lockCheckpoint(file *os.File) error {
	var overlapped syscall.Overlapped
	result, _, callErr := lockFileEx.Call(
		file.Fd(),
		lockfileFailImmediately|lockfileExclusiveLock,
		0,
		0xffffffff,
		0xffffffff,
		uintptr(unsafe.Pointer(&overlapped)),
	)
	if result != 0 {
		return nil
	}
	if errors.Is(callErr, errorSharingViolation) || errors.Is(callErr, errorLockViolation) {
		return errCheckpointLocked
	}
	if callErr == syscall.Errno(0) {
		return syscall.EINVAL
	}
	return callErr
}

func checkpointPrivate(os.FileInfo) bool { return true }
