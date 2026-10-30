//go:build !windows

package fsx

import "os"

func Replace(oldPath, newPath string) error { return os.Rename(oldPath, newPath) }

func SyncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	if err = dir.Sync(); err != nil {
		_ = dir.Close()
		return err
	}
	return dir.Close()
}

func SameCanonicalPath(a, b string) bool { return a == b }
