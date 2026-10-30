package fsx

import "path/filepath"

func SyncParent(path string) error { return SyncDir(filepath.Dir(path)) }
