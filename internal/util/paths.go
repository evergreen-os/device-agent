package util

import (
	"fmt"
	"os"
	"path/filepath"
)

// EnsureDir ensures the directory exists with the provided permissions.
func EnsureDir(path string, perm os.FileMode) error {
	if path == "" {
		return fmt.Errorf("path cannot be empty")
	}
	if err := os.MkdirAll(path, perm); err != nil {
		return fmt.Errorf("create dir %s: %w", path, err)
	}
	return nil
}

// EnsureParentDir ensures that the parent directory for the given file exists.
func EnsureParentDir(filePath string, perm os.FileMode) error {
	dir := filepath.Dir(filePath)
	if dir == "." || dir == "" {
		return nil
	}
	return EnsureDir(dir, perm)
}
