package util

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
)

const secretFilePerm = 0o600
const secretDirPerm = 0o700

// WriteSecretFile writes data to the provided path with restrictive permissions.
func WriteSecretFile(path string, data []byte) error {
	if path == "" {
		return errors.New("path cannot be empty")
	}
	if err := EnsureParentDir(path, secretDirPerm); err != nil {
		return err
	}
	tmpFile := path + ".tmp"
	if err := os.WriteFile(tmpFile, data, secretFilePerm); err != nil {
		return fmt.Errorf("write temp secret: %w", err)
	}
	if err := os.Chmod(tmpFile, secretFilePerm); err != nil {
		return fmt.Errorf("chmod temp secret: %w", err)
	}
	if err := os.Rename(tmpFile, path); err != nil {
		return fmt.Errorf("rename secret: %w", err)
	}
	return nil
}

// ReadSecretFile reads data from a secret file.
func ReadSecretFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// FileExists checks if a file exists.
func FileExists(path string) (bool, error) {
	if path == "" {
		return false, errors.New("path cannot be empty")
	}
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return false, err
}
