package util

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteAndReadSecretFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets", "token")
	data := []byte("super-secret-token")
	if err := WriteSecretFile(path, data); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	read, err := ReadSecretFile(path)
	if err != nil {
		t.Fatalf("read secret: %v", err)
	}
	if string(read) != string(data) {
		t.Fatalf("unexpected secret content %q", string(read))
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat secret: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("expected file perm 0600, got %o", perm)
	}
	dirInfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("stat parent: %v", err)
	}
	if perm := dirInfo.Mode().Perm(); perm != 0o700 {
		t.Fatalf("expected dir perm 0700, got %o", perm)
	}
}

func TestFileExists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "missing")
	exists, err := FileExists(path)
	if err != nil {
		t.Fatalf("file exists: %v", err)
	}
	if exists {
		t.Fatalf("expected file to be missing")
	}
	if err := os.WriteFile(path, []byte("data"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	exists, err = FileExists(path)
	if err != nil {
		t.Fatalf("file exists after write: %v", err)
	}
	if !exists {
		t.Fatalf("expected file to exist")
	}
}
