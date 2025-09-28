package util

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"syscall"
)

// HardwareFacts represents immutable device information used during enrollment.
type HardwareFacts struct {
	SerialNumber string `json:"serial"`
	Model        string `json:"model"`
	CPUModel     string `json:"cpu_model"`
	CPUCount     int    `json:"cpu_count"`
	TotalRAM     uint64 `json:"total_ram_bytes"`
	HasTPM       bool   `json:"has_tpm"`
}

// CollectHardwareFacts gathers best-effort hardware facts from the host.
func CollectHardwareFacts() (HardwareFacts, error) {
	serial := readFirstLine("/sys/class/dmi/id/product_serial")
	model := readFirstLine("/sys/class/dmi/id/product_name")
	cpuModel := cpuModelName()
	cpuCount := runtime.NumCPU()
	ram, err := totalRAM()
	if err != nil {
		return HardwareFacts{}, fmt.Errorf("total ram: %w", err)
	}
	hasTPM := pathExists("/dev/tpm0") || pathExists("/dev/tpmrm0")
	return HardwareFacts{
		SerialNumber: serial,
		Model:        model,
		CPUModel:     cpuModel,
		CPUCount:     cpuCount,
		TotalRAM:     ram,
		HasTPM:       hasTPM,
	}, nil
}

func readFirstLine(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	if scanner.Scan() {
		return strings.TrimSpace(scanner.Text())
	}
	return ""
}

func cpuModelName() string {
	file, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return runtime.GOARCH
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(strings.ToLower(line), "model name") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return runtime.GOARCH
}

func totalRAM() (uint64, error) {
	var info syscall.Sysinfo_t
	if err := syscall.Sysinfo(&info); err != nil {
		return 0, err
	}
	return uint64(info.Totalram) * uint64(info.Unit), nil
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// DiskUsage returns available and total disk bytes for the given path.
func DiskUsage(path string) (total uint64, free uint64, err error) {
	if path == "" {
		return 0, 0, errors.New("path cannot be empty")
	}
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, 0, fmt.Errorf("statfs %s: %w", path, err)
	}
	total = stat.Blocks * uint64(stat.Bsize)
	free = stat.Bavail * uint64(stat.Bsize)
	return total, free, nil
}
