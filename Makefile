BINARY ?= evergreen-agent
BUILD_DIR ?= build

.PHONY: all build test fmt lint clean docker

all: build

build:
	go build -o $(BUILD_DIR)/$(BINARY) ./cmd/agent

test:
	go test ./...

fmt:
	go fmt ./...

lint:
	go vet ./...

clean:
	rm -rf $(BUILD_DIR)

docker:
	docker build -t evergreen/device-agent:latest .
