BINARY := hilt
BIN_DIR := .
CMD := ./cmd

VERSION=$(shell awk -F'"' '/"version":/ {print $$4}' version.json)
COMMIT=$(shell git rev-parse --short HEAD)
DATE=$(shell date -u -Iseconds)
GOFLAGS=-ldflags="-X github.com/fil-forge/hilt/pkg/build.version=$(VERSION) -X github.com/fil-forge/hilt/pkg/build.Commit=$(COMMIT) -X github.com/fil-forge/hilt/pkg/build.Date=$(DATE) -X github.com/fil-forge/hilt/pkg/build.BuiltBy=make"

.PHONY: build test vet clean gen

build:
	go build $(GOFLAGS) -o $(BIN_DIR)/$(BINARY) $(CMD)

gen:
	go generate ./...

test:
	go test ./...

vet:
	go vet ./...

clean:
	rm $(BIN_DIR)/$(BINARY)
