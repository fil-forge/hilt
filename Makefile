BINARY := hilt
BIN_DIR := .
CMD := ./cmd

.PHONY: build test vet clean gen

build:
	go build -o $(BIN_DIR)/$(BINARY) $(CMD)

gen:
	go generate ./...

test:
	go test ./...

vet:
	go vet ./...

clean:
	rm $(BIN_DIR)/$(BINARY)
