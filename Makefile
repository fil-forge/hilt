BINARY := hilt
BIN_DIR := .
CMD := ./cmd

.PHONY: build test vet clean run

build:
	go build -o $(BIN_DIR)/$(BINARY) $(CMD)

test:
	go test ./...

vet:
	go vet ./...

clean:
	rm $(BIN_DIR)/$(BINARY)
