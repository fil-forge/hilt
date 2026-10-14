//go:generate go run -tags codegen .

package main

import (
	"os"

	jsg "github.com/alanshaw/dag-json-gen"
	"github.com/fil-forge/hilt/pkg/bucketpolicy/internal/dagjson"
)

const buildTag = "//go:build !codegen\n\n"

func tag(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(path, append([]byte(buildTag), data...), 0644); err != nil {
		panic(err)
	}
}

func main() {
	const jsonFile = "../json_gen.go"
	// JSON only: the encoding exists for the ETag, and nothing carries it as CBOR.
	if err := jsg.WriteMapEncodersToFile(jsonFile, "dagjson",
		dagjson.Empty{},
		dagjson.Statement{},
		dagjson.Policy{},
	); err != nil {
		panic(err)
	}
	tag(jsonFile)
}
