//go:generate go run -tags codegen .

package main

import (
	"os"

	jsg "github.com/alanshaw/dag-json-gen"
	provider "github.com/fil-forge/hilt/pkg/commands/admin/provider"
	cbg "github.com/whyrusleeping/cbor-gen"
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
	models := []any{
		provider.AddArguments{},
	}
	const (
		cborFile = "../cbor_gen.go"
		jsonFile = "../json_gen.go"
	)
	if err := cbg.WriteMapEncodersToFile(cborFile, "provider", models...); err != nil {
		panic(err)
	}
	if err := jsg.WriteMapEncodersToFile(jsonFile, "provider", models...); err != nil {
		panic(err)
	}
	tag(cborFile)
	tag(jsonFile)
}
