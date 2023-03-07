//go:build !debug
// +build !debug

package main

import (
	"embed"
	"io/fs"
)

//go:embed views assets
var efs embed.FS

const Debug = false

func GetViews() fs.FS {
	f, err := fs.Sub(efs, "views")
	if err != nil {
		panic("failed to subfs")
	}
	return f
}

func GetAssets() fs.FS {
	f, err := fs.Sub(efs, "assets")
	if err != nil {
		panic("failed to subfs")
	}
	return f
}
