//go:build !debug
// +build !debug

package main

import (
	"embed"
	"io/fs"
)

//go:embed views assets
var efs embed.FS

func GetViews() (fs.FS, bool) {
	f, err := fs.Sub(efs, "views")
	if err != nil {
		panic("failed to subfs")
	}
	return f, false
}

func GetAssets() fs.FS {
	f, err := fs.Sub(efs, "assets")
	if err != nil {
		panic("failed to subfs")
	}
	return f
}
