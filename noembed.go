//go:build debug
// +build debug

package main

import (
	"io/fs"
	"os"
)

const Debug = true

func GetViews() fs.FS {
	return os.DirFS("./views")
}

func GetAssets() fs.FS {
	return os.DirFS("./assets")
}
