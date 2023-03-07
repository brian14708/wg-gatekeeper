//go:build debug
// +build debug

package main

import (
	"io/fs"
	"os"
)

func GetViews() (fs.FS, bool) {
	return os.DirFS("./views"), true
}

func GetAssets() fs.FS {
	return os.DirFS("./assets")
}
