//go:build !windows

package main

import (
	"fmt"
	"os"
)

func guiMain(test bool) int {
	fmt.Fprintln(os.Stderr, "crocau: GUI пока только для Windows")
	return 1
}
