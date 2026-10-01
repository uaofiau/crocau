//go:build !windows

package main

import "errors"

func platformSeal(string) (string, error) {
	return "", errors.New("защита паролей на этой системе пока не поддерживается")
}

func platformOpen(string) (string, error) {
	return "", errors.New("защита паролей на этой системе пока не поддерживается")
}
