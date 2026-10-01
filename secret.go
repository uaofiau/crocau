package main

import "strings"

// Защищённые значения хранятся в crocau.ini в виде "crocau-dpapi:v1:<base64>".
// Значение без этого префикса считается открытым текстом (старый формат) и при следующем сохранении защищается.
const sealPrefix = "crocau-dpapi:v1:"

// Реализации подменяются в тестах на системах без защиты.
var (
	sealImpl = platformSeal
	openImpl = platformOpen
)

func sealSecret(plain string) (string, error) {
	if plain == "" {
		return "", nil
	}
	return sealImpl(plain)
}

func openSecret(v string) (string, error) {
	if v == "" {
		return "", nil
	}
	if !strings.HasPrefix(v, sealPrefix) {
		return v, nil
	}
	return openImpl(v)
}
