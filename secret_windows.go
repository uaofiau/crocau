//go:build windows

package main

import (
	"encoding/base64"
	"errors"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// DPAPI: ключ привязан к учётной записи Windows на этом компьютере и в файле не хранится.
var dpapiEntropy = []byte("crocau-settings-v1")

func blobOf(b []byte) windows.DataBlob {
	if len(b) == 0 {
		return windows.DataBlob{}
	}
	return windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
}

func platformSeal(plain string) (string, error) {
	din := blobOf([]byte(plain))
	ent := blobOf(dpapiEntropy)
	var out windows.DataBlob
	if err := windows.CryptProtectData(&din, nil, &ent, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return "", err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	raw := make([]byte, out.Size)
	copy(raw, unsafe.Slice(out.Data, out.Size))
	return sealPrefix + base64.StdEncoding.EncodeToString(raw), nil
}

func platformOpen(v string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(v, sealPrefix))
	if err != nil || len(raw) == 0 {
		return "", errors.New("повреждённые данные")
	}
	din := blobOf(raw)
	ent := blobOf(dpapiEntropy)
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(&din, nil, &ent, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return "", err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	plain := make([]byte, out.Size)
	copy(plain, unsafe.Slice(out.Data, out.Size))
	return string(plain), nil
}
