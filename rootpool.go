package main

import (
	"crypto/x509"
	_ "embed"
	"sync"
)

// Запасной набор корневых сертификатов (Mozilla): на старых Windows 7 без обновлений системного набора может
// не хватать современных корневых центров. Файл подгружается при сборке (при неудаче остаётся заглушка).
//
//go:embed certs/cacert.pem
var embeddedCA []byte

var (
	rootOnce sync.Once
	rootPool *x509.CertPool
)

func fallbackRoots() *x509.CertPool {
	rootOnce.Do(func() {
		p := x509.NewCertPool()
		if p.AppendCertsFromPEM(embeddedCA) {
			rootPool = p
		}
	})
	return rootPool
}
