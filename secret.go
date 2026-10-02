package main

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"sync"

	"github.com/schollz/croc/v10/src/crypt"
)

// Защищённые значения хранятся в crocau.ini в виде:
//
//	crocau-dpapi:v1:<base64>  - средствами Windows (ключ привязан к учётной записи на этом компьютере);
//	crocau-mk:v1:<base64>     - мастер-паролем: argon2id + XChaCha20-Poly1305 (код шифрования - из croc).
//
// Значение без префикса считается открытым текстом (старый формат) и при следующем сохранении защищается.
const (
	sealPrefix       = "crocau-dpapi:v1:"
	mkPrefix         = "crocau-mk:v1:"
	masterCheckPlain = "crocau-master-ok"
)

var (
	errLocked      = errors.New("заблокировано мастер-паролем")
	errWrongMaster = errors.New("неверный мастер-пароль")
)

// Реализации DPAPI подменяются в тестах на системах без защиты.
var (
	sealImpl = platformSeal
	openImpl = platformOpen
)

type vaultState struct {
	master bool
	salt   []byte
	aead   cipher.AEAD
}

var (
	vaultMu sync.Mutex
	vault   vaultState
)

func vaultSnapshot() vaultState {
	vaultMu.Lock()
	defer vaultMu.Unlock()
	return vault
}

func vaultIsMaster() bool      { return vaultSnapshot().master }
func vaultUnlocked() bool      { return vaultSnapshot().aead != nil }
func vaultSaltB64() string     { return base64.StdEncoding.EncodeToString(vaultSnapshot().salt) }
func masterMode(s string) bool { return s == "master" }

func deriveAEAD(pw string, salt []byte) (cipher.AEAD, error) {
	aead, _, err := crypt.NewArgon2([]byte(pw), salt)
	return aead, err
}

// masterEnable включает мастер-пароль с новой солью (смена пароля - то же самое).
func masterEnable(pw string) error {
	if pw == "" {
		return errors.New("пустой мастер-пароль")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	aead, err := deriveAEAD(pw, salt)
	if err != nil {
		return err
	}
	vaultMu.Lock()
	vault = vaultState{master: true, salt: salt, aead: aead}
	vaultMu.Unlock()
	return nil
}

// masterUnlock проверяет мастер-пароль по контрольному значению из файла и открывает сейф.
func masterUnlock(pw, saltB64, check string) error {
	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil || len(salt) == 0 {
		return errors.New("в файле настроек нет данных мастер-пароля")
	}
	aead, err := deriveAEAD(pw, salt)
	if err != nil {
		return err
	}
	if check != "" {
		if _, err := mkOpenWith(aead, check); err != nil {
			return errWrongMaster
		}
	}
	vaultMu.Lock()
	vault = vaultState{master: true, salt: salt, aead: aead}
	vaultMu.Unlock()
	return nil
}

// masterDisable возвращает защиту средствами Windows (пароли пере-шифруются при следующем сохранении).
func masterDisable() {
	vaultMu.Lock()
	vault = vaultState{}
	vaultMu.Unlock()
}

func mkSealWith(aead cipher.AEAD, plain string) (string, error) {
	enc, err := crypt.EncryptChaCha([]byte(plain), aead)
	if err != nil {
		return "", err
	}
	return mkPrefix + base64.StdEncoding.EncodeToString(enc), nil
}

func mkOpenWith(aead cipher.AEAD, v string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(v, mkPrefix))
	if err != nil {
		return "", errors.New("повреждённые данные")
	}
	plain, err := crypt.DecryptChaCha(raw, aead)
	if err != nil {
		return "", errors.New("повреждённые данные или неверный ключ")
	}
	return string(plain), nil
}

func sealSecret(plain string) (string, error) {
	if plain == "" {
		return "", nil
	}
	v := vaultSnapshot()
	if v.master {
		if v.aead == nil {
			return "", errLocked
		}
		return mkSealWith(v.aead, plain)
	}
	return sealImpl(plain)
}

func openSecret(s string) (string, error) {
	if s == "" {
		return "", nil
	}
	switch {
	case strings.HasPrefix(s, mkPrefix):
		v := vaultSnapshot()
		if v.aead == nil {
			return "", errLocked
		}
		return mkOpenWith(v.aead, s)
	case strings.HasPrefix(s, sealPrefix):
		return openImpl(s)
	default:
		return s, nil
	}
}
