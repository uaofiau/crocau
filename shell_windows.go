//go:build windows

package main

import (
	"errors"
	"os"

	"golang.org/x/sys/windows/registry"
)

// Пункт «Отправить через Crocau» в контекстном меню Проводника (для файлов и папок) - только для текущего
// пользователя (HKCU), права администратора не нужны. В Windows 11 пункт находится в «Показать дополнительные параметры».

var shellKeys = []string{`Software\Classes\*\shell\Crocau`, `Software\Classes\Directory\shell\Crocau`}

const shellTitle = "Отправить через Crocau"

func shellCommand(exe string) string { return `"` + exe + `" --send "%1"` }

func shellInstalled() bool {
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	for _, k := range shellKeys {
		key, err := registry.OpenKey(registry.CURRENT_USER, k+`\command`, registry.QUERY_VALUE)
		if err != nil {
			return false
		}
		v, _, err := key.GetStringValue("")
		key.Close()
		if err != nil || v != shellCommand(exe) {
			return false
		}
	}
	return true
}

func shellRegister() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	for _, k := range shellKeys {
		key, _, err := registry.CreateKey(registry.CURRENT_USER, k, registry.SET_VALUE)
		if err != nil {
			return err
		}
		err = key.SetStringValue("", shellTitle)
		if err == nil {
			err = key.SetStringValue("Icon", `"`+exe+`",0`)
		}
		key.Close()
		if err != nil {
			return err
		}
		ck, _, err := registry.CreateKey(registry.CURRENT_USER, k+`\command`, registry.SET_VALUE)
		if err != nil {
			return err
		}
		err = ck.SetStringValue("", shellCommand(exe))
		ck.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func shellUnregister() error {
	var first error
	for _, k := range shellKeys {
		for _, p := range []string{k + `\command`, k} {
			if err := registry.DeleteKey(registry.CURRENT_USER, p); err != nil && !errors.Is(err, registry.ErrNotExist) && first == nil {
				first = err
			}
		}
	}
	return first
}

// shellSelfTest: регистрация -> проверка -> удаление.
func shellSelfTest() (bool, string) {
	if err := shellRegister(); err != nil {
		return false, "register: " + err.Error()
	}
	if !shellInstalled() {
		_ = shellUnregister()
		return false, "not detected after register"
	}
	if err := shellUnregister(); err != nil {
		return false, "unregister: " + err.Error()
	}
	if shellInstalled() {
		return false, "still present after unregister"
	}
	return true, ""
}
