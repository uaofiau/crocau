//go:build windows

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/sys/windows"
)

// Правила брандмауэра создаются под текущий путь к exe (программа портабельна, путь может меняться).
func fwNames() (tcp, udp string) {
	exe, _ := os.Executable()
	h := sha256.Sum256([]byte(strings.ToLower(exe)))
	id := hex.EncodeToString(h[:3])
	return "crocau LAN TCP " + id, "crocau LAN UDP " + id
}

func netsh(args ...string) error {
	cmd := exec.Command("netsh", append([]string{"advfirewall", "firewall"}, args...)...)
	hideWindow(cmd)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("netsh: %v", err)
	}
	return nil
}

func fwPresent() bool {
	tcp, udp := fwNames()
	return netsh("show", "rule", "name="+tcp) == nil && netsh("show", "rule", "name="+udp) == nil
}

func tcpRange() string {
	return lanRelayPorts[0] + "-" + lanRelayPorts[len(lanRelayPorts)-1]
}

// fwInstallDirect создаёт правила (нужны права администратора).
func fwInstallDirect() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	tcp, udp := fwNames()
	_ = netsh("delete", "rule", "name="+tcp)
	_ = netsh("delete", "rule", "name="+udp)
	e1 := netsh("add", "rule", "name="+tcp, "dir=in", "action=allow", "protocol=TCP", "localport="+tcpRange(),
		"program="+exe, "profile=any", "enable=yes")
	e2 := netsh("add", "rule", "name="+udp, "dir=in", "action=allow", "protocol=UDP", "localport="+itoa(lanDiscPort),
		"program="+exe, "profile=any", "enable=yes")
	if e1 != nil {
		return e1
	}
	return e2
}

func fwRemoveDirect() error {
	tcp, udp := fwNames()
	e1 := netsh("delete", "rule", "name="+tcp)
	e2 := netsh("delete", "rule", "name="+udp)
	if e1 != nil {
		return e1
	}
	return e2
}

// elevated перезапускает этот же exe с правами администратора (запрос UAC) и ждёт результата.
func elevated(arg string, done func() bool) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(exe)
	args, _ := windows.UTF16PtrFromString(arg)
	if err := windows.ShellExecute(0, verb, file, args, nil, windows.SW_HIDE); err != nil {
		return fmt.Errorf("запрос прав администратора отклонён или недоступен: %v", err)
	}
	for i := 0; i < 120; i++ {
		time.Sleep(500 * time.Millisecond)
		if done() {
			return nil
		}
	}
	return errors.New("не дождались выполнения операции от имени администратора")
}

// fwEnsure гарантирует наличие правил: сначала пробует напрямую (если программа запущена от администратора),
// иначе один раз просит подтверждение UAC.
func fwEnsure() error {
	if fwPresent() {
		return nil
	}
	if err := fwInstallDirect(); err == nil && fwPresent() {
		return nil
	}
	return elevated("--fw-install", fwPresent)
}

func fwRemove() error {
	if !fwPresent() {
		return nil
	}
	if err := fwRemoveDirect(); err == nil && !fwPresent() {
		return nil
	}
	return elevated("--fw-remove", func() bool { return !fwPresent() })
}

func fwInstallMain() int {
	if fwInstallDirect() != nil {
		return 1
	}
	return 0
}

func fwRemoveMain() int {
	if fwRemoveDirect() != nil {
		return 1
	}
	return 0
}

// fwSelfTest (для CI, запускается от администратора): создать правила, увидеть их, удалить.
func fwSelfTest() int {
	if err := fwInstallDirect(); err != nil {
		testLogf("FIREWALL: add failed: %v", err)
		return 1
	}
	present := fwPresent()
	if err := fwRemoveDirect(); err != nil {
		testLogf("FIREWALL: remove failed: %v", err)
		return 1
	}
	gone := !fwPresent()
	exe, _ := os.Executable()
	if present && gone {
		testLogf("FIREWALL RULES (add / present / remove) from %s: OK", exe)
		return 0
	}
	testLogf("FIREWALL RULES: FAIL present=%v gone=%v", present, gone)
	return 1
}
