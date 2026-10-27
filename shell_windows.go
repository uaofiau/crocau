//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Ярлык «Crocau» в папке «Отправить» (shell:sendto): Проводник → ПКМ → Отправить → Crocau.
// Создаётся только для текущего пользователя, права администратора не нужны, общее контекстное меню не засоряется.
// Выделенные файлы и папки Проводник передаёт программе аргументами: crocau.exe --send путь1 путь2 ...

const sendToName = "Crocau.lnk"

var (
	modOle32             = windows.NewLazySystemDLL("ole32.dll")
	procCoInitializeEx   = modOle32.NewProc("CoInitializeEx")
	procCoUninitialize   = modOle32.NewProc("CoUninitialize")
	procCoCreateInstance = modOle32.NewProc("CoCreateInstance")
)

var (
	clsidShellLink  = windows.GUID{Data1: 0x00021401, Data4: [8]byte{0xC0, 0, 0, 0, 0, 0, 0, 0x46}}
	iidIShellLinkW  = windows.GUID{Data1: 0x000214F9, Data4: [8]byte{0xC0, 0, 0, 0, 0, 0, 0, 0x46}}
	iidIPersistFile = windows.GUID{Data1: 0x0000010B, Data4: [8]byte{0xC0, 0, 0, 0, 0, 0, 0, 0x46}}
)

func sendToPath() string {
	return filepath.Join(os.Getenv("APPDATA"), "Microsoft", "Windows", "SendTo", sendToName)
}

// vcall вызывает метод COM-объекта по номеру в таблице виртуальных методов.
func vcall(obj uintptr, idx int, args ...uintptr) uintptr {
	vt := *(*uintptr)(unsafe.Pointer(obj))
	fn := *(*uintptr)(unsafe.Pointer(vt + uintptr(idx)*unsafe.Sizeof(uintptr(0))))
	var a [6]uintptr
	a[0] = obj
	copy(a[1:], args)
	r, _, _ := syscall.Syscall6(fn, uintptr(len(args)+1), a[0], a[1], a[2], a[3], a[4], a[5])
	return r
}

func comRelease(obj uintptr) {
	if obj != 0 {
		vcall(obj, 2)
	}
}

func u16(s string) uintptr {
	p, _ := windows.UTF16PtrFromString(s)
	return uintptr(unsafe.Pointer(p))
}

// withShellLink выполняет f на отдельном потоке с инициализированным COM; передаёт IShellLinkW и IPersistFile.
func withShellLink(f func(psl, ppf uintptr) error) error {
	ch := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		_, _, _ = procCoInitializeEx.Call(0, 2) // COINIT_APARTMENTTHREADED
		defer procCoUninitialize.Call()
		var psl uintptr
		if hr, _, _ := procCoCreateInstance.Call(uintptr(unsafe.Pointer(&clsidShellLink)), 0, 1, // CLSCTX_INPROC_SERVER
			uintptr(unsafe.Pointer(&iidIShellLinkW)), uintptr(unsafe.Pointer(&psl))); hr != 0 || psl == 0 {
			ch <- fmt.Errorf("не удалось создать ярлык: 0x%x", hr)
			return
		}
		defer comRelease(psl)
		var ppf uintptr
		if hr := vcall(psl, 0, uintptr(unsafe.Pointer(&iidIPersistFile)), uintptr(unsafe.Pointer(&ppf))); hr != 0 || ppf == 0 {
			ch <- fmt.Errorf("IPersistFile: 0x%x", hr)
			return
		}
		defer comRelease(ppf)
		ch <- f(psl, ppf)
	}()
	return <-ch
}

func hrErr(what string, hr uintptr) error {
	if hr != 0 {
		return fmt.Errorf("%s: 0x%x", what, hr)
	}
	return nil
}

func createSendToLink(lnk, exe string) error {
	if err := os.MkdirAll(filepath.Dir(lnk), 0755); err != nil {
		return err
	}
	return withShellLink(func(psl, ppf uintptr) error {
		if err := hrErr("SetPath", vcall(psl, 20, u16(exe))); err != nil {
			return err
		}
		_ = vcall(psl, 11, u16("--send"))
		_ = vcall(psl, 9, u16(filepath.Dir(exe)))
		_ = vcall(psl, 7, u16("Отправить через Crocau"))
		_ = vcall(psl, 17, u16(exe), 0)
		return hrErr("Save", vcall(ppf, 6, u16(lnk), 1))
	})
}

func readSendToLink(lnk string) (target, args string, err error) {
	err = withShellLink(func(psl, ppf uintptr) error {
		if e := hrErr("Load", vcall(ppf, 5, u16(lnk), 0)); e != nil {
			return e
		}
		buf := make([]uint16, 1024)
		if e := hrErr("GetPath", vcall(psl, 3, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 0, 0)); e != nil {
			return e
		}
		target = windows.UTF16ToString(buf)
		buf2 := make([]uint16, 1024)
		_ = vcall(psl, 10, uintptr(unsafe.Pointer(&buf2[0])), uintptr(len(buf2)))
		args = windows.UTF16ToString(buf2)
		return nil
	})
	return
}

var legacyShellKeys = []string{`Software\Classes\*\shell\Crocau`, `Software\Classes\Directory\shell\Crocau`}

// shellCleanupLegacy убирает пункты, которые ранние версии добавляли в общее контекстное меню.
func shellCleanupLegacy() {
	for _, k := range legacyShellKeys {
		key, err := registry.OpenKey(registry.CURRENT_USER, k+`\command`, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		v, _, err := key.GetStringValue("")
		key.Close()
		if err != nil || !strings.Contains(v, "--send") {
			continue
		}
		_ = registry.DeleteKey(registry.CURRENT_USER, k+`\command`)
		_ = registry.DeleteKey(registry.CURRENT_USER, k)
	}
}

func shellInstalled() bool {
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	lnk := sendToPath()
	if _, err := os.Stat(lnk); err != nil {
		return false
	}
	t, a, err := readSendToLink(lnk)
	return err == nil && strings.EqualFold(t, exe) && strings.TrimSpace(a) == "--send"
}

func shellRegister() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	shellCleanupLegacy()
	return createSendToLink(sendToPath(), exe)
}

func shellUnregister() error {
	shellCleanupLegacy()
	if err := os.Remove(sendToPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// shellSelfTest: создать ярлык -> проверить нашим чтением и независимо через WScript.Shell -> удалить.
func shellSelfTest() (bool, string) {
	exe, _ := os.Executable()
	if err := shellRegister(); err != nil {
		return false, "register: " + err.Error()
	}
	if !shellInstalled() {
		_ = shellUnregister()
		return false, "not detected after register"
	}
	msg := ""
	ps := `$s=(New-Object -ComObject WScript.Shell).CreateShortcut($env:CROCAU_LNK); Write-Output ($s.TargetPath + '|' + $s.Arguments)`
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", ps)
	cmd.Env = append(os.Environ(), "CROCAU_LNK="+sendToPath())
	hideWindow(cmd)
	if out, err := cmd.Output(); err == nil {
		got := strings.TrimSpace(string(out))
		if !strings.EqualFold(got, exe+"|--send") {
			_ = shellUnregister()
			return false, "WScript.Shell sees: " + got
		}
		msg = "verified by WScript.Shell"
	}
	if err := shellUnregister(); err != nil {
		return false, "unregister: " + err.Error()
	}
	if shellInstalled() {
		return false, "still present after unregister"
	}
	return true, msg
}
