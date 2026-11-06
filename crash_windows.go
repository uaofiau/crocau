//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"time"

	"github.com/lxn/walk"
)

// runGuarded запускает цикл окна; если внутри него случилась непредвиденная ошибка (panic), она записывается в
// crocau-crash.log рядом с программой, а программа продолжает работать, а не закрывается молча.
func runGuarded(mw *walk.MainWindow) {
	for attempt := 0; attempt < 5; attempt++ {
		start := time.Now()
		crashed := func() (c bool) {
			defer func() {
				if r := recover(); r != nil {
					c = true
					logCrash(r)
					func() {
						defer func() { _ = recover() }()
						walk.MsgBox(mw, "crocau", "Произошла внутренняя ошибка, программа продолжает работу.\nПодробности записаны в файл crocau-crash.log рядом с программой - пришлите его разработчику.", walk.MsgBoxIconWarning)
					}()
				}
			}()
			mw.Run()
			return false
		}()
		if !crashed || time.Since(start) < time.Second {
			return
		}
	}
}

func logCrash(r interface{}) {
	f, err := os.OpenFile(filepath.Join(exeDir(), "crocau-crash.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "=== %s  версия %s ===\n%v\n%s\n", time.Now().Format("2006-01-02 15:04:05"), appVersion, r, debug.Stack())
}
