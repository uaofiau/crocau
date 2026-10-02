//go:build windows

package main

import (
	"github.com/lxn/win"
	"golang.org/x/sys/windows"
)

// widenTooltips увеличивает максимальную ширину (по умолчанию 300 пикселей) и время показа
// всплывающих подсказок нашего процесса, чтобы длинная подсказка не превращалась в узкую колонку.
func widenTooltips(width, popMs int) {
	pid := windows.GetCurrentProcessId()
	cb := windows.NewCallback(func(hwnd uintptr, lparam uintptr) uintptr {
		var buf [64]uint16
		n, _ := windows.GetClassName(windows.HWND(hwnd), &buf[0], int32(len(buf)))
		if n > 0 && windows.UTF16ToString(buf[:n]) == "tooltips_class32" {
			var wpid uint32
			_, _ = windows.GetWindowThreadProcessId(windows.HWND(hwnd), &wpid)
			if wpid == pid {
				h := win.HWND(hwnd)
				win.SendMessage(h, win.TTM_SETMAXTIPWIDTH, 0, uintptr(width))
				win.SendMessage(h, 0x0403, 2, uintptr(popMs)) // TTM_SETDELAYTIME, TTDT_AUTOPOP
			}
		}
		return 1
	})
	_ = windows.EnumWindows(cb, nil)
}
