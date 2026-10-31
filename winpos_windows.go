//go:build windows

package main

import (
	"os"
	"unsafe"

	"github.com/lxn/walk"
	"github.com/lxn/win"
	"golang.org/x/sys/windows/registry"
)

func machineHost() string {
	guid := ""
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE|registry.WOW64_64KEY); err == nil {
		guid, _, _ = k.GetStringValue("MachineGuid")
		k.Close()
	}
	host, _ := os.Hostname()
	return hostToken(guid, host)
}

// currentWinRecord - запись о положении окна (обычного, не свёрнутого) для crocau.ini.
func currentWinRecord(mw *walk.MainWindow) string {
	var wp win.WINDOWPLACEMENT
	wp.Length = uint32(unsafe.Sizeof(wp))
	if !win.GetWindowPlacement(mw.Handle(), &wp) {
		return ""
	}
	r := wp.RcNormalPosition
	g := winGeom{X: int(r.Left), Y: int(r.Top), W: int(r.Right - r.Left), H: int(r.Bottom - r.Top), Max: wp.ShowCmd == win.SW_SHOWMAXIMIZED}
	if g.W < 100 || g.H < 100 {
		return ""
	}
	return encodeGeom(machineHost(), g)
}

// restoreWindowGeom применяет сохранённое положение, если оно сделано на этом компьютере (иначе возвращает false:
// запись надо сбросить); окно всегда вписывается в рабочую область ближайшего монитора (смена разрешения,
// отключённый монитор).
func restoreWindowGeom(mw *walk.MainWindow, rec string, minW, minH int) bool {
	g, ok := parseGeom(rec, machineHost())
	if !ok {
		return false
	}
	// сначала ставим окно на сохранённое место, затем смотрим, какой монитор ему ближайший, и вписываем в него
	win.SetWindowPos(mw.Handle(), 0, int32(g.X), int32(g.Y), int32(g.W), int32(g.H), win.SWP_NOZORDER|win.SWP_NOACTIVATE)
	hm := win.MonitorFromWindow(mw.Handle(), win.MONITOR_DEFAULTTONEAREST)
	var mi win.MONITORINFO
	mi.CbSize = uint32(unsafe.Sizeof(mi))
	if hm == 0 || !win.GetMonitorInfo(hm, &mi) {
		return true
	}
	w := mi.RcWork
	g = clampGeom(g, int(w.Left), int(w.Top), int(w.Right), int(w.Bottom), minW, minH)
	win.SetWindowPos(mw.Handle(), 0, int32(g.X), int32(g.Y), int32(g.W), int32(g.H), win.SWP_NOZORDER|win.SWP_NOACTIVATE)
	if g.Max {
		mw.Synchronize(func() { win.ShowWindow(mw.Handle(), win.SW_MAXIMIZE) })
	}
	return true
}
