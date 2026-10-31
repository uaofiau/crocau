//go:build windows

package main

import (
	"os"
	"path/filepath"
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

func geomPath() string { return filepath.Join(exeDir(), "crocau-window.dat") }

// saveWindowGeom запоминает положение и размер окна (обычного, не свёрнутого) для этого компьютера.
func saveWindowGeom(mw *walk.MainWindow) {
	var wp win.WINDOWPLACEMENT
	wp.Length = uint32(unsafe.Sizeof(wp))
	if !win.GetWindowPlacement(mw.Handle(), &wp) {
		return
	}
	r := wp.RcNormalPosition
	g := winGeom{X: int(r.Left), Y: int(r.Top), W: int(r.Right - r.Left), H: int(r.Bottom - r.Top), Max: wp.ShowCmd == win.SW_SHOWMAXIMIZED}
	if g.W < 100 || g.H < 100 {
		return
	}
	_ = os.WriteFile(geomPath(), []byte(encodeGeom(machineHost(), g)), 0o644)
}

// restoreWindowGeom применяет сохранённое положение, если оно сделано на этом компьютере; окно всегда
// вписывается в рабочую область ближайшего монитора (учитывает смену разрешения и отключённые мониторы).
func restoreWindowGeom(mw *walk.MainWindow, minW, minH int) {
	b, err := os.ReadFile(geomPath())
	if err != nil {
		return
	}
	g, ok := parseGeom(string(b), machineHost())
	if !ok {
		return
	}
	// сначала ставим окно на сохранённое место, затем смотрим, какой монитор ему ближайший, и вписываем в него
	win.SetWindowPos(mw.Handle(), 0, int32(g.X), int32(g.Y), int32(g.W), int32(g.H), win.SWP_NOZORDER|win.SWP_NOACTIVATE)
	hm := win.MonitorFromWindow(mw.Handle(), win.MONITOR_DEFAULTTONEAREST)
	var mi win.MONITORINFO
	mi.CbSize = uint32(unsafe.Sizeof(mi))
	if hm == 0 || !win.GetMonitorInfo(hm, &mi) {
		return
	}
	w := mi.RcWork
	g = clampGeom(g, int(w.Left), int(w.Top), int(w.Right), int(w.Bottom), minW, minH)
	win.SetWindowPos(mw.Handle(), 0, int32(g.X), int32(g.Y), int32(g.W), int32(g.H), win.SWP_NOZORDER|win.SWP_NOACTIVATE)
	if g.Max {
		mw.Synchronize(func() { win.ShowWindow(mw.Handle(), win.SW_MAXIMIZE) })
	}
}
