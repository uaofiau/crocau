package main

import (
	"bufio"
	"net"
	"os"
	"strings"
	"time"
)

// Передача файлов из меню Проводника: «crocau.exe --send путь». Если выделено несколько файлов, Проводник запускает
// отдельный процесс на каждый. Первый занимает локальный порт и становится окном программы, остальные пересылают
// ему свои пути и сразу завершаются - в итоге одно окно со всем выделенным.

const instanceAddr = "127.0.0.1:29007"

var (
	shellInitPaths []string
	shellListener  net.Listener
)

// shellSendMain: возвращает код выхода (>=0), если всё сделано пересылкой, или -1 - тогда нужно открыть окно.
func shellSendMain(paths []string) int {
	return shellSendAt(instanceAddr, paths)
}

func shellSendAt(addr string, paths []string) int {
	if ln, err := net.Listen("tcp", addr); err == nil {
		shellListener = ln
		shellInitPaths = paths
		return -1
	}
	for i := 0; i < 40; i++ {
		if forwardPaths(addr, paths) == nil {
			return 0
		}
		time.Sleep(150 * time.Millisecond)
	}
	shellInitPaths = paths // не удалось передать: открываем своё окно
	return -1
}

func forwardPaths(addr string, paths []string) error {
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	w := bufio.NewWriter(c)
	for _, p := range paths {
		if p != "" && !strings.ContainsAny(p, "\r\n") {
			_, _ = w.WriteString(p + "\n")
		}
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if cw, ok := c.(*net.TCPConn); ok {
		_ = cw.CloseWrite()
	}
	_, _ = bufio.NewReader(c).ReadByte() // дождаться подтверждения, что получатель принял
	return nil
}

// serveShell принимает пути от других процессов и отдаёт их в on (в любом потоке).
func serveShell(ln net.Listener, on func(paths []string)) {
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				var paths []string
				sc := bufio.NewScanner(c)
				sc.Buffer(make([]byte, 64*1024), 1<<20)
				for sc.Scan() {
					if p := strings.TrimSpace(sc.Text()); p != "" {
						paths = append(paths, p)
					}
				}
				if len(paths) > 0 {
					on(paths)
				}
				_, _ = c.Write([]byte{1})
			}(c)
		}
	}()
}

// listenIfFree при обычном запуске занимает порт, чтобы меню Проводника отправляло файлы в это окно.
func listenIfFree() {
	if shellListener == nil {
		if ln, err := net.Listen("tcp", instanceAddr); err == nil {
			shellListener = ln
		}
	}
}

func existingPaths(ps []string) []string {
	var out []string
	for _, p := range ps {
		if _, err := os.Stat(p); err == nil {
			out = append(out, p)
		}
	}
	return out
}
