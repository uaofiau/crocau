package main

import (
	"bufio"
	"encoding/base64"
	"io"
	"net"
	"strings"
	"time"
)

// Тестовые прокси-серверы для самотеста. Имена из resolve подменяются адресами (так проверяется,
// что имя сервера уходит именно прокси, а не разрешается локально).

type testProxy struct {
	Addr string
	ln   net.Listener
}

func (t *testProxy) Close() { _ = t.ln.Close() }

func mapDial(resolve map[string]string) func(string) (net.Conn, error) {
	return func(target string) (net.Conn, error) {
		h, p, err := net.SplitHostPort(target)
		if err != nil {
			return nil, err
		}
		if m, ok := resolve[h]; ok {
			h = m
		}
		return net.DialTimeout("tcp", net.JoinHostPort(h, p), 5*time.Second)
	}
}

func listenTest(handler func(c net.Conn)) *testProxy {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handler(c)
		}
	}()
	return &testProxy{Addr: ln.Addr().String(), ln: ln}
}

func startTestSocks5(user, pass string, resolve map[string]string) *testProxy {
	return listenTest(func(c net.Conn) { serveSocks5(c, user, pass, mapDial(resolve)) })
}

func startTestSocks4(user string, resolve map[string]string) *testProxy {
	return listenTest(func(c net.Conn) {
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(20 * time.Second))
		var h [8]byte
		if _, err := io.ReadFull(c, h[:]); err != nil || h[0] != 4 || h[1] != 1 {
			return
		}
		port := int(h[2])<<8 | int(h[3])
		readZ := func() (string, bool) {
			var sb strings.Builder
			var b [1]byte
			for {
				if _, err := io.ReadFull(c, b[:]); err != nil {
					return "", false
				}
				if b[0] == 0 {
					return sb.String(), true
				}
				sb.WriteByte(b[0])
			}
		}
		uid, ok := readZ()
		if !ok {
			return
		}
		host := net.IP(h[4:8]).String()
		if h[4] == 0 && h[5] == 0 && h[6] == 0 && h[7] != 0 {
			host, ok = readZ()
			if !ok {
				return
			}
		}
		if uid != user {
			_, _ = c.Write([]byte{0, 0x5D, 0, 0, 0, 0, 0, 0})
			return
		}
		up, err := mapDial(resolve)(net.JoinHostPort(host, itoa(port)))
		if err != nil {
			_, _ = c.Write([]byte{0, 0x5B, 0, 0, 0, 0, 0, 0})
			return
		}
		defer up.Close()
		_, _ = c.Write([]byte{0, 0x5A, 0, 0, 0, 0, 0, 0})
		_ = c.SetDeadline(time.Time{})
		pipe(c, up)
	})
}

func startTestHTTP(user, pass string, resolve map[string]string) *testProxy {
	return listenTest(func(c net.Conn) {
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(20 * time.Second))
		br := bufio.NewReader(c)
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		f := strings.Fields(line)
		if len(f) < 2 || f[0] != "CONNECT" {
			return
		}
		auth := ""
		for {
			l, err := br.ReadString('\n')
			if err != nil {
				return
			}
			l = strings.TrimRight(l, "\r\n")
			if l == "" {
				break
			}
			if strings.HasPrefix(strings.ToLower(l), "proxy-authorization:") {
				auth = strings.TrimSpace(l[len("proxy-authorization:"):])
			}
		}
		if user != "" {
			want := "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
			if auth != want {
				_, _ = c.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"t\"\r\nContent-Length: 0\r\n\r\n"))
				return
			}
		}
		up, err := mapDial(resolve)(f[1])
		if err != nil {
			_, _ = c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"))
			return
		}
		defer up.Close()
		_, _ = c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		_ = c.SetDeadline(time.Time{})
		pipe(&bufConn{Conn: c, r: br}, up)
	})
}
