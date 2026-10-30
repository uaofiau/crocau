package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Минимальный клиент WebSocket (RFC 6455) поверх TLS: без сторонних библиотек. Достаточно для текстовых сообщений.

type wsConn struct {
	c  net.Conn
	br *bufio.Reader
	mu sync.Mutex // защищает запись
}

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// wsDial открывает ws:// или wss:// напрямую или через маршрут r (прокси).
func wsDial(ctx context.Context, rawURL string, r Route, timeout time.Duration) (*wsConn, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	host := u.Host
	port := u.Port()
	secure := u.Scheme == "wss"
	if port == "" {
		if secure {
			port = "443"
		} else {
			port = "80"
		}
		host = net.JoinHostPort(u.Hostname(), port)
	}
	var conn net.Conn
	if r.P == nil {
		d := net.Dialer{Timeout: timeout}
		conn, err = d.DialContext(ctx, "tcp", host)
	} else {
		conn, err = dialVia(r, host, timeout)
	}
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if secure {
		tc := tls.Client(conn, &tls.Config{ServerName: u.Hostname()})
		if err := tc.Handshake(); err != nil {
			conn.Close()
			return nil, err
		}
		conn = tc
	}
	keyRaw := make([]byte, 16)
	_, _ = rand.Read(keyRaw)
	key := base64.StdEncoding.EncodeToString(keyRaw)
	path := u.RequestURI()
	if path == "" {
		path = "/"
	}
	req := "GET " + path + " HTTP/1.1\r\nHost: " + u.Host + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\nSec-WebSocket-Version: 13\r\nUser-Agent: " + uploaderUA + "\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: "GET"})
	if err != nil {
		conn.Close()
		return nil, err
	}
	if resp.StatusCode != 101 {
		conn.Close()
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	sum := sha1.Sum([]byte(key + wsGUID))
	if resp.Header.Get("Sec-WebSocket-Accept") != base64.StdEncoding.EncodeToString(sum[:]) {
		conn.Close()
		return nil, errors.New("неверный ответ WebSocket")
	}
	_ = conn.SetDeadline(time.Time{})
	return &wsConn{c: conn, br: br}, nil
}

func (w *wsConn) writeFrame(op byte, payload []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	hdr := []byte{0x80 | op}
	n := len(payload)
	switch {
	case n < 126:
		hdr = append(hdr, 0x80|byte(n))
	case n < 65536:
		hdr = append(hdr, 0x80|126, byte(n>>8), byte(n))
	default:
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, uint64(n))
		hdr = append(hdr, 0x80|127)
		hdr = append(hdr, b...)
	}
	mask := make([]byte, 4)
	_, _ = rand.Read(mask)
	hdr = append(hdr, mask...)
	body := make([]byte, n)
	for i := range payload {
		body[i] = payload[i] ^ mask[i%4]
	}
	_ = w.c.SetWriteDeadline(time.Now().Add(20 * time.Second))
	if _, err := w.c.Write(append(hdr, body...)); err != nil {
		return err
	}
	return nil
}

func (w *wsConn) WriteText(b []byte) error { return w.writeFrame(1, b) }

// ReadMessage читает следующее текстовое/двоичное сообщение (ping/pong обрабатывает сам); ждёт не дольше d (0 - без предела).
func (w *wsConn) ReadMessage(d time.Duration) ([]byte, error) {
	var msg []byte
	for {
		if d > 0 {
			_ = w.c.SetReadDeadline(time.Now().Add(d))
		} else {
			_ = w.c.SetReadDeadline(time.Time{})
		}
		h := make([]byte, 2)
		if _, err := io.ReadFull(w.br, h); err != nil {
			return nil, err
		}
		fin := h[0]&0x80 != 0
		op := h[0] & 0x0f
		masked := h[1]&0x80 != 0
		n := uint64(h[1] & 0x7f)
		if n == 126 {
			b := make([]byte, 2)
			if _, err := io.ReadFull(w.br, b); err != nil {
				return nil, err
			}
			n = uint64(binary.BigEndian.Uint16(b))
		} else if n == 127 {
			b := make([]byte, 8)
			if _, err := io.ReadFull(w.br, b); err != nil {
				return nil, err
			}
			n = binary.BigEndian.Uint64(b)
		}
		if n > 16<<20 {
			return nil, errors.New("слишком большое сообщение")
		}
		var mk []byte
		if masked {
			mk = make([]byte, 4)
			if _, err := io.ReadFull(w.br, mk); err != nil {
				return nil, err
			}
		}
		p := make([]byte, n)
		if _, err := io.ReadFull(w.br, p); err != nil {
			return nil, err
		}
		if masked {
			for i := range p {
				p[i] ^= mk[i%4]
			}
		}
		switch op {
		case 8:
			return nil, io.EOF
		case 9:
			_ = w.writeFrame(10, p)
			continue
		case 10:
			continue
		}
		msg = append(msg, p...)
		if fin {
			return msg, nil
		}
	}
}

func (w *wsConn) Close() error {
	_ = w.writeFrame(8, nil)
	return w.c.Close()
}

func wsHost(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return strings.TrimPrefix(rawURL, "wss://")
	}
	return u.Host
}
