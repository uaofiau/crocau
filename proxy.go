package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/schollz/croc/v10/src/comm"
)

// Route - способ выйти в сеть: напрямую (P == nil) или через прокси.
type Route struct {
	P *ProxyCfg
}

func (r Route) Name() string {
	if r.P == nil {
		return "напрямую"
	}
	return strings.ToUpper(r.P.Type) + " " + r.P.Addr
}

func splitTarget(target string) (string, int, error) {
	h, ps, err := net.SplitHostPort(target)
	if err != nil {
		return "", 0, err
	}
	p, err := strconv.Atoi(ps)
	if err != nil || p < 1 || p > 65535 {
		return "", 0, errors.New("неверный порт")
	}
	return h, p, nil
}

func validAddr(a string) bool {
	h, _, err := splitTarget(a)
	return err == nil && h != ""
}

type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }
func (b *bufConn) CloseWrite() error {
	if cw, ok := b.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// dialVia соединяется с addr (host:port) выбранным способом.
func dialVia(r Route, addr string, timeout time.Duration) (net.Conn, error) {
	if r.P == nil {
		return net.DialTimeout("tcp", addr, timeout)
	}
	conn, err := net.DialTimeout("tcp", r.P.Addr, timeout)
	if err != nil {
		return nil, fmt.Errorf("прокси %s недоступен: %v", r.P.Addr, err)
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	out := conn
	switch r.P.Type {
	case "socks5":
		err = socks5Connect(conn, r.P, addr)
	case "socks4":
		err = socks4Connect(conn, r.P, addr)
	case "http":
		out, err = httpConnect(conn, r.P, addr)
	default:
		err = fmt.Errorf("неизвестный тип прокси %q", r.P.Type)
	}
	if err != nil {
		conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return out, nil
}

func socks5Connect(conn net.Conn, p *ProxyCfg, target string) error {
	host, port, err := splitTarget(target)
	if err != nil {
		return err
	}
	if p.Auth {
		_, err = conn.Write([]byte{5, 2, 0, 2})
	} else {
		_, err = conn.Write([]byte{5, 1, 0})
	}
	if err != nil {
		return err
	}
	var resp [2]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		return fmt.Errorf("socks5: %v", err)
	}
	if resp[0] != 5 {
		return errors.New("socks5: это не SOCKS5-прокси")
	}
	switch resp[1] {
	case 0:
	case 2:
		if !p.Auth {
			return errors.New("socks5: прокси требует логин и пароль")
		}
		if len(p.User) > 255 || len(p.Pass) > 255 {
			return errors.New("socks5: слишком длинный логин или пароль")
		}
		buf := []byte{1, byte(len(p.User))}
		buf = append(buf, p.User...)
		buf = append(buf, byte(len(p.Pass)))
		buf = append(buf, p.Pass...)
		if _, err := conn.Write(buf); err != nil {
			return err
		}
		var ar [2]byte
		if _, err := io.ReadFull(conn, ar[:]); err != nil {
			return fmt.Errorf("socks5: %v", err)
		}
		if ar[1] != 0 {
			return errors.New("socks5: неверный логин или пароль")
		}
	default:
		return errors.New("socks5: прокси не принял способ авторизации")
	}
	req := []byte{5, 1, 0}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			req = append(req, 1)
			req = append(req, ip4...)
		} else {
			req = append(req, 4)
			req = append(req, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return errors.New("слишком длинное имя сервера")
		}
		req = append(req, 3, byte(len(host)))
		req = append(req, host...)
	}
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		return err
	}
	var h [4]byte
	if _, err := io.ReadFull(conn, h[:]); err != nil {
		return fmt.Errorf("socks5: %v", err)
	}
	if h[0] != 5 {
		return errors.New("socks5: неверный ответ прокси")
	}
	if h[1] != 0 {
		return fmt.Errorf("socks5: прокси отказал (код %d)", h[1])
	}
	var n int
	switch h[3] {
	case 1:
		n = 4
	case 4:
		n = 16
	case 3:
		var l [1]byte
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			return err
		}
		n = int(l[0])
	default:
		return errors.New("socks5: неверный ответ прокси")
	}
	_, err = io.CopyN(io.Discard, conn, int64(n+2))
	return err
}

// socks4Connect: для имён серверов используется расширение SOCKS4a.
func socks4Connect(conn net.Conn, p *ProxyCfg, target string) error {
	host, port, err := splitTarget(target)
	if err != nil {
		return err
	}
	req := []byte{4, 1, byte(port >> 8), byte(port)}
	domain := ""
	if ip := net.ParseIP(host); ip != nil {
		ip4 := ip.To4()
		if ip4 == nil {
			return errors.New("socks4: IPv6 не поддерживается")
		}
		req = append(req, ip4...)
	} else {
		req = append(req, 0, 0, 0, 1)
		domain = host
	}
	if p.Auth {
		req = append(req, p.User...)
	}
	req = append(req, 0)
	if domain != "" {
		req = append(req, domain...)
		req = append(req, 0)
	}
	if _, err := conn.Write(req); err != nil {
		return err
	}
	var r [8]byte
	if _, err := io.ReadFull(conn, r[:]); err != nil {
		return fmt.Errorf("socks4: %v", err)
	}
	if r[1] != 0x5A {
		return fmt.Errorf("socks4: прокси отказал (код 0x%02X)", r[1])
	}
	return nil
}

func httpConnect(conn net.Conn, p *ProxyCfg, target string) (net.Conn, error) {
	req := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n"
	if p.Auth {
		req += "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(p.User+":"+p.Pass)) + "\r\n"
	}
	req += "\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		return nil, err
	}
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("http: %v", err)
	}
	f := strings.Fields(line)
	if len(f) < 2 || f[1] != "200" {
		msg := strings.TrimSpace(line)
		if len(f) >= 2 && f[1] == "407" {
			msg = "прокси требует логин и пароль или они неверны (407)"
		}
		return nil, errors.New("http: " + msg)
	}
	for {
		l, err := br.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("http: %v", err)
		}
		if strings.TrimRight(l, "\r\n") == "" {
			break
		}
	}
	return &bufConn{Conn: conn, r: br}, nil
}

// ---------- SOCKS5-сервер (локальный мост для croc и тестовый прокси) ----------

// serveSocks5 обслуживает одно клиентское соединение. Пустой user - без авторизации.
func serveSocks5(c net.Conn, user, pass string, dial func(target string) (net.Conn, error)) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	var h [2]byte
	if _, err := io.ReadFull(c, h[:]); err != nil || h[0] != 5 {
		return
	}
	methods := make([]byte, h[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	want := byte(0)
	if user != "" {
		want = 2
	}
	found := false
	for _, m := range methods {
		if m == want {
			found = true
		}
	}
	if !found {
		_, _ = c.Write([]byte{5, 0xFF})
		return
	}
	_, _ = c.Write([]byte{5, want})
	if want == 2 {
		var v [2]byte
		if _, err := io.ReadFull(c, v[:]); err != nil {
			return
		}
		ub := make([]byte, v[1])
		if _, err := io.ReadFull(c, ub); err != nil {
			return
		}
		var pl [1]byte
		if _, err := io.ReadFull(c, pl[:]); err != nil {
			return
		}
		pb := make([]byte, pl[0])
		if _, err := io.ReadFull(c, pb); err != nil {
			return
		}
		if string(ub) != user || string(pb) != pass {
			_, _ = c.Write([]byte{1, 1})
			return
		}
		_, _ = c.Write([]byte{1, 0})
	}
	var rq [4]byte
	if _, err := io.ReadFull(c, rq[:]); err != nil {
		return
	}
	fail := func(code byte) { _, _ = c.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0}) }
	if rq[0] != 5 || rq[1] != 1 {
		fail(7)
		return
	}
	var host string
	switch rq[3] {
	case 1:
		b := make([]byte, 4)
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 4:
		b := make([]byte, 16)
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 3:
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return
		}
		b := make([]byte, l[0])
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		host = string(b)
	default:
		fail(8)
		return
	}
	var pb [2]byte
	if _, err := io.ReadFull(c, pb[:]); err != nil {
		return
	}
	target := net.JoinHostPort(host, strconv.Itoa(int(pb[0])<<8|int(pb[1])))
	up, err := dial(target)
	if err != nil {
		fail(5)
		return
	}
	defer up.Close()
	_, _ = c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	_ = c.SetDeadline(time.Time{})
	pipe(c, up)
}

// pipe гонит данные в обе стороны; конец одной стороны передаётся другой как полузакрытие.
func pipe(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = dst.Close()
		}
	}
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
}

// Bridge - локальный SOCKS5-сервер с одноразовым логином/паролем; выходит в сеть через Route.
type Bridge struct {
	URL     string
	ln      net.Listener
	mu      sync.Mutex
	conns   []net.Conn
	lastErr string
	closed  bool
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func startBridge(r Route) (*Bridge, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	user, pass := randHex(6), randHex(12)
	b := &Bridge{ln: ln, URL: "socks5://" + user + ":" + pass + "@" + ln.Addr().String()}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			b.track(c)
			go serveSocks5(c, user, pass, func(target string) (net.Conn, error) {
				up, err := dialVia(r, target, 8*time.Second)
				if err != nil {
					b.mu.Lock()
					b.lastErr = err.Error()
					b.mu.Unlock()
					return nil, err
				}
				b.track(up)
				return up, nil
			})
		}
	}()
	return b, nil
}

func (b *Bridge) track(c net.Conn) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		c.Close()
		return
	}
	b.conns = append(b.conns, c)
}

func (b *Bridge) LastError() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.lastErr
}

func (b *Bridge) Close() {
	b.mu.Lock()
	b.closed = true
	conns := b.conns
	b.conns = nil
	b.mu.Unlock()
	_ = b.ln.Close()
	for _, c := range conns {
		_ = c.Close()
	}
}

// ---------- Проверка доступности серверов croc ----------

// probe соединяется с relay выбранным способом и обменивается с ним ping/pong.
func probe(r Route, relay string, timeout time.Duration) (time.Duration, error) {
	start := time.Now()
	conn, err := dialVia(r, relay, timeout)
	if err != nil {
		return 0, err
	}
	timer := time.AfterFunc(timeout, func() { conn.Close() })
	defer timer.Stop()
	defer conn.Close()
	c := comm.New(conn)
	if err := c.Send([]byte("ping")); err != nil {
		return 0, err
	}
	b, err := c.Receive()
	if err != nil {
		return 0, err
	}
	if string(b) != "pong" {
		return 0, errors.New("нет ответа pong")
	}
	return time.Since(start), nil
}

type CheckResult struct {
	RTT time.Duration
	Err error
}

// checkAll возвращает результаты [маршрут][relay], проверяя всё параллельно.
func checkAll(routes []Route, relays []string, timeout time.Duration) [][]CheckResult {
	res := make([][]CheckResult, len(routes))
	var wg sync.WaitGroup
	for i := range routes {
		res[i] = make([]CheckResult, len(relays))
		for k := range relays {
			wg.Add(1)
			go func(i, k int) {
				defer wg.Done()
				rtt, err := probe(routes[i], relays[k], timeout)
				res[i][k] = CheckResult{RTT: rtt, Err: err}
			}(i, k)
		}
	}
	wg.Wait()
	return res
}

// orderRoutes ставит вперёд рабочие маршруты. Первый маршрут (обычно "напрямую") проверяется один:
// если он работает, остальные не трогаем.
func orderRoutes(routes []Route, relay string, timeout time.Duration) []Route {
	if len(routes) < 2 {
		return routes
	}
	if _, err := probe(routes[0], relay, timeout); err == nil {
		return routes
	}
	rest := routes[1:]
	ok := make([]bool, len(rest))
	var wg sync.WaitGroup
	for i := range rest {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := probe(rest[i], relay, timeout)
			ok[i] = err == nil
		}(i)
	}
	wg.Wait()
	var out []Route
	for i, r := range rest {
		if ok[i] {
			out = append(out, r)
		}
	}
	for i, r := range rest {
		if !ok[i] {
			out = append(out, r)
		}
	}
	return append(out, routes[0])
}

// routesFor строит список маршрутов по настройкам.
func routesFor(s Settings) ([]Route, error) {
	var list []Route
	for i := range s.Proxies {
		p := s.Proxies[i]
		p.Type = normType(p.Type)
		p.Addr = strings.TrimSpace(p.Addr)
		if p.Addr == "" {
			continue
		}
		if !validAddr(p.Addr) {
			return nil, fmt.Errorf("неверный адрес прокси %q: нужен вид хост:порт", p.Addr)
		}
		list = append(list, Route{P: &p})
	}
	switch s.ProxyMode {
	case modeDirect:
		return []Route{{}}, nil
	case modeProxy:
		if s.ProxySel < 0 || s.ProxySel >= len(s.Proxies) || strings.TrimSpace(s.Proxies[s.ProxySel].Addr) == "" {
			return nil, errors.New("Режим «Только выбранный прокси»: выберите прокси кружком и укажите его адрес:порт (вкладка «Прокси»).")
		}
		p := s.Proxies[s.ProxySel]
		p.Type = normType(p.Type)
		p.Addr = strings.TrimSpace(p.Addr)
		if !validAddr(p.Addr) {
			return nil, fmt.Errorf("неверный адрес прокси %q: нужен вид хост:порт", p.Addr)
		}
		return []Route{{P: &p}}, nil
	default:
		return append([]Route{{}}, list...), nil
	}
}

// checkRoutes: "напрямую" и все заполненные прокси; rowIdx - номер строки прокси (-1 для прямого).
func checkRoutes(s Settings) (routes []Route, rowIdx []int) {
	routes = append(routes, Route{})
	rowIdx = append(rowIdx, -1)
	for i := range s.Proxies {
		p := s.Proxies[i]
		p.Type = normType(p.Type)
		p.Addr = strings.TrimSpace(p.Addr)
		if p.Addr == "" {
			continue
		}
		routes = append(routes, Route{P: &p})
		rowIdx = append(rowIdx, i)
	}
	return
}
