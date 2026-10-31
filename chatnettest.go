package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Проверка интернет-чата на поддельном сервере Nostr (в памяти): запись, чтение истории, дозаливка на другие
// серверы, подделка автора, шифрование файлов, работа через прокси из настроек.

type mockRelay struct {
	ln     net.Listener
	mu     sync.Mutex
	events []nostrEvent
	subs   map[*mockConn]map[string]map[string]interface{}
	conns  int32
}

type mockConn struct {
	c  net.Conn
	mu sync.Mutex
}

func (m *mockConn) send(v interface{}) {
	b, _ := json.Marshal(v)
	hdr := []byte{0x81}
	switch {
	case len(b) < 126:
		hdr = append(hdr, byte(len(b)))
	case len(b) < 65536:
		hdr = append(hdr, 126, byte(len(b)>>8), byte(len(b)))
	default:
		hdr = append(hdr, 127, 0, 0, 0, 0, byte(len(b)>>24), byte(len(b)>>16), byte(len(b)>>8), byte(len(b)))
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	_, _ = m.c.Write(append(hdr, b...))
}

func startMockRelay() (*mockRelay, error) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	r := &mockRelay{ln: ln, subs: map[*mockConn]map[string]map[string]interface{}{}}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go r.serve(c)
		}
	}()
	return r, nil
}

func (r *mockRelay) URL() string { return "ws://" + r.ln.Addr().String() }
func (r *mockRelay) Close()      { _ = r.ln.Close() }

func (r *mockRelay) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.events)
}

func (r *mockRelay) match(ev nostrEvent, f map[string]interface{}) bool {
	if ks, ok := f["kinds"].([]interface{}); ok {
		found := false
		for _, k := range ks {
			if int(k.(float64)) == ev.Kind {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	if ps, ok := f["#p"].([]interface{}); ok {
		found := false
		for _, t := range ev.Tags {
			if len(t) >= 2 && t[0] == "p" {
				for _, p := range ps {
					if p.(string) == t[1] {
						found = true
					}
				}
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// Inject кладёт событие на сервер напрямую (без проверок) - для проверки подделок.
func (r *mockRelay) Inject(ev nostrEvent) {
	r.mu.Lock()
	r.events = append(r.events, ev)
	conns := map[*mockConn]map[string]map[string]interface{}{}
	for c, s := range r.subs {
		conns[c] = s
	}
	r.mu.Unlock()
	for c, s := range conns {
		for id, f := range s {
			if r.match(ev, f) {
				c.send([]interface{}{"EVENT", id, ev})
			}
		}
	}
}

func (r *mockRelay) serve(c net.Conn) {
	defer c.Close()
	atomic.AddInt32(&r.conns, 1)
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	sum := sha1.Sum([]byte(req.Header.Get("Sec-WebSocket-Key") + wsGUID))
	_, _ = c.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " +
		base64.StdEncoding.EncodeToString(sum[:]) + "\r\n\r\n"))
	mc := &mockConn{c: c}
	defer func() {
		r.mu.Lock()
		delete(r.subs, mc)
		r.mu.Unlock()
	}()
	for {
		b0, err := br.ReadByte()
		if err != nil {
			return
		}
		b1, _ := br.ReadByte()
		n := int(b1 & 0x7F)
		if n == 126 {
			var l [2]byte
			_, _ = io.ReadFull(br, l[:])
			n = int(binary.BigEndian.Uint16(l[:]))
		} else if n == 127 {
			var l [8]byte
			_, _ = io.ReadFull(br, l[:])
			n = int(binary.BigEndian.Uint64(l[:]))
		}
		var mask [4]byte
		if b1&0x80 != 0 {
			_, _ = io.ReadFull(br, mask[:])
		}
		pl := make([]byte, n)
		if _, err := io.ReadFull(br, pl); err != nil {
			return
		}
		for i := range pl {
			pl[i] ^= mask[i%4]
		}
		switch b0 & 0x0F {
		case 8:
			return
		case 9:
			mc.mu.Lock()
			_, _ = c.Write([]byte{0x8A, 0})
			mc.mu.Unlock()
			continue
		case 1:
		default:
			continue
		}
		var arr []json.RawMessage
		if json.Unmarshal(pl, &arr) != nil || len(arr) == 0 {
			continue
		}
		var typ string
		_ = json.Unmarshal(arr[0], &typ)
		switch typ {
		case "EVENT":
			var ev nostrEvent
			if len(arr) < 2 || json.Unmarshal(arr[1], &ev) != nil {
				continue
			}
			if !nostrVerify(ev) {
				mc.send([]interface{}{"OK", ev.ID, false, "invalid: bad signature"})
				continue
			}
			r.mu.Lock()
			dup := false
			for _, e := range r.events {
				if e.ID == ev.ID {
					dup = true
				}
			}
			r.mu.Unlock()
			if dup {
				mc.send([]interface{}{"OK", ev.ID, true, "duplicate: have it"})
				continue
			}
			r.Inject(ev)
			mc.send([]interface{}{"OK", ev.ID, true, ""})
		case "REQ":
			var id string
			var f map[string]interface{}
			if len(arr) < 3 || json.Unmarshal(arr[1], &id) != nil || json.Unmarshal(arr[2], &f) != nil {
				continue
			}
			r.mu.Lock()
			var hits []nostrEvent
			for _, e := range r.events {
				if r.match(e, f) {
					hits = append(hits, e)
				}
			}
			if r.subs[mc] == nil {
				r.subs[mc] = map[string]map[string]interface{}{}
			}
			r.subs[mc][id] = f
			r.mu.Unlock()
			sort.Slice(hits, func(i, j int) bool { return hits[i].CreatedAt < hits[j].CreatedAt })
			for _, e := range hits {
				mc.send([]interface{}{"EVENT", id, e})
			}
			mc.send([]interface{}{"EOSE", id})
		case "CLOSE":
			var id string
			if len(arr) > 1 && json.Unmarshal(arr[1], &id) == nil {
				r.mu.Lock()
				delete(r.subs[mc], id)
				r.mu.Unlock()
			}
		}
	}
}

func netTestNode(name string, relays []string, get func() Settings) (*NetChat, string) {
	dir, _ := os.MkdirTemp("", "crocau-net-test")
	n, _ := NewNetChat(dir, newNetKey(), name, get)
	n.relays = relays
	return n, dir
}

func chatNetSelfTest() int {
	fails := 0
	check := func(ok bool, name, detail string) {
		if ok {
			testLogf("%s: OK", name)
		} else {
			fails++
			testLogf("%s: FAIL %s", name, detail)
		}
	}
	direct := func() Settings { return Settings{ProxyMode: modeDirect} }
	r1, err1 := startMockRelay()
	r2, err2 := startMockRelay()
	if err1 != nil || err2 != nil {
		testLogf("NET CHAT: mock relay: %v %v", err1, err2)
		return 1
	}
	defer r1.Close()
	defer r2.Close()
	a, da := netTestNode("Аня", []string{r1.URL()}, direct)
	defer os.RemoveAll(da)
	_ = a.Start()
	defer a.Stop()
	pw := "общий пароль интернет-комнаты"
	ra, _ := a.AddRoom("Комната", pw)
	check(waitFor(5*time.Second, func() bool { return a.PeerCount() == 1 }), "NET CHAT connect to relay", "")
	_ = a.SendText(ra, "первое из интернета")
	_ = a.SendText(ra, "второе")
	check(waitFor(5*time.Second, func() bool { return r1.Count() >= 3 }), "NET CHAT messages stored on relay (encrypted events)", itoa(r1.Count()))
	// участник, пришедший позже, получает историю с серверов; серверов у него два
	b, db := netTestNode("Боря", []string{r1.URL(), r2.URL()}, direct)
	defer os.RemoveAll(db)
	_ = b.Start()
	defer b.Stop()
	rb, _ := b.AddRoom("Комната у Бори", pw)
	check(waitFor(8*time.Second, func() bool { return len(lastTexts(rb)) == 2 }), "NET CHAT history from relay for a late member", "")
	// дозаливка: второй сервер был пуст - Боря отправил ему то, что знает
	check(waitFor(8*time.Second, func() bool { return r2.Count() >= 3 }), "NET CHAT republish to a relay that lacks events", itoa(r2.Count()))
	// живая доставка
	_ = b.SendText(rb, "ответ Бори")
	check(waitFor(5*time.Second, func() bool { return len(lastTexts(ra)) == 3 }), "NET CHAT live message", "")
	// другая комната не видит
	c, dc := netTestNode("Витя", []string{r1.URL()}, direct)
	defer os.RemoveAll(dc)
	_ = c.Start()
	defer c.Stop()
	rc, _ := c.AddRoom("Чужая", "другой пароль")
	time.Sleep(700 * time.Millisecond)
	check(len(rc.Messages()) == 0, "NET CHAT other password room sees nothing", "")
	// подделка автора: событие подписано чужим ключом, но внутри указан UID Ани
	evil, _ := nostrNewKey()
	fr, _ := ra.seal(ChatMsg{UID: a.UserID(), Name: "Аня", TS: nowMs(), Kind: "msg", Text: "подделка"})
	fake, _ := nostrSign(evil, 4, [][]string{{"p", roomTag(ra.key)}}, fr.C, time.Now().Unix())
	r1.Inject(fake)
	time.Sleep(700 * time.Millisecond)
	bad := false
	for _, t := range append(lastTexts(ra), lastTexts(rb)...) {
		if containsStr(t, "подделка") {
			bad = true
		}
	}
	check(!bad, "NET CHAT forged author rejected (signature key must match sender)", "")
	// переименование и очистка у всех
	b.Rename("Борис")
	check(waitFor(5*time.Second, func() bool {
		for _, m := range ra.Messages() {
			if m.Text == "ответ Бори" && m.Name == "Борис" {
				return true
			}
		}
		return false
	}), "NET CHAT rename propagates", "")
	a.ClearAll(ra)
	check(waitFor(5*time.Second, func() bool { return len(ra.Messages()) == 0 && len(rb.Messages()) == 0 }), "NET CHAT clear for all", "")
	// файл: шифрование блоками
	dir, _ := os.MkdirTemp("", "crocau-chatfile-test")
	defer os.RemoveAll(dir)
	key := mustRand(32)
	okFile := true
	for _, size := range []int{0, 1, chatFileChunk - 1, chatFileChunk, chatFileChunk + 1, 3*chatFileChunk + 17} {
		src := filepath.Join(dir, "src.bin")
		data := mustRand(size)
		_ = os.WriteFile(src, data, 0o644)
		enc, out := filepath.Join(dir, "enc"), filepath.Join(dir, "out")
		if chatEncryptFile(src, enc, key) != nil || chatDecryptFile(enc, out, key) != nil {
			okFile = false
			continue
		}
		got, _ := os.ReadFile(out)
		if string(got) != string(data) {
			okFile = false
		}
	}
	check(okFile, "NET CHAT FILE encrypt/decrypt (0 B .. 3 chunks)", "")
	src := filepath.Join(dir, "s2.bin")
	_ = os.WriteFile(src, mustRand(200000), 0o644)
	enc := filepath.Join(dir, "enc2")
	_ = chatEncryptFile(src, enc, key)
	eb, _ := os.ReadFile(enc)
	_ = os.WriteFile(enc+".cut", eb[:len(eb)-100], 0o644)
	eb[len(eb)/2] ^= 1
	_ = os.WriteFile(enc+".bad", eb, 0o644)
	check(chatDecryptFile(enc+".cut", filepath.Join(dir, "o1"), key) != nil && chatDecryptFile(enc+".bad", filepath.Join(dir, "o2"), key) != nil &&
		chatDecryptFile(enc, filepath.Join(dir, "o3"), mustRand(32)) != nil, "NET CHAT FILE truncated/modified/wrong key refused", "")
	// маршрут через прокси из настроек (вкладка «Прокси»): соединение с сервером идёт через SOCKS5
	pl, _ := net.Listen("tcp4", "127.0.0.1:0")
	defer pl.Close()
	var through int32
	go func() {
		for {
			c, err := pl.Accept()
			if err != nil {
				return
			}
			atomic.AddInt32(&through, 1)
			go serveSocks5(c, "", "", func(target string) (net.Conn, error) { return net.DialTimeout("tcp", target, 5*time.Second) })
		}
	}()
	viaProxy := func() Settings {
		return Settings{ProxyMode: modeProxy, ProxySel: 0, Proxies: []ProxyCfg{{Type: "socks5", Addr: pl.Addr().String()}}}
	}
	d, dd := netTestNode("Дина", []string{r1.URL()}, viaProxy)
	defer os.RemoveAll(dd)
	_ = d.Start()
	defer d.Stop()
	rd, _ := d.AddRoom("Через прокси", pw)
	_ = d.SendText(rd, "привет через прокси")
	check(waitFor(6*time.Second, func() bool { return atomic.LoadInt32(&through) > 0 && d.PeerCount() == 1 }), "NET CHAT uses proxy route from Proxy tab settings", itoa(int(atomic.LoadInt32(&through))))
	check(waitFor(5*time.Second, func() bool { return len(lastTexts(rb)) >= 1 }), "NET CHAT message sent via proxy reaches others", "")
	return fails
}
