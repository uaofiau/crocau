package main

import (
	"context"
	"os"
	"path/filepath"
	"time"
)

func waitFor(d time.Duration, f func() bool) bool {
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		if f() {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return f()
}

func chatTestNode(name string, tcp, disc int) (*ChatNode, string) {
	dir, _ := os.MkdirTemp("", "crocau-chat-test")
	n := NewChatNode(dir, randHex(8), name)
	n.tcpPort, n.discPort = tcp, disc
	n.allowLoopback, n.noAutoScan = true, true
	return n, dir
}

func lastTexts(r *ChatRoom) []string {
	var l []string
	for _, m := range r.Messages() {
		if m.Kind == "msg" {
			l = append(l, m.Name+": "+m.Text)
		}
	}
	return l
}

// chatSelfTest проверяет движок локального чата: два-три узла на одном компьютере.
func chatSelfTest() int {
	fails := 0
	check := func(ok bool, name, detail string) {
		if ok {
			testLogf("%s: OK", name)
		} else {
			fails++
			testLogf("%s: FAIL %s", name, detail)
		}
	}
	a, da := chatTestNode("Аня", 39014, 39015)
	b, db := chatTestNode("Боря", 39016, 39017)
	c, dc := chatTestNode("Витя", 39018, 39019)
	defer os.RemoveAll(da)
	defer os.RemoveAll(db)
	defer os.RemoveAll(dc)
	if err := a.Start(); err != nil {
		testLogf("CHAT start A: %v", err)
		return 1
	}
	defer a.Stop()
	ra, _ := a.AddRoom("Общая", chatCommonDefaultPw)
	// сообщения, написанные до того, как Б появился в сети
	_ = a.SendText(ra, "первое")
	_ = a.SendText(ra, "второе")
	// Б с другой комнатой тоже в сети, но по паролю общей комнаты у него есть комната; В - другой пароль
	if err := b.Start(); err != nil {
		testLogf("CHAT start B: %v", err)
		return 1
	}
	defer b.Stop()
	rb, _ := b.AddRoom("Общая", chatCommonDefaultPw)
	if err := c.Start(); err != nil {
		testLogf("CHAT start C: %v", err)
		return 1
	}
	defer c.Stop()
	rc, _ := c.AddRoom("Чужая", "другой пароль")
	// поиск по UDP: Б ищет А (адрес для поиска - порт поиска узла А на loopback)
	b.scanTargets = []string{"127.0.0.1:39015"}
	b.Scan(1200 * time.Millisecond)
	check(waitFor(8*time.Second, func() bool { return a.PeerCount() == 1 && b.PeerCount() == 1 }), "CHAT DISCOVERY+CONNECT (UDP search, TCP link, one link per pair)",
		"peers "+itoa(a.PeerCount())+"/"+itoa(b.PeerCount()))
	check(waitFor(5*time.Second, func() bool { return len(lastTexts(rb)) == 2 }), "CHAT HISTORY SYNC on connect (messages written before)", "")
	// адрес вручную + рассылка по цепочке: В знает только Б, но общая комната у А и Б
	_ = c.AddPeer("127.0.0.1:39016")
	check(waitFor(8*time.Second, func() bool { return c.PeerCount() >= 1 && b.PeerCount() >= 2 }), "CHAT MANUAL ADDRESS + peer address gossip", "")
	check(waitFor(10*time.Second, func() bool { return a.PeerCount() == 2 && c.PeerCount() == 2 }), "CHAT MESH via gossip (C finds A through B)", "a="+itoa(a.PeerCount())+" c="+itoa(c.PeerCount()))
	_ = b.SendText(rb, "привет от Бори")
	check(waitFor(5*time.Second, func() bool { return len(lastTexts(ra)) == 3 }), "CHAT LIVE MESSAGE", "")
	check(len(rc.Messages()) == 0, "CHAT OTHER PASSWORD ROOM sees nothing", "")
	// переименование видно в старых сообщениях
	b.Rename("Борис")
	check(waitFor(5*time.Second, func() bool {
		for _, m := range ra.Messages() {
			if m.Text == "привет от Бори" && m.Name == "Борис" {
				return true
			}
		}
		return false
	}), "CHAT RENAME (same ID, old messages show new name)", "")
	// файл
	src := filepath.Join(da, "док.txt")
	_ = os.WriteFile(src, []byte("содержимое файла"), 0o644)
	_ = a.SendFile(ra, src)
	var fm *ChatFile
	waitFor(5*time.Second, func() bool {
		for _, m := range rb.Messages() {
			if m.Kind == "file" {
				fm = m.File
			}
		}
		return fm != nil
	})
	if fm == nil {
		check(false, "CHAT FILE", "offer not received")
	} else {
		dst := filepath.Join(db, "dl")
		p, err := b.Download(context.Background(), *fm, dst, nil)
		got, _ := os.ReadFile(p)
		check(err == nil && string(got) == "содержимое файла" && filepath.Base(p) == "док.txt", "CHAT FILE (offer in chat, direct download)", "")
		fm2 := *fm
		fm2.Tok = "unknown"
		_, err = b.Download(context.Background(), fm2, dst, nil)
		check(err != nil, "CHAT FILE unknown token refused", "")
	}
	// история сохраняется на диске и читается после перезапуска
	b.Stop()
	b2 := NewChatNode(db, b.UID, "Борис")
	b2.tcpPort, b2.discPort, b2.allowLoopback, b2.noAutoScan = 39016, 39017, true, true
	r2, _ := newChatRoom("Общая", chatCommonDefaultPw, b2.histDir())
	check(len(lastTexts(r2)) >= 3 && len(r2.Messages()) >= 4, "CHAT HISTORY kept on disk (encrypted) after restart", itoa(len(r2.Messages())))
	raw, _ := os.ReadFile(r2.path)
	check(len(raw) > 0 && !containsStr(string(raw), "привет от Бори"), "CHAT HISTORY file has no plaintext", "")
	return fails
}

func containsStr(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
