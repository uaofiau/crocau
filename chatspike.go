package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Проверка транспортов будущего чата на реальных серверах (информационно, для CI): публичные relay Nostr и ntfy.sh.

var spikeRelays = []string{
	"wss://relay.damus.io", "wss://nos.lol", "wss://relay.nostr.band", "wss://relay.primal.net",
	"wss://nostr.mom", "wss://offchain.pub", "wss://relay.snort.social", "wss://nostr-pub.wellorder.net",
	"wss://relay.nostr.bg", "wss://nostr.oxtr.dev", "wss://relayable.org", "wss://nostr.fmt.wiz.biz",
	"wss://relay.current.fyi", "wss://purplepag.es", "wss://nostr.wine", "wss://relay.mostr.pub",
	"wss://nostr.einundzwanzig.space", "wss://relay.nostr.net", "wss://nostr.bitcoiner.social", "wss://relay.orangepill.dev",
}

func nip11Info(rawURL string) string {
	u := strings.Replace(strings.Replace(rawURL, "wss://", "https://", 1), "ws://", "http://", 1)
	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("Accept", "application/nostr+json")
	req.Header.Set("User-Agent", uploaderUA)
	c := httpClientVia(Route{}, 10*time.Second)
	resp, err := c.Do(req)
	if err != nil {
		return "nip11 err: " + trimErr(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var m map[string]json.RawMessage
	if json.Unmarshal(b, &m) != nil {
		return fmt.Sprintf("nip11: HTTP %d, не JSON", resp.StatusCode)
	}
	str := func(k string) string {
		var s string
		_ = json.Unmarshal(m[k], &s)
		return s
	}
	out := "software=" + str("software") + " " + str("version")
	if r, ok := m["limitation"]; ok {
		var l map[string]interface{}
		_ = json.Unmarshal(r, &l)
		for _, k := range []string{"max_message_length", "max_content_length", "auth_required", "payment_required", "restricted_writes", "min_pow_difficulty"} {
			if v, ok := l[k]; ok {
				out += fmt.Sprintf(" %s=%v", k, v)
			}
		}
	}
	if r, ok := m["retention"]; ok {
		s := string(r)
		if len(s) > 120 {
			s = s[:120]
		}
		out += " retention=" + s
	}
	return out
}

func trimErr(err error) string {
	s := err.Error()
	if len(s) > 90 {
		s = s[:90]
	}
	return s
}

// relayRoundTrip публикует событие и читает его обратно по фильтру; возвращает описание результата.
func relayRoundTrip(ctx context.Context, ws *wsConn, ev nostrEvent, filter map[string]interface{}, label string) string {
	b, _ := json.Marshal([]interface{}{"EVENT", ev})
	if err := ws.WriteText(b); err != nil {
		return label + ": send err " + trimErr(err)
	}
	status := ""
	end := time.Now().Add(9 * time.Second)
	for status == "" && time.Now().Before(end) {
		m, err := ws.ReadMessage(time.Until(end))
		if err != nil {
			return label + ": no OK (" + trimErr(err) + ")"
		}
		var arr []json.RawMessage
		if json.Unmarshal(m, &arr) != nil || len(arr) == 0 {
			continue
		}
		var typ string
		_ = json.Unmarshal(arr[0], &typ)
		switch typ {
		case "OK":
			var ok bool
			var msg string
			if len(arr) > 2 {
				_ = json.Unmarshal(arr[2], &ok)
			}
			if len(arr) > 3 {
				_ = json.Unmarshal(arr[3], &msg)
			}
			if !ok {
				return label + ": REJECT " + msg
			}
			status = "accepted"
		case "AUTH":
			status = "auth-challenge"
		case "NOTICE":
			var msg string
			if len(arr) > 1 {
				_ = json.Unmarshal(arr[1], &msg)
			}
			return label + ": NOTICE " + msg
		}
	}
	if status == "" {
		return label + ": no OK (timeout)"
	}
	if status == "auth-challenge" {
		return label + ": AUTH required"
	}
	rb, _ := json.Marshal([]interface{}{"REQ", "t" + ev.ID[:6], filter})
	if err := ws.WriteText(rb); err != nil {
		return label + ": accepted, REQ err"
	}
	end = time.Now().Add(9 * time.Second)
	found := false
	for time.Now().Before(end) {
		m, err := ws.ReadMessage(time.Until(end))
		if err != nil {
			break
		}
		var arr []json.RawMessage
		if json.Unmarshal(m, &arr) != nil || len(arr) == 0 {
			continue
		}
		var typ string
		_ = json.Unmarshal(arr[0], &typ)
		if typ == "EVENT" && len(arr) > 2 {
			var e nostrEvent
			if json.Unmarshal(arr[2], &e) == nil && e.ID == ev.ID {
				found = true
			}
		}
		if typ == "EOSE" || typ == "CLOSED" {
			if typ == "CLOSED" {
				var msg string
				if len(arr) > 2 {
					_ = json.Unmarshal(arr[2], &msg)
				}
				return label + ": accepted, REQ CLOSED " + msg
			}
			break
		}
		if found {
			break
		}
	}
	if found {
		return label + ": OK (записано и прочитано)"
	}
	return label + ": accepted, но не вернулось по фильтру"
}

func checkRelay(rawURL string) string {
	start := time.Now()
	var parts []string
	parts = append(parts, nip11Info(rawURL))
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	ws, err := wsDial(ctx, rawURL, Route{}, 12*time.Second)
	if err != nil {
		return fmt.Sprintf("RELAY %s: недоступен (%s) | %s", wsHost(rawURL), trimErr(err), parts[0])
	}
	defer ws.Close()
	parts = append(parts, fmt.Sprintf("connect=%dms", time.Since(start).Milliseconds()))
	author, _ := nostrNewKey()
	room, _ := nostrNewKey()
	roomPub := nostrPubHex(room)
	now := time.Now().Unix()
	// kind 4 (зашифрованное сообщение) на «комнатный» ключ, как в планируемом чате
	ev4, _ := nostrSign(author, 4, [][]string{{"p", roomPub}}, "dGVzdC1jaGF0LW1lc3NhZ2U=?iv=AAAAAAAAAAAAAAAAAAAAAA==", now)
	parts = append(parts, relayRoundTrip(ctx, ws, ev4, map[string]interface{}{"kinds": []int{4}, "#p": []string{roomPub}, "limit": 5}, "kind4"))
	// kind 30078 (данные приложения)
	ev30078, _ := nostrSign(author, 30078, [][]string{{"d", "crocau-" + roomPub[:8]}}, "dGVzdA==", now)
	parts = append(parts, relayRoundTrip(ctx, ws, ev30078, map[string]interface{}{"kinds": []int{30078}, "authors": []string{ev30078.PubKey}, "limit": 5}, "kind30078"))
	// большое сообщение (~48 КБ base64)
	big := strings.Repeat("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=", 1300)
	evBig, _ := nostrSign(author, 4, [][]string{{"p", roomPub}}, big, now+1)
	parts = append(parts, relayRoundTrip(ctx, ws, evBig, map[string]interface{}{"kinds": []int{4}, "ids": []string{evBig.ID}}, fmt.Sprintf("kind4-%dKB", len(big)/1024)))
	return fmt.Sprintf("RELAY %s: %s", wsHost(rawURL), strings.Join(parts, " | "))
}

func checkNtfy() string {
	topic := "crocau-spike-" + randHex(6)
	c := httpClientVia(Route{}, 30*time.Second)
	var out []string
	for _, n := range []int{300, 3500, 6000} {
		body := strings.Repeat("x", n)
		req, _ := http.NewRequest("POST", "https://ntfy.sh/"+topic, strings.NewReader(body))
		req.Header.Set("User-Agent", uploaderUA)
		resp, err := c.Do(req)
		if err != nil {
			out = append(out, fmt.Sprintf("publish %dB: ERR %s", n, trimErr(err)))
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		out = append(out, fmt.Sprintf("publish %dB: HTTP %d %s", n, resp.StatusCode, strings.ReplaceAll(truncate(string(b), 60), "\n", " ")))
	}
	req, _ := http.NewRequest("GET", "https://ntfy.sh/"+topic+"/json?poll=1&since=all", nil)
	req.Header.Set("User-Agent", uploaderUA)
	resp, err := c.Do(req)
	if err != nil {
		out = append(out, "read: ERR "+trimErr(err))
	} else {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		lines := strings.Count(strings.TrimSpace(string(b)), "\n") + 1
		out = append(out, fmt.Sprintf("read: HTTP %d, сообщений %d", resp.StatusCode, lines))
	}
	return "NTFY ntfy.sh: " + strings.Join(out, " | ")
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// realNetChat - сквозная проверка интернет-чата на настоящих серверах и обменниках.
func realNetChat() {
	testLogf("CA bundle embedded: %d bytes, pool=%v", len(embeddedCA), fallbackRoots() != nil)
	get := func() Settings { return Settings{ProxyMode: modeDirect} }
	mk := func(name string) (*NetChat, string) {
		d, _ := os.MkdirTemp("", "crocau-e2e")
		n, _ := NewNetChat(d, newNetKey(), name, get)
		_ = n.Start()
		return n, d
	}
	pw := "crocau-ci-" + randHex(6)
	a, da := mk("A")
	defer os.RemoveAll(da)
	defer a.Stop()
	ra, _ := a.AddRoom("e2e", pw)
	okConn := waitFor(25*time.Second, func() bool { return a.PeerCount() >= 2 })
	testLogf("E2E relays connected: %d of %d (waited for >=2: %v)", a.PeerCount(), a.RelayTotal(), okConn)
	for _, l := range a.PeerInfo() {
		testLogf("  %s", l)
	}
	_ = a.SendText(ra, "ci-hello")
	time.Sleep(4 * time.Second)
	b, db := mk("B")
	defer os.RemoveAll(db)
	defer b.Stop()
	t0 := time.Now()
	rb, _ := b.AddRoom("e2e", pw)
	got := waitFor(30*time.Second, func() bool { return len(lastTexts(rb)) >= 1 })
	testLogf("E2E late member got history from relays: %v (%d ms)", got, time.Since(t0).Milliseconds())
	_ = b.SendText(rb, "ci-reply")
	testLogf("E2E live reply reaches first member: %v", waitFor(20*time.Second, func() bool { return len(lastTexts(ra)) >= 2 }))
	// файл через настоящий обменник (шифруется)
	src := filepath.Join(da, "e2e.bin")
	data := mustRand(300000)
	_ = os.WriteFile(src, data, 0o644)
	t1 := time.Now()
	err := a.SendFile(ra, src, func(s string) {
		if !strings.HasPrefix(s, "Загрузка «") {
			testLogf("E2E file note (%ds): %s", int(time.Since(t1).Seconds()), s)
		}
	})
	if err != nil {
		testLogf("E2E file upload: FAIL %v", err)
		return
	}
	var fm *ChatFile
	waitFor(20*time.Second, func() bool {
		for _, m := range rb.Messages() {
			if m.Kind == "file" {
				fm = m.File
			}
		}
		return fm != nil
	})
	if fm == nil {
		testLogf("E2E file message not received")
		return
	}
	p, err := b.Download(context.Background(), *fm, filepath.Join(db, "dl"), nil)
	if err != nil {
		testLogf("E2E file download: FAIL %v", err)
		return
	}
	back, _ := os.ReadFile(p)
	testLogf("E2E file via exchanger (encrypted) round trip: %v  link=%s", string(back) == string(data), fm.Link)
}

func chatSpike() int {
	realNetChat()
	var wg sync.WaitGroup
	res := make([]string, len(spikeRelays)+1)
	sem := make(chan struct{}, 10)
	for i, r := range spikeRelays {
		wg.Add(1)
		go func(i int, r string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			res[i] = checkRelay(r)
		}(i, r)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		res[len(spikeRelays)] = checkNtfy()
	}()
	wg.Wait()
	for _, l := range res {
		testLogf("%s", l)
	}
	testLogf("CHATTEST done")
	return 0
}
