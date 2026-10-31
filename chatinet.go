package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Интернет-чат: сообщения (зашифрованные ключом комнаты) публикуются как события Nostr на нескольких публичных
// серверах и читаются оттуда по "метке комнаты". Регистрация не нужна. Каждый участник, подключаясь, дозаливает
// на серверы известные ему события, которых там нет, - так история живёт дольше, чем хранит один сервер.
// Все соединения идут по маршрутам вкладки «Прокси». Файлы - через обменники (в зашифрованном виде).

// Серверы по умолчанию (проверены на запись и чтение без регистрации). Свой список: crocau-chat/relays.txt.
var defaultRelays = []string{
	"wss://nos.lol", "wss://relay.primal.net", "wss://nostr.mom", "wss://nostr.oxtr.dev", "wss://relay.snort.social",
}

type relayState struct {
	url    string
	status string
	ws     *wsConn
	seen   map[string]bool
	eose   bool
	sub    string
	pend   map[string]nostrEvent
}

// NetChat - участник интернет-чата на этом компьютере.
type NetChat struct {
	Dir string

	getSettings func() Settings
	priv        *nostrPriv
	pub         string
	relays      []string

	mu    sync.Mutex
	name  string
	rooms map[string]*ChatRoom
	tags  map[string]string // номер комнаты -> метка на серверах
	rs    map[string]*relayState
	stop  chan struct{}
	wg    sync.WaitGroup
	ready bool

	OnUpdate func(string)
	OnPeers  func()
}

func NewNetChat(dir string, privHex, name string, getSettings func() Settings) (*NetChat, error) {
	kb, err := hex.DecodeString(privHex)
	if err != nil || len(kb) != 32 {
		return nil, errors.New("неверный ключ чата")
	}
	priv := nostrKeyFromBytes(kb)
	n := &NetChat{Dir: dir, getSettings: getSettings, priv: priv, pub: nostrPubHex(priv), name: name,
		rooms: map[string]*ChatRoom{}, tags: map[string]string{}, rs: map[string]*relayState{}, stop: make(chan struct{})}
	n.relays = defaultRelays
	if b, err := os.ReadFile(filepath.Join(dir, "relays.txt")); err == nil {
		var l []string
		for _, ln := range strings.Split(string(b), "\n") {
			ln = strings.TrimSpace(ln)
			if strings.HasPrefix(ln, "wss://") || strings.HasPrefix(ln, "ws://") {
				l = append(l, ln)
			}
		}
		if len(l) > 0 {
			n.relays = l
		}
	}
	return n, nil
}

// newNetKey создаёт ключ подписи (hex).
func newNetKey() string {
	k, _ := nostrNewKey()
	return hex.EncodeToString(nostrKeyBytes(k))
}

func (n *NetChat) SetCallbacks(upd func(string), peers func()) { n.OnUpdate, n.OnPeers = upd, peers }
func (n *NetChat) UserID() string                              { return n.pub }
func (n *NetChat) Name() string                                { n.mu.Lock(); defer n.mu.Unlock(); return n.name }
func (n *NetChat) Ready() bool                                 { n.mu.Lock(); defer n.mu.Unlock(); return n.ready }
func (n *NetChat) histDir() string                             { return filepath.Join(n.Dir, "history-net") }

func (n *NetChat) Start() error {
	_ = os.MkdirAll(n.histDir(), 0o700)
	n.mu.Lock()
	n.ready = true
	for _, u := range n.relays {
		n.rs[u] = &relayState{url: u, status: "подключение...", pend: map[string]nostrEvent{}}
	}
	n.mu.Unlock()
	for _, u := range n.relays {
		n.wg.Add(1)
		go n.relayLoop(u)
	}
	return nil
}

func (n *NetChat) Stop() {
	select {
	case <-n.stop:
		return
	default:
	}
	close(n.stop)
	n.mu.Lock()
	for _, r := range n.rs {
		if r.ws != nil {
			_ = r.ws.Close()
		}
	}
	n.mu.Unlock()
	n.wg.Wait()
}

// PeerCount - число серверов на связи; PeerInfo - состояние каждого сервера.
func (n *NetChat) PeerCount() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	c := 0
	for _, r := range n.rs {
		if r.ws != nil {
			c++
		}
	}
	return c
}

func (n *NetChat) PeerInfo() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	var l []string
	for _, r := range n.rs {
		l = append(l, r.url+"  -  "+r.status)
	}
	sort.Strings(l)
	return l
}

func (n *NetChat) RelayTotal() int { return len(n.relays) }

// defaultRelaysFor - список серверов узла (для показа числа).
func defaultRelaysFor(b ChatBackend) []string {
	if nc, ok := b.(*NetChat); ok {
		return nc.relays
	}
	return nil
}

func (n *NetChat) setStatus(u, s string) {
	n.mu.Lock()
	if r := n.rs[u]; r != nil {
		r.status = s
	}
	n.mu.Unlock()
	if n.OnPeers != nil {
		n.OnPeers()
	}
}

// ---------- комнаты ----------

func roomTag(key []byte) string {
	h := sha256.Sum256(append(append([]byte(nil), key...), []byte("|nostr-room-tag")...))
	return hex.EncodeToString(h[:])
}

func (r *ChatRoom) expectAuthor(id, pub string) {
	r.mu.Lock()
	if r.authors == nil {
		r.authors = map[string]string{}
	}
	r.authors[id] = pub
	r.mu.Unlock()
}

func (n *NetChat) AddRoom(label, pw string) (*ChatRoom, error) {
	r, err := newChatRoom(label, pw, n.histDir())
	if err != nil {
		return nil, err
	}
	r.enforceAuthor = true
	n.mu.Lock()
	if old := n.rooms[r.ID]; old != nil {
		n.mu.Unlock()
		return old, nil
	}
	n.rooms[r.ID] = r
	n.tags[r.ID] = roomTag(r.key)
	n.mu.Unlock()
	n.resubscribeAll()
	_ = n.post(r, ChatMsg{Kind: "hi"})
	return r, nil
}

func (n *NetChat) RemoveRoom(id string) {
	n.mu.Lock()
	delete(n.rooms, id)
	delete(n.tags, id)
	n.mu.Unlock()
	n.resubscribeAll()
}

func (n *NetChat) roomByTag(tag string) *ChatRoom {
	n.mu.Lock()
	defer n.mu.Unlock()
	for id, t := range n.tags {
		if t == tag {
			return n.rooms[id]
		}
	}
	return nil
}

// ---------- отправка ----------

func (n *NetChat) post(r *ChatRoom, m ChatMsg) error {
	m.UID = n.pub
	m.Name = n.Name()
	m.TS = nowMs()
	fr, err := r.seal(m)
	if err != nil {
		return err
	}
	n.mu.Lock()
	tag := n.tags[r.ID]
	n.mu.Unlock()
	ev, err := nostrSign(n.priv, 4, [][]string{{"p", tag}}, fr.C, time.Now().Unix())
	if err != nil {
		return err
	}
	f := chatFrame{ID: ev.ID, TS: ev.CreatedAt * 1000, C: ev.Content, A: ev.PubKey, S: ev.Sig}
	r.expectAuthor(f.ID, n.pub)
	if _, ok := r.add(f, true); !ok {
		return errors.New("не удалось сохранить сообщение")
	}
	n.publish(ev)
	if m.Kind != "hi" && n.OnUpdate != nil {
		n.OnUpdate(r.ID)
	}
	return nil
}

func (n *NetChat) SendText(r *ChatRoom, text string) error {
	text = strings.TrimSpace(text)
	if text == "" {
		return errors.New("пустое сообщение")
	}
	if len([]rune(text)) > 8000 {
		return errors.New("сообщение слишком длинное (до 8000 символов)")
	}
	return n.post(r, ChatMsg{Kind: "msg", Text: text})
}

func (n *NetChat) ClearAll(r *ChatRoom) { _ = n.post(r, ChatMsg{Kind: "clear"}) }

func (n *NetChat) Rename(name string) {
	name = strings.TrimSpace(name)
	if name == "" {
		return
	}
	n.mu.Lock()
	n.name = name
	var rs []*ChatRoom
	for _, r := range n.rooms {
		rs = append(rs, r)
	}
	n.mu.Unlock()
	for _, r := range rs {
		_ = n.post(r, ChatMsg{Kind: "hi"})
		if n.OnUpdate != nil {
			n.OnUpdate(r.ID)
		}
	}
}

func (n *NetChat) publish(ev nostrEvent) {
	n.mu.Lock()
	var conns []*relayState
	for _, rs := range n.rs {
		if len(rs.pend) < 300 {
			rs.pend[ev.ID] = ev
		}
		if rs.ws != nil {
			conns = append(conns, rs)
		}
	}
	n.mu.Unlock()
	b, _ := json.Marshal([]interface{}{"EVENT", ev})
	for _, rs := range conns {
		n.mu.Lock()
		ws := rs.ws
		n.mu.Unlock()
		if ws != nil {
			go func() { _ = ws.WriteText(b) }()
		}
	}
}

// ---------- соединения с серверами ----------

func (n *NetChat) relayLoop(u string) {
	defer n.wg.Done()
	backoff := 3 * time.Second
	for {
		select {
		case <-n.stop:
			return
		default:
		}
		routes, err := routesFor(n.getSettings())
		if err != nil {
			n.setStatus(u, "настройки прокси: "+trimErr(err))
			if n.sleep(20 * time.Second) {
				return
			}
			continue
		}
		var ws *wsConn
		var derr error
		for _, rt := range routes {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			ws, derr = wsDial(ctx, u, rt, 12*time.Second)
			cancel()
			if derr == nil {
				break
			}
		}
		if ws == nil {
			n.setStatus(u, "недоступен: "+trimErr(derr))
			if n.sleep(backoff) {
				return
			}
			if backoff < 90*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = 3 * time.Second
		n.mu.Lock()
		rs := n.rs[u]
		rs.ws, rs.seen, rs.eose = ws, map[string]bool{}, false
		n.mu.Unlock()
		n.setStatus(u, "на связи")
		n.subscribe(rs)
		err = n.session(rs)
		n.mu.Lock()
		rs.ws = nil
		n.mu.Unlock()
		_ = ws.Close()
		select {
		case <-n.stop:
			return
		default:
		}
		st := "переподключение"
		if err != nil {
			st += ": " + trimErr(err)
		}
		n.setStatus(u, st)
		if n.sleep(3 * time.Second) {
			return
		}
	}
}

func (n *NetChat) sleep(d time.Duration) bool {
	select {
	case <-n.stop:
		return true
	case <-time.After(d):
		return false
	}
}

// subscribe запрашивает события всех комнат и отправляет накопленные неотправленные.
func (n *NetChat) subscribe(rs *relayState) {
	n.mu.Lock()
	ws := rs.ws
	old := rs.sub
	var tags []string
	for _, t := range n.tags {
		tags = append(tags, t)
	}
	sub := "c" + randHex(4)
	rs.sub, rs.eose = sub, false
	var pend []nostrEvent
	for _, ev := range rs.pend {
		pend = append(pend, ev)
	}
	n.mu.Unlock()
	if ws == nil {
		return
	}
	if old != "" {
		cb, _ := json.Marshal([]interface{}{"CLOSE", old})
		_ = ws.WriteText(cb)
	}
	if len(tags) > 0 {
		rb, _ := json.Marshal([]interface{}{"REQ", sub, map[string]interface{}{"kinds": []int{4}, "#p": tags, "limit": 500}})
		_ = ws.WriteText(rb)
	}
	for _, ev := range pend {
		b, _ := json.Marshal([]interface{}{"EVENT", ev})
		_ = ws.WriteText(b)
	}
}

func (n *NetChat) resubscribeAll() {
	n.mu.Lock()
	var list []*relayState
	for _, rs := range n.rs {
		if rs.ws != nil {
			list = append(list, rs)
		}
	}
	n.mu.Unlock()
	for _, rs := range list {
		n.subscribe(rs)
	}
}

func (n *NetChat) session(rs *relayState) error {
	n.mu.Lock()
	ws := rs.ws
	n.mu.Unlock()
	done := make(chan struct{})
	defer close(done)
	go func() { // периодический ping, чтобы соединение не считалось мёртвым
		t := time.NewTicker(35 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-n.stop:
				return
			case <-t.C:
				_ = ws.writeFrame(0x9, nil)
			}
		}
	}()
	for {
		m, err := ws.ReadMessage(100 * time.Second)
		if err != nil {
			return err
		}
		var arr []json.RawMessage
		if json.Unmarshal(m, &arr) != nil || len(arr) == 0 {
			continue
		}
		var typ string
		_ = json.Unmarshal(arr[0], &typ)
		switch typ {
		case "EVENT":
			if len(arr) < 3 {
				continue
			}
			var ev nostrEvent
			if json.Unmarshal(arr[2], &ev) == nil {
				n.handleEvent(rs, ev)
			}
		case "EOSE":
			n.mu.Lock()
			first := !rs.eose
			rs.eose = true
			n.mu.Unlock()
			if first {
				go n.republish(rs)
			}
		case "OK":
			var id string
			var ok bool
			var msg string
			if len(arr) > 1 {
				_ = json.Unmarshal(arr[1], &id)
			}
			if len(arr) > 2 {
				_ = json.Unmarshal(arr[2], &ok)
			}
			if len(arr) > 3 {
				_ = json.Unmarshal(arr[3], &msg)
			}
			n.mu.Lock()
			if ok || strings.HasPrefix(msg, "duplicate") || strings.Contains(msg, "already") || strings.HasPrefix(msg, "blocked") || strings.HasPrefix(msg, "invalid") {
				delete(rs.pend, id)
			}
			n.mu.Unlock()
		case "CLOSED":
			var msg string
			if len(arr) > 2 {
				_ = json.Unmarshal(arr[2], &msg)
			}
			n.setStatus(rs.url, "сервер закрыл подписку: "+trimErr(errors.New(msg)))
		}
	}
}

func (n *NetChat) handleEvent(rs *relayState, ev nostrEvent) {
	if ev.Kind != 4 || len(ev.Content) > 300000 {
		return
	}
	tag := ""
	for _, t := range ev.Tags {
		if len(t) >= 2 && t[0] == "p" {
			tag = t[1]
			break
		}
	}
	r := n.roomByTag(tag)
	if r == nil || !nostrVerify(ev) {
		return
	}
	n.mu.Lock()
	rs.seen[ev.ID] = true
	n.mu.Unlock()
	r.expectAuthor(ev.ID, ev.PubKey)
	m, isNew := r.add(chatFrame{ID: ev.ID, TS: ev.CreatedAt * 1000, C: ev.Content, A: ev.PubKey, S: ev.Sig}, true)
	if isNew && m.Kind != "hi" && n.OnUpdate != nil {
		n.OnUpdate(r.ID)
	}
	if isNew {
		// через 3 секунды дослать событие тем серверам, которые его так и не прислали
		time.AfterFunc(3*time.Second, func() { n.forward(ev) })
	}
}

func (n *NetChat) forward(ev nostrEvent) {
	select {
	case <-n.stop:
		return
	default:
	}
	b, _ := json.Marshal([]interface{}{"EVENT", ev})
	n.mu.Lock()
	var targets []*wsConn
	for _, rs := range n.rs {
		if rs.ws != nil && rs.eose && !rs.seen[ev.ID] {
			rs.seen[ev.ID] = true
			targets = append(targets, rs.ws)
		}
	}
	n.mu.Unlock()
	for _, ws := range targets {
		_ = ws.WriteText(b)
	}
}

// republish отправляет на сервер известные нам события комнат, которых он не прислал (до 150 самых новых).
func (n *NetChat) republish(rs *relayState) {
	n.mu.Lock()
	ws := rs.ws
	type item struct {
		f   chatFrame
		tag string
	}
	var items []item
	for id, r := range n.rooms {
		for _, f := range r.allFrames() {
			if f.A != "" && f.S != "" && !rs.seen[f.ID] {
				items = append(items, item{f, n.tags[id]})
			}
		}
	}
	n.mu.Unlock()
	if ws == nil {
		return
	}
	sort.Slice(items, func(i, j int) bool { return items[i].f.TS > items[j].f.TS })
	if len(items) > 150 {
		items = items[:150]
	}
	for _, it := range items {
		ev := nostrEvent{ID: it.f.ID, PubKey: it.f.A, CreatedAt: it.f.TS / 1000, Kind: 4, Tags: [][]string{{"p", it.tag}}, Content: it.f.C, Sig: it.f.S}
		b, _ := json.Marshal([]interface{}{"EVENT", ev})
		if ws.WriteText(b) != nil {
			return
		}
		select {
		case <-n.stop:
			return
		case <-time.After(40 * time.Millisecond):
		}
	}
}

// ---------- файлы через обменники ----------

func (n *NetChat) SendFile(r *ChatRoom, path string, note func(string)) error {
	if note == nil {
		note = func(string) {}
	}
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if st.IsDir() {
		return errors.New("папки пока нельзя отправлять в чат - добавьте файлы или заархивируйте папку")
	}
	routes, err := routesFor(n.getSettings())
	if err != nil {
		return err
	}
	key := make([]byte, 32)
	copy(key, mustRand(32))
	tmp, err := os.CreateTemp("", "crocau-chatfile-*.bin")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	tmp.Close()
	defer os.Remove(tmpPath)
	note("Шифрую «" + filepath.Base(path) + "»...")
	if err := chatEncryptFile(path, tmpPath, key); err != nil {
		return err
	}
	var link string
	var last error
	for _, rt := range routes {
		var info string
		link, info, last = uploadChain(context.Background(), rt, tmpPath, "crocau-"+randHex(5)+".bin", func(done, total int64) {
			note(fmt.Sprintf("Загрузка «%s»: %s из %s", filepath.Base(path), humanSize(done), humanSize(total)))
		}, func(s string) { note(s) })
		if last == nil {
			note("Файл загружен (" + info + ")")
			break
		}
	}
	if last != nil {
		return last
	}
	return n.post(r, ChatMsg{Kind: "file", File: &ChatFile{Name: filepath.Base(path), Size: st.Size(), Link: link, Key: hex.EncodeToString(key)}})
}

func (n *NetChat) Download(ctx context.Context, f ChatFile, destDir string, progress func(done, total int64)) (string, error) {
	if f.Link == "" || f.Key == "" {
		return "", errors.New("в сообщении нет ссылки на файл")
	}
	key, err := hex.DecodeString(f.Key)
	if err != nil || len(key) != 32 {
		return "", errors.New("неверный ключ файла")
	}
	routes, err := routesFor(n.getSettings())
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return "", err
	}
	tmpDir, err := os.MkdirTemp("", "crocau-chatdl")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmpDir)
	var got string
	var last error
	for _, rt := range routes {
		got, last = downloadLink(ctx, rt, f.Link, tmpDir, progress)
		if last == nil {
			break
		}
	}
	if last != nil {
		return "", fmt.Errorf("не удалось скачать (возможно, срок хранения файла на обменнике истёк): %v", last)
	}
	out := uniquePath(destDir, safeFileName(f.Name))
	if err := chatDecryptFile(got, out, key); err != nil {
		return "", err
	}
	return out, nil
}
