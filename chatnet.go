package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Сеть локального чата: каждый запущенный чат слушает один TCP-порт, находит соседей по UDP (широковещательно
// и перебором адресов подсетей на всех интерфейсах) и соединяется с каждым найденным напрямую. Адреса соседей
// пересылаются друг другу, поэтому достаточно найти одного (например, в большой сети ZeroTier). Сообщения
// рассылаются дальше по цепочке, а при соединении собеседники обмениваются недостающей историей.

type chatWire struct {
	T      string   `json:"t"`
	ID     string   `json:"id,omitempty"`
	Port   int      `json:"port,omitempty"`
	Addrs  []string `json:"addrs,omitempty"`
	Gossip []string `json:"gossip,omitempty"`
	Rooms  []string `json:"rooms,omitempty"`
	R      string   `json:"r,omitempty"`
	IDs    []string `json:"ids,omitempty"`
	I      string   `json:"i,omitempty"`
	TS     int64    `json:"ts,omitempty"`
	C      string   `json:"c,omitempty"`
	Tok    string   `json:"tok,omitempty"`
	U      string   `json:"u,omitempty"`
	N      string   `json:"n,omitempty"`
	OK     bool     `json:"ok,omitempty"`
	Size   int64    `json:"size,omitempty"`
}

type chatCand struct {
	addr   string
	fails  int
	next   time.Time
	manual bool
	busy   bool
}

type chatConn struct {
	c      net.Conn
	out    bool
	id     string
	uid    string
	name   string
	remote string
	addrs  []string
	wmu    sync.Mutex
	rooms  map[string]bool
	synced map[string]bool
}

func (cc *chatConn) send(w chatWire) error {
	b, _ := json.Marshal(w)
	cc.wmu.Lock()
	defer cc.wmu.Unlock()
	_ = cc.c.SetWriteDeadline(time.Now().Add(15 * time.Second))
	_, err := cc.c.Write(append(b, '\n'))
	return err
}

// ChatNode - один участник сети чата на этом компьютере (все комнаты одного вида: локальные).
type ChatNode struct {
	Dir string // папка данных чата
	UID string // постоянный идентификатор пользователя

	nodeID string
	mu     sync.Mutex
	name   string
	rooms  map[string]*ChatRoom
	peers  map[string]*chatConn
	cands  map[string]*chatCand
	files  map[string]string // токен -> путь к файлу
	stop   chan struct{}
	ln     net.Listener
	udp    *net.UDPConn
	wg     sync.WaitGroup

	tcpPort       int
	discPort      int
	scanTargets   []string // если задано - только эти адреса для поиска (тесты)
	allowLoopback bool
	noAutoScan    bool
	lastScan      []string

	OnUpdate func(roomID string) // пришли новые сообщения
	OnPeers  func()              // изменился набор соединений
}

func NewChatNode(dir, uid, name string) *ChatNode {
	return &ChatNode{Dir: dir, UID: uid, name: name, nodeID: randHex(6), rooms: map[string]*ChatRoom{},
		peers: map[string]*chatConn{}, cands: map[string]*chatCand{}, files: map[string]string{},
		tcpPort: chatTCPPort, discPort: chatDiscPort, stop: make(chan struct{})}
}

func (n *ChatNode) SetCallbacks(upd func(string), peers func()) { n.OnUpdate, n.OnPeers = upd, peers }

func (n *ChatNode) UserID() string { return n.UID }

func (n *ChatNode) Ready() bool { return n.ln != nil }

func (n *ChatNode) Name() string { n.mu.Lock(); defer n.mu.Unlock(); return n.name }

func (n *ChatNode) Port() int { return n.tcpPort }

func (n *ChatNode) histDir() string { return filepath.Join(n.Dir, "history") }

func (n *ChatNode) loadFiles() {
	b, err := os.ReadFile(filepath.Join(n.Dir, "files.json"))
	if err != nil {
		return
	}
	var m map[string]string
	if json.Unmarshal(b, &m) == nil {
		for k, v := range m {
			n.files[k] = v
		}
	}
}

func (n *ChatNode) saveFilesLocked() {
	b, _ := json.Marshal(n.files)
	_ = os.MkdirAll(n.Dir, 0o700)
	_ = os.WriteFile(filepath.Join(n.Dir, "files.json"), b, 0o600)
}

// Start открывает порт, запускает поиск соседей и соединения.
func (n *ChatNode) Start() error {
	_ = os.MkdirAll(n.histDir(), 0o700)
	n.loadFiles()
	ln, err := net.Listen("tcp4", fmt.Sprintf(":%d", n.tcpPort))
	if err != nil {
		return fmt.Errorf("порт чата %d занят: %v", n.tcpPort, err)
	}
	n.ln = ln
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go n.serveConn(c, false)
		}
	}()
	if u, err := net.ListenUDP("udp4", &net.UDPAddr{Port: n.discPort}); err == nil {
		n.udp = u
		n.wg.Add(1)
		go n.respond(u)
	}
	n.wg.Add(1)
	go n.dialLoop()
	if !n.noAutoScan {
		n.wg.Add(1)
		go n.scanLoop()
	}
	return nil
}

func (n *ChatNode) Stop() {
	select {
	case <-n.stop:
		return
	default:
	}
	close(n.stop)
	if n.ln != nil {
		_ = n.ln.Close()
	}
	if n.udp != nil {
		_ = n.udp.Close()
	}
	n.mu.Lock()
	for _, p := range n.peers {
		_ = p.c.Close()
	}
	n.mu.Unlock()
	n.wg.Wait()
}

// ---------- комнаты ----------

// AddRoom добавляет комнату (или возвращает уже существующую с тем же паролем).
func (n *ChatNode) AddRoom(label, pw string) (*ChatRoom, error) {
	r, err := newChatRoom(label, pw, n.histDir())
	if err != nil {
		return nil, err
	}
	n.mu.Lock()
	if old := n.rooms[r.ID]; old != nil {
		n.mu.Unlock()
		return old, nil
	}
	n.rooms[r.ID] = r
	n.mu.Unlock()
	n.announceRooms()
	n.post(r, ChatMsg{Kind: "hi"})
	return r, nil
}

func (n *ChatNode) RemoveRoom(id string) {
	n.mu.Lock()
	delete(n.rooms, id)
	n.mu.Unlock()
	n.announceRooms()
}

func (n *ChatNode) Room(id string) *ChatRoom {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.rooms[id]
}

func (n *ChatNode) roomIDs() []string {
	var ids []string
	for id := range n.rooms {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func (n *ChatNode) announceRooms() {
	n.mu.Lock()
	ids := n.roomIDs()
	conns := n.connList()
	n.mu.Unlock()
	for _, cc := range conns {
		_ = cc.send(chatWire{T: "rooms", Rooms: ids})
	}
}

func (n *ChatNode) connList() []*chatConn {
	var l []*chatConn
	for _, c := range n.peers {
		l = append(l, c)
	}
	return l
}

// ---------- отправка ----------

func (n *ChatNode) post(r *ChatRoom, m ChatMsg) {
	m.ID = newMsgID()
	m.UID = n.UID
	m.Name = n.Name()
	m.TS = nowMs()
	f, err := r.seal(m)
	if err != nil {
		return
	}
	if _, ok := r.add(f, true); !ok {
		return
	}
	n.broadcast(r.ID, f, nil)
	if m.Kind != "hi" && n.OnUpdate != nil {
		n.OnUpdate(r.ID)
	}
}

func (n *ChatNode) broadcast(roomID string, f chatFrame, except *chatConn) {
	n.mu.Lock()
	conns := n.connList()
	n.mu.Unlock()
	w := chatWire{T: "m", R: roomID, I: f.ID, TS: f.TS, C: f.C}
	for _, cc := range conns {
		if cc == except {
			continue
		}
		n.mu.Lock()
		has := cc.rooms[roomID]
		n.mu.Unlock()
		if has {
			go func(cc *chatConn) { _ = cc.send(w) }(cc)
		}
	}
}

func (n *ChatNode) SendText(r *ChatRoom, text string) error {
	text = strings.TrimSpace(text)
	if text == "" {
		return errors.New("пустое сообщение")
	}
	if len([]rune(text)) > 8000 {
		return errors.New("сообщение слишком длинное (до 8000 символов)")
	}
	n.post(r, ChatMsg{Kind: "msg", Text: text})
	return nil
}

// SendFile предлагает файл в комнате: сам файл остаётся у отправителя и скачивается по запросу участников.
func (n *ChatNode) SendFile(r *ChatRoom, path string, _ func(string)) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if st.IsDir() {
		return errors.New("папки пока нельзя отправлять в чат - добавьте файлы или заархивируйте папку")
	}
	tok := randHex(16)
	n.mu.Lock()
	n.files[tok] = path
	n.saveFilesLocked()
	n.mu.Unlock()
	n.post(r, ChatMsg{Kind: "file", File: &ChatFile{Name: filepath.Base(path), Size: st.Size(), Tok: tok, Addrs: n.ownAddrs()}})
	return nil
}

// Rename меняет имя; новое имя рассылается и обновляется у всех в старых сообщениях.
func (n *ChatNode) Rename(name string) {
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
	n.mu.Lock()
	conns := n.connList()
	n.mu.Unlock()
	for _, cc := range conns {
		_ = cc.send(chatWire{T: "who", U: n.UID, N: name})
	}
	for _, r := range rs {
		n.post(r, ChatMsg{Kind: "hi"})
		if n.OnUpdate != nil {
			n.OnUpdate(r.ID)
		}
	}
}

func (n *ChatNode) ownAddrs() []string {
	var out []string
	for _, ip := range localIPv4s() {
		out = append(out, net.JoinHostPort(ip, itoa(n.tcpPort)))
	}
	if n.allowLoopback {
		out = append(out, net.JoinHostPort("127.0.0.1", itoa(n.tcpPort)))
	}
	return out
}

func (n *ChatNode) isOwn(addr string) bool {
	h, p, err := net.SplitHostPort(addr)
	if err != nil || p != itoa(n.tcpPort) {
		return false
	}
	if h == "127.0.0.1" {
		return !n.allowLoopback
	}
	for _, ip := range localIPv4s() {
		if ip == h {
			return true
		}
	}
	return false
}

// ClearAll очищает комнату у всех участников, которые сейчас на связи или подключатся позже.
func (n *ChatNode) ClearAll(r *ChatRoom) { n.post(r, ChatMsg{Kind: "clear"}) }

// PeerInfo - строки «имя  адрес» подключённых устройств.
func (n *ChatNode) PeerInfo() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	var l []string
	for _, p := range n.peers {
		host, _, _ := net.SplitHostPort(p.remote)
		name := p.name
		if name == "" {
			name = "?"
		}
		l = append(l, name+"  "+host)
	}
	sort.Strings(l)
	return l
}

// ---------- соседи ----------

// PeerCount - число подключённых устройств.
func (n *ChatNode) PeerCount() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.peers)
}

// PeerAddrs - адреса подключённых устройств (для показа).
func (n *ChatNode) PeerAddrs() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	var l []string
	for _, p := range n.peers {
		l = append(l, p.remote)
	}
	sort.Strings(l)
	return l
}

// AddPeer добавляет адрес вручную (ip или ip:порт).
func (n *ChatNode) AddPeer(addr string) error {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return errors.New("пустой адрес")
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, itoa(n.tcpPort))
	}
	if n.isOwn(addr) {
		return errors.New("это адрес этого компьютера")
	}
	n.mu.Lock()
	n.cands[addr] = &chatCand{addr: addr, manual: true}
	n.mu.Unlock()
	return nil
}

func (n *ChatNode) addCand(addr string) {
	if addr == "" || n.isOwn(addr) {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if _, ok := n.cands[addr]; !ok {
		n.cands[addr] = &chatCand{addr: addr}
	}
}

func (n *ChatNode) connectedAddrLocked(addr string) bool {
	for _, p := range n.peers {
		if p.remote == addr {
			return true
		}
		for _, a := range p.addrs {
			if a == addr {
				return true
			}
		}
	}
	return false
}

func (n *ChatNode) dialLoop() {
	defer n.wg.Done()
	t := time.NewTicker(1500 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-n.stop:
			return
		case <-t.C:
		}
		now := time.Now()
		var due []*chatCand
		n.mu.Lock()
		for _, c := range n.cands {
			if !c.busy && now.After(c.next) && !n.connectedAddrLocked(c.addr) {
				c.busy = true
				due = append(due, c)
			}
		}
		n.mu.Unlock()
		for _, c := range due {
			go func(c *chatCand) {
				conn, err := net.DialTimeout("tcp4", c.addr, 4*time.Second)
				n.mu.Lock()
				c.busy = false
				if err != nil {
					c.fails++
					back := time.Duration(5<<uint(minInt(c.fails, 6))) * time.Second
					if c.manual && back > time.Minute {
						back = time.Minute
					}
					c.next = time.Now().Add(back)
					if !c.manual && c.fails >= 8 {
						delete(n.cands, c.addr)
					}
					n.mu.Unlock()
					return
				}
				c.fails = 0
				c.next = time.Now().Add(3 * time.Second)
				n.mu.Unlock()
				n.serveConn(conn, true)
			}(c)
		}
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (n *ChatNode) helloWire() chatWire {
	n.mu.Lock()
	defer n.mu.Unlock()
	w := chatWire{T: "hello", ID: n.nodeID, U: n.UID, N: n.name, Port: n.tcpPort, Addrs: n.ownAddrs(), Rooms: n.roomIDs()}
	seen := map[string]bool{}
	for _, p := range n.peers {
		for _, a := range p.addrs {
			if !seen[a] && len(w.Gossip) < 60 {
				seen[a] = true
				w.Gossip = append(w.Gossip, a)
			}
		}
	}
	return w
}

func readWire(br *bufio.Reader) (chatWire, error) {
	var w chatWire
	line, err := br.ReadBytes('\n')
	if err != nil {
		return w, err
	}
	if len(line) > 2<<20 {
		return w, errors.New("слишком длинная строка")
	}
	return w, json.Unmarshal(line, &w)
}

func (n *ChatNode) serveConn(c net.Conn, out bool) {
	defer c.Close()
	cc := &chatConn{c: c, out: out, remote: c.RemoteAddr().String(), rooms: map[string]bool{}, synced: map[string]bool{}}
	br := bufio.NewReaderSize(c, 64*1024)
	if err := cc.send(n.helloWire()); err != nil {
		return
	}
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	first, err := readWire(br)
	if err != nil {
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	if first.T == "get" {
		n.serveGet(c, first)
		return
	}
	if first.T != "hello" || first.ID == "" {
		return
	}
	if first.ID == n.nodeID {
		// соединились сами с собой через один из своих адресов
		n.mu.Lock()
		delete(n.cands, cc.remote)
		n.mu.Unlock()
		return
	}
	host, _, _ := net.SplitHostPort(cc.remote)
	if first.Port > 0 {
		cc.remote = net.JoinHostPort(host, itoa(first.Port))
	}
	cc.id = first.ID
	cc.uid, cc.name = first.U, first.N
	cc.addrs = first.Addrs
	n.mu.Lock()
	if old := n.peers[cc.id]; old != nil {
		if out != (n.nodeID < cc.id) { // оставляем соединение, которое открыл узел с меньшим номером
			n.mu.Unlock()
			return
		}
		_ = old.c.Close()
	}
	n.peers[cc.id] = cc
	for _, r := range first.Rooms {
		cc.rooms[r] = true
	}
	n.mu.Unlock()
	if n.OnPeers != nil {
		n.OnPeers()
	}
	for _, a := range append(append([]string(nil), first.Gossip...), first.Addrs...) {
		n.addCand(a)
	}
	n.addCand(cc.remote)
	n.syncWith(cc)
	defer func() {
		n.mu.Lock()
		if n.peers[cc.id] == cc {
			delete(n.peers, cc.id)
		}
		n.mu.Unlock()
		if n.OnPeers != nil {
			n.OnPeers()
		}
	}()
	for {
		w, err := readWire(br)
		if err != nil {
			return
		}
		switch w.T {
		case "who":
			n.mu.Lock()
			cc.uid, cc.name = w.U, w.N
			n.mu.Unlock()
			if n.OnPeers != nil {
				n.OnPeers()
			}
		case "rooms":
			n.mu.Lock()
			cc.rooms = map[string]bool{}
			for _, r := range w.Rooms {
				cc.rooms[r] = true
			}
			n.mu.Unlock()
			n.syncWith(cc)
		case "have":
			r := n.Room(w.R)
			if r == nil {
				continue
			}
			for _, f := range r.missingFor(w.IDs, 400) {
				_ = cc.send(chatWire{T: "m", R: r.ID, I: f.ID, TS: f.TS, C: f.C})
			}
		case "m":
			r := n.Room(w.R)
			if r == nil {
				continue
			}
			f := chatFrame{ID: w.I, TS: w.TS, C: w.C}
			m, isNew := r.add(f, true)
			if isNew {
				n.broadcast(r.ID, f, cc)
				if m.Kind != "hi" && n.OnUpdate != nil {
					n.OnUpdate(r.ID)
				}
			}
		}
	}
}

// syncWith просит у собеседника то, чего нет у нас, по каждой общей комнате (один раз на соединение).
func (n *ChatNode) syncWith(cc *chatConn) {
	n.mu.Lock()
	var todo []*ChatRoom
	for id, r := range n.rooms {
		if cc.rooms[id] && !cc.synced[id] {
			cc.synced[id] = true
			todo = append(todo, r)
		}
	}
	n.mu.Unlock()
	for _, r := range todo {
		_ = cc.send(chatWire{T: "have", R: r.ID, IDs: r.recentIDs(400)})
	}
}

// ---------- поиск по UDP ----------

const chatDiscQuery, chatDiscReply = "CROCAUCHAT1?", "CROCAUCHAT1!"

func (n *ChatNode) respond(u *net.UDPConn) {
	defer n.wg.Done()
	buf := make([]byte, 512)
	reply, _ := json.Marshal(chatWire{ID: n.nodeID, Port: n.tcpPort})
	for {
		k, addr, err := u.ReadFromUDP(buf)
		if err != nil {
			return
		}
		msg := string(buf[:k])
		if strings.HasPrefix(msg, chatDiscQuery) && strings.TrimSpace(msg[len(chatDiscQuery):]) != n.nodeID {
			_, _ = u.WriteToUDP(append([]byte(chatDiscReply), reply...), addr)
		}
	}
}

func (n *ChatNode) scanLoop() {
	defer n.wg.Done()
	n.Scan(1500 * time.Millisecond)
	t := time.NewTicker(40 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-n.stop:
			return
		case <-t.C:
			n.Scan(1500 * time.Millisecond)
		}
	}
}

// Scan ищет соседей (широковещательно и перебором адресов подсетей), найденные адреса добавляет в список для
// соединения. Возвращает описание: интерфейсы и число найденных.
func (n *ChatNode) Scan(wait time.Duration) []string {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return []string{"поиск: " + err.Error()}
	}
	defer conn.Close()
	var lines, targets []string
	if n.scanTargets != nil {
		targets = n.scanTargets
	} else {
		plan := planScanPort(n.discPort)
		targets, lines = plan.Targets, plan.Lines
	}
	q := []byte(chatDiscQuery + n.nodeID)
	found := 0
	buf := make([]byte, 1024)
	for round := 0; round < 2; round++ {
		for _, t := range targets {
			if a, err := net.ResolveUDPAddr("udp4", t); err == nil {
				_, _ = conn.WriteToUDP(q, a)
			}
		}
		_ = conn.SetReadDeadline(time.Now().Add(wait / 2))
		for {
			k, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				break
			}
			if !strings.HasPrefix(string(buf[:k]), chatDiscReply) {
				continue
			}
			var w chatWire
			if json.Unmarshal(buf[len(chatDiscReply):k], &w) != nil || w.ID == n.nodeID || w.Port <= 0 {
				continue
			}
			a := net.JoinHostPort(addr.IP.String(), itoa(w.Port))
			n.mu.Lock()
			_, known := n.cands[a]
			n.mu.Unlock()
			if !known && !n.isOwn(a) {
				found++
			}
			n.addCand(a)
		}
	}
	lines = append(lines, fmt.Sprintf("новых устройств найдено: %d, подключено: %d", found, n.PeerCount()))
	n.mu.Lock()
	n.lastScan = lines
	n.mu.Unlock()
	return lines
}

// ---------- файлы ----------

func (n *ChatNode) serveGet(c net.Conn, w chatWire) {
	n.mu.Lock()
	path := n.files[w.Tok]
	n.mu.Unlock()
	cc := &chatConn{c: c}
	f, err := os.Open(path)
	if path == "" || err != nil {
		_ = cc.send(chatWire{T: "file", OK: false})
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		_ = cc.send(chatWire{T: "file", OK: false})
		return
	}
	if cc.send(chatWire{T: "file", OK: true, Size: st.Size()}) != nil {
		return
	}
	_ = c.SetWriteDeadline(time.Time{})
	_, _ = io.Copy(c, f)
}

func safeFileName(s string) string {
	s = filepath.Base(strings.ReplaceAll(s, "\\", "/"))
	s = strings.Map(func(r rune) rune {
		if r < 32 || strings.ContainsRune(`<>:"/\|?*`, r) {
			return '_'
		}
		return r
	}, s)
	s = strings.Trim(s, " .")
	if s == "" {
		return "file"
	}
	return s
}

func uniquePath(dir, name string) string {
	p := filepath.Join(dir, name)
	if _, err := os.Stat(p); err != nil {
		return p
	}
	ext := filepath.Ext(name)
	base := strings.TrimSuffix(name, ext)
	for i := 1; ; i++ {
		p = filepath.Join(dir, fmt.Sprintf("%s (%d)%s", base, i, ext))
		if _, err := os.Stat(p); err != nil {
			return p
		}
	}
}

// Download скачивает файл напрямую с компьютера отправителя (перебирает его адреса). progress может быть nil.
func (n *ChatNode) Download(ctx context.Context, f ChatFile, destDir string, progress func(done, total int64)) (string, error) {
	if len(f.Addrs) == 0 {
		return "", errors.New("у отправителя нет адресов")
	}
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return "", err
	}
	var lastErr error
	for _, a := range f.Addrs {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		default:
		}
		d := net.Dialer{Timeout: 3 * time.Second}
		c, err := d.DialContext(ctx, "tcp4", a)
		if err != nil {
			lastErr = err
			continue
		}
		path, err := func() (string, error) {
			defer c.Close()
			go func() { <-ctx.Done(); _ = c.Close() }()
			cc := &chatConn{c: c}
			if err := cc.send(chatWire{T: "get", Tok: f.Tok}); err != nil {
				return "", err
			}
			br := bufio.NewReaderSize(c, 64*1024)
			// сервер сначала присылает hello - пропускаем его
			var resp chatWire
			for i := 0; i < 3; i++ {
				_ = c.SetReadDeadline(time.Now().Add(15 * time.Second))
				resp, err = readWire(br)
				if err != nil {
					return "", err
				}
				if resp.T == "file" {
					break
				}
			}
			_ = c.SetReadDeadline(time.Time{})
			if resp.T != "file" || !resp.OK {
				return "", errors.New("отправитель больше не предлагает этот файл")
			}
			out := uniquePath(destDir, safeFileName(f.Name))
			part := out + ".part"
			fh, err := os.Create(part)
			if err != nil {
				return "", err
			}
			var done int64
			buf := make([]byte, 64*1024)
			for done < resp.Size {
				want := int64(len(buf))
				if resp.Size-done < want {
					want = resp.Size - done
				}
				k, err := br.Read(buf[:want])
				if k > 0 {
					if _, werr := fh.Write(buf[:k]); werr != nil {
						fh.Close()
						os.Remove(part)
						return "", werr
					}
					done += int64(k)
					if progress != nil {
						progress(done, resp.Size)
					}
				}
				if err != nil {
					if done == resp.Size {
						break
					}
					fh.Close()
					os.Remove(part)
					return "", err
				}
			}
			if err := fh.Close(); err != nil {
				return "", err
			}
			if err := os.Rename(part, out); err != nil {
				return "", err
			}
			return out, nil
		}()
		if err == nil {
			return path, nil
		}
		lastErr = err
	}
	return "", fmt.Errorf("не удалось скачать: %v", lastErr)
}
