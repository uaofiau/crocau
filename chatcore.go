package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Порты локального чата. Переменные - чтобы тесты могли подставить свободные.
var (
	chatTCPPort  = 29014
	chatDiscPort = 29015
)

// Ядро чата: комната определяется паролем (из пароля получается ключ шифрования и "номер комнаты"),
// сообщения хранятся и передаются только в зашифрованном виде (AES-GCM).

func pbkdf2Gen(h func() hash.Hash, pw, salt []byte, iter, keyLen int) []byte {
	prf := hmac.New(h, pw)
	hl := prf.Size()
	n := (keyLen + hl - 1) / hl
	var dk []byte
	for b := 1; b <= n; b++ {
		prf.Reset()
		prf.Write(salt)
		prf.Write([]byte{byte(b >> 24), byte(b >> 16), byte(b >> 8), byte(b)})
		u := prf.Sum(nil)
		t := append([]byte(nil), u...)
		for i := 1; i < iter; i++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(u[:0])
			for j := range t {
				t[j] ^= u[j]
			}
		}
		dk = append(dk, t...)
	}
	return dk[:keyLen]
}

func chatKeyFor(pw string) []byte {
	return pbkdf2Gen(sha256.New, []byte(pw), []byte("crocau-chat-v1"), 20000, 32)
}

func chatRoomIDFor(key []byte) string {
	h := sha256.Sum256(append(append([]byte(nil), key...), []byte("|room-id")...))
	return hex.EncodeToString(h[:8])
}

// Общая комната: пароль по умолчанию известен всем копиям программы, поэтому она открыта для всех, кто её включил.
// Чтобы закрыть общую комнату от посторонних, достаточно задать свой пароль общей комнаты.
const chatCommonDefaultPw = "crocau-common"

// ChatFile - файл, предложенный в чате: скачивается напрямую с компьютера отправителя.
type ChatFile struct {
	Name  string   `json:"name"`
	Size  int64    `json:"size"`
	Tok   string   `json:"tok"`
	Addrs []string `json:"addrs,omitempty"`
}

// ChatMsg - сообщение чата (внутри шифрования).
type ChatMsg struct {
	ID   string    `json:"-"`
	UID  string    `json:"u"`
	Name string    `json:"n"`
	TS   int64     `json:"ts"` // миллисекунды Unix
	Kind string    `json:"k"`  // msg, file, hi (объявление имени, не показывается)
	Text string    `json:"x,omitempty"`
	File *ChatFile `json:"f,omitempty"`
}

// chatFrame - зашифрованное сообщение в том виде, как оно хранится и пересылается.
type chatFrame struct {
	ID string `json:"i"`
	TS int64  `json:"ts"`
	C  string `json:"c"`
}

// ChatRoom - комната: история и ключ.
type ChatRoom struct {
	Label string
	ID    string
	key   []byte
	aead  cipher.AEAD
	path  string // файл истории
	mu    sync.Mutex
	msgs  []ChatMsg
	blobs map[string]chatFrame
	names map[string]string
	nameT map[string]int64
	// clearedTS - всё, что старше этого времени, считается очищенным (очистка чата локально или у всех).
	clearedTS int64
}

const chatMaxHistory = 5000

func newChatRoom(label, pw, histDir string) (*ChatRoom, error) {
	key := chatKeyFor(pw)
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	r := &ChatRoom{Label: label, ID: chatRoomIDFor(key), key: key, aead: g,
		blobs: map[string]chatFrame{}, names: map[string]string{}, nameT: map[string]int64{}}
	if histDir != "" {
		r.path = filepath.Join(histDir, r.ID+".log")
		if b, err := os.ReadFile(r.clrPath()); err == nil {
			r.clearedTS, _ = strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
		}
		r.loadHistory()
	}
	return r, nil
}

func (r *ChatRoom) seal(m ChatMsg) (chatFrame, error) {
	plain, _ := json.Marshal(m)
	nonce := make([]byte, r.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return chatFrame{}, err
	}
	ct := r.aead.Seal(nonce, nonce, plain, []byte(r.ID))
	return chatFrame{ID: m.ID, TS: m.TS, C: base64.RawStdEncoding.EncodeToString(ct)}, nil
}

func (r *ChatRoom) open(f chatFrame) (ChatMsg, error) {
	var m ChatMsg
	ct, err := base64.RawStdEncoding.DecodeString(f.C)
	if err != nil || len(ct) < r.aead.NonceSize()+1 {
		return m, errors.New("bad frame")
	}
	ns := r.aead.NonceSize()
	plain, err := r.aead.Open(nil, ct[:ns], ct[ns:], []byte(r.ID))
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(plain, &m); err != nil {
		return m, err
	}
	m.ID = f.ID
	return m, nil
}

// add добавляет кадр (если он расшифровывается и ещё не известен). Возвращает сообщение и признак "новое".
func (r *ChatRoom) add(f chatFrame, persist bool) (ChatMsg, bool) {
	if f.ID == "" || len(f.ID) > 64 {
		return ChatMsg{}, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.blobs[f.ID]; ok {
		return ChatMsg{}, false
	}
	m, err := r.open(f)
	if err != nil {
		return ChatMsg{}, false
	}
	r.blobs[f.ID] = f
	if m.Kind == "clear" {
		if m.TS < r.clearedTS {
			return ChatMsg{}, false
		}
		if m.TS > r.clearedTS {
			r.clearedTS = m.TS
			r.dropOlderLocked(m.TS, f.ID)
			r.saveClrLocked()
		}
	} else if m.TS <= r.clearedTS {
		return ChatMsg{}, false
	}
	i := sort.Search(len(r.msgs), func(i int) bool { return r.msgs[i].TS > m.TS })
	r.msgs = append(r.msgs, ChatMsg{})
	copy(r.msgs[i+1:], r.msgs[i:])
	r.msgs[i] = m
	if m.UID != "" && m.Name != "" && m.TS >= r.nameT[m.UID] {
		r.names[m.UID], r.nameT[m.UID] = m.Name, m.TS
	}
	if persist && r.path != "" {
		if fh, err := os.OpenFile(r.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600); err == nil {
			b, _ := json.Marshal(f)
			_, _ = fh.Write(append(b, '\n'))
			_ = fh.Close()
		}
	}
	return m, true
}

func (r *ChatRoom) loadHistory() {
	b, err := os.ReadFile(r.path)
	if err != nil {
		return
	}
	lines := strings.Split(string(b), "\n")
	var frames []chatFrame
	for _, ln := range lines {
		var f chatFrame
		if strings.TrimSpace(ln) != "" && json.Unmarshal([]byte(ln), &f) == nil {
			frames = append(frames, f)
		}
	}
	for _, f := range frames {
		r.add(f, false)
	}
	// ограничение длины истории: самые старые сообщения отбрасываем
	if len(r.msgs) > chatMaxHistory {
		cut := len(r.msgs) - chatMaxHistory
		for _, m := range r.msgs[:cut] {
			delete(r.blobs, m.ID)
		}
		r.msgs = append([]ChatMsg(nil), r.msgs[cut:]...)
		var out []byte
		for _, m := range r.msgs {
			jb, _ := json.Marshal(r.blobs[m.ID])
			out = append(append(out, jb...), '\n')
		}
		_ = os.WriteFile(r.path, out, 0o600)
	}
}

func (r *ChatRoom) clrPath() string { return strings.TrimSuffix(r.path, ".log") + ".clr" }

func (r *ChatRoom) saveClrLocked() {
	if r.path != "" {
		_ = os.WriteFile(r.clrPath(), []byte(strconv.FormatInt(r.clearedTS, 10)), 0o600)
	}
}

// dropOlderLocked удаляет сообщения не новее ts (кроме keepID) и переписывает файл истории.
func (r *ChatRoom) dropOlderLocked(ts int64, keepID string) {
	var keep []ChatMsg
	for _, m := range r.msgs {
		if m.TS > ts || m.ID == keepID {
			keep = append(keep, m)
		} else {
			delete(r.blobs, m.ID)
		}
	}
	r.msgs = keep
	r.rewriteLocked()
}

func (r *ChatRoom) rewriteLocked() {
	if r.path == "" {
		return
	}
	var out []byte
	for _, m := range r.msgs {
		jb, _ := json.Marshal(r.blobs[m.ID])
		out = append(append(out, jb...), '\n')
	}
	_ = os.WriteFile(r.path, out, 0o600)
}

// ClearLocal очищает историю только на этом компьютере (старые сообщения от других больше не вернутся).
func (r *ChatRoom) ClearLocal() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.clearedTS = nowMs()
	r.msgs = nil
	r.blobs = map[string]chatFrame{}
	r.saveClrLocked()
	r.rewriteLocked()
}

// ExportText - история в виде обычного текста.
func (r *ChatRoom) ExportText() string {
	var sb strings.Builder
	sb.WriteString("Чат: " + r.Label + "\r\n\r\n")
	for _, m := range r.Messages() {
		t := time.Unix(m.TS/1000, 0).Format("2006-01-02 15:04:05")
		body := strings.ReplaceAll(strings.ReplaceAll(m.Text, "\r\n", "\n"), "\n", "\r\n")
		if m.Kind == "file" && m.File != nil {
			body = "[файл] " + m.File.Name + " (" + humanSize(m.File.Size) + ")"
		}
		sb.WriteString(t + "  " + m.Name + ": " + body + "\r\n")
	}
	return sb.String()
}

// Messages возвращает копию истории (без служебных "hi") с актуальными именами авторов.
func (r *ChatRoom) Messages() []ChatMsg {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]ChatMsg, 0, len(r.msgs))
	for _, m := range r.msgs {
		if m.Kind == "hi" || m.Kind == "clear" {
			continue
		}
		if n := r.names[m.UID]; n != "" {
			m.Name = n
		}
		out = append(out, m)
	}
	return out
}

func (r *ChatRoom) recentIDs(n int) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	ids := make([]string, 0, n)
	for i := len(r.msgs) - 1; i >= 0 && len(ids) < n; i-- {
		ids = append(ids, r.msgs[i].ID)
	}
	return ids
}

// missingFor возвращает кадры, которых нет у собеседника (не больше limit самых новых).
func (r *ChatRoom) missingFor(have []string, limit int) []chatFrame {
	hv := make(map[string]bool, len(have))
	for _, id := range have {
		hv[id] = true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []chatFrame
	for i := len(r.msgs) - 1; i >= 0 && len(out) < limit; i-- {
		if !hv[r.msgs[i].ID] {
			out = append(out, r.blobs[r.msgs[i].ID])
		}
	}
	return out
}

func newMsgID() string { return randHex(8) }

func nowMs() int64 { return time.Now().UnixNano() / 1e6 }

// FormatLine - строка истории для окна чата.
func (m ChatMsg) FormatLine() string {
	t := time.Unix(m.TS/1000, 0).Format("02.01 15:04")
	name := m.Name
	if name == "" {
		name = "?"
	}
	if m.Kind == "file" && m.File != nil {
		return t + "  " + name + ": [файл] " + m.File.Name + " (" + humanSize(m.File.Size) + ")"
	}
	return t + "  " + name + ": " + m.Text
}
