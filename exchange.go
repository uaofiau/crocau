package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Минимум такой же, как у обычной передачи: программа для быстрой передачи рабочих файлов, а не секретов
// (для чувствительных данных используют запароленный архив). От перебора на постоянно слушающем устройстве
// остаётся торможение: после неудачных попыток приём приостанавливается на всё более долгое время.
const exchangeMinPw = 3

// skipFirewall отключает работу с брандмауэром (тесты).
var skipFirewall bool

type ExchangeEvent struct {
	Time  time.Time
	Kind  string // "received", "info", "error"
	Msg   string
	Text  string
	Names []string
	Files bool
}

// Exchange - режим непрерывного обмена. Устройство держит у себя relay croc (слушает порты локальной сети),
// постоянно ждёт в комнате отправителя с общим паролем, принимает присланное и сразу ждёт следующее.
type Exchange struct {
	mu       sync.Mutex
	running  bool
	stopCh   chan struct{}
	wg       sync.WaitGroup
	relay    *Job
	cur      *Job
	stopResp func()
	lastFail string // журнал последней неудачной попытки приёма (для диагностики)
}

func (x *Exchange) Running() bool {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.running
}

func waitTCP(addr string, d time.Duration, j *Job) bool {
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		if j != nil && !j.Running() {
			return false
		}
		c, err := net.DialTimeout("tcp", addr, 300*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(strings.ReplaceAll(s, "\r", "")), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}

func newNames(dir string, pre map[string]bool) []string {
	var out []string
	if es, err := os.ReadDir(dir); err == nil {
		for _, e := range es {
			if !pre[e.Name()] && e.Name() != textFileName {
				out = append(out, e.Name())
			}
		}
	}
	return out
}

// Start включает режим обмена.
func (x *Exchange) Start(pw, out, name string, onEvent func(ExchangeEvent)) error {
	x.mu.Lock()
	if x.running {
		x.mu.Unlock()
		return errors.New("режим обмена уже включён")
	}
	x.mu.Unlock()
	if utf8.RuneCountInString(pw) < exchangeMinPw {
		return fmt.Errorf("пароль режима обмена должен быть не короче %d символов", exchangeMinPw)
	}
	if strings.TrimSpace(out) == "" {
		return errors.New("укажите папку для сохранения (вкладка «Получить»)")
	}
	if err := os.MkdirAll(out, 0755); err != nil {
		return fmt.Errorf("не удалось создать папку Share: %v", err)
	}
	port := lanRelayPorts[0]

	work, err := newWork()
	if err != nil {
		return err
	}
	ports := strings.Join(lanRelayPorts, ",")
	relay := startJob(JobSpec{Work: work, MkArgs: func(string) []string {
		return []string{"relay", "--port", port, "--ports", ports}
	}})
	if !waitTCP("127.0.0.1:"+port, 5*time.Second, relay) {
		msg := lastLine(relay.Log())
		relay.Kill()
		relay.Cleanup()
		if msg == "" {
			msg = "relay не запустился"
		}
		return fmt.Errorf("не удалось открыть порт %s (возможно, он занят): %s", port, msg)
	}

	x.mu.Lock()
	x.running = true
	x.stopCh = make(chan struct{})
	x.relay = relay
	x.mu.Unlock()

	id := instanceID
	var warn []string
	if stop, err := startResponder(id, roleRecv, name, mustAtoi(port)); err != nil {
		warn = append(warn, "поиск устройств недоступен (UDP-порт занят)")
	} else {
		x.mu.Lock()
		x.stopResp = stop
		x.mu.Unlock()
	}
	ips := localIPv4s()
	msg := "Режим обмена включён. Адрес этого устройства: " + strings.Join(ips, ", ")
	if len(ips) == 0 {
		msg = "Режим обмена включён (сетевых адресов не найдено)"
	}
	if len(warn) > 0 {
		msg += ". Внимание: " + strings.Join(warn, "; ")
	}
	onEvent(ExchangeEvent{Time: time.Now(), Kind: "info", Msg: msg})

	if !skipFirewall {
		x.wg.Add(1)
		go func() {
			defer x.wg.Done()
			if err := fwEnsure(); err != nil {
				onEvent(ExchangeEvent{Time: time.Now(), Kind: "error", Msg: "Не удалось открыть порты в брандмауэре: " + err.Error() +
					". Если другие устройства не видят это, разрешите crocau.exe в брандмауэре вручную."})
			} else {
				onEvent(ExchangeEvent{Time: time.Now(), Kind: "info", Msg: "Порты в брандмауэре открыты"})
			}
		}()
	}

	x.wg.Add(1)
	go x.loop(pw, out, "127.0.0.1:"+port, onEvent)
	return nil
}

func (x *Exchange) stopped() bool {
	select {
	case <-x.stopCh:
		return true
	default:
		return false
	}
}

func (x *Exchange) loop(pw, out, relayAddr string, onEvent func(ExchangeEvent)) {
	defer x.wg.Done()
	local := Settings{Relay: relayAddr, ProxyMode: modeDirect}
	// приём идёт во временную папку (не в Share, чтобы в ней ничего не мигало), затем содержимое переносится в Share с разбором конфликтов
	stageRoot, serr := newWork()
	if serr != nil {
		onEvent(ExchangeEvent{Time: time.Now(), Kind: "error", Msg: serr.Error()})
		return
	}
	defer os.RemoveAll(stageRoot)
	staging := filepath.Join(stageRoot, "in")
	lastErr := ""
	hfails := 0
	backoff := time.Second
	fails := 0
	for !x.stopped() {
		j, created, err := startReceive(local, pw, staging)
		if err != nil {
			onEvent(ExchangeEvent{Time: time.Now(), Kind: "error", Msg: err.Error()})
			if !x.sleep(5 * time.Second) {
				return
			}
			continue
		}
		x.mu.Lock()
		x.cur = j
		x.mu.Unlock()
		select {
		case <-j.done:
		case <-x.stopCh:
			j.Kill()
			<-j.done
			j.Cleanup()
			return
		}
		if j.ExitCode() == 0 {
			res := finalizeReceive(j, staging, created)
			j.Cleanup()
			names, renamed := mergeIncoming(staging, out, res.From, time.Now())
			_ = os.Remove(staging)
			fails, backoff, hfails = 0, time.Second, 0
			ev := ExchangeEvent{Time: time.Now(), Kind: "received", Text: res.Text, Names: names, Files: res.HasFiles || len(names) > 0}
			if renamed > 0 {
				ev.Msg = fmt.Sprintf("совпали имена, новые версии сохранены с пометкой CONFLICT: %d", renamed)
			}
			onEvent(ev)
			continue
		}
		msg := lastLine(j.Log())
		x.mu.Lock()
		x.lastFail = j.Log()
		x.mu.Unlock()
		j.Cleanup()
		_ = os.Remove(staging)
		if x.stopped() {
			return
		}
		if isHandshakeError(msg + "\n" + x.lastFailText()) {
			// чужой пароль или одновременная попытка: приём не «ломается», поэтому задержка небольшая (до 4 с) -
			// иначе устройство подолгу не слушает и законный отправитель не может подключиться
			hfails++
			d := 500 * time.Millisecond << uint(min(hfails-1, 3))
			if !x.sleep(d) {
				return
			}
			continue
		}
		hfails = 0
		fails++
		if msg != lastErr || fails%20 == 0 {
			lastErr = msg
			onEvent(ExchangeEvent{Time: time.Now(), Kind: "error", Msg: "Приём не удался (попыток подряд: " + itoa(fails) + "): " + msg})
		}
		if !x.sleep(backoff) {
			return
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

// cleanDeviceName оставляет в имени устройства только то, что допустимо в имени файла.
func cleanDeviceName(n string) string {
	n = strings.TrimSpace(n)
	r := strings.Map(func(c rune) rune {
		if c < 32 || strings.ContainsRune(`\/:*?"<>|`, c) {
			return '_'
		}
		return c
	}, n)
	if rs := []rune(r); len(rs) > 40 {
		r = string(rs[:40])
	}
	return strings.Trim(r, " .")
}

// conflictName: [имя]-CONFLICT-[устройство]_[дата]-[время].[расширение]
func conflictName(name string, isDir bool, from string, t time.Time) string {
	if from == "" {
		from = "device"
	}
	stamp := t.Format("2006-01-02_15-04-05")
	ext := ""
	base := name
	if !isDir {
		ext = filepath.Ext(name)
		base = strings.TrimSuffix(name, ext)
	}
	return base + "-CONFLICT-" + from + "_" + stamp + ext
}

// mergeIncoming переносит принятое из staging в папку Share. Если такое имя уже есть - существующий файл
// остаётся нетронутым, а принятый сохраняется под именем с пометкой CONFLICT. Возвращает итоговые имена и число переименований.
func mergeIncoming(staging, out, from string, t time.Time) ([]string, int) {
	es, err := os.ReadDir(staging)
	if err != nil {
		return nil, 0
	}
	if err := os.MkdirAll(out, 0755); err != nil {
		return nil, 0
	}
	var names []string
	renamed := 0
	for _, e := range es {
		name := e.Name()
		if name == textFileName || name == fromFileName {
			continue
		}
		dst := name
		if _, err := os.Lstat(filepath.Join(out, dst)); err == nil {
			dst = conflictName(name, e.IsDir(), from, t)
			for i := 2; ; i++ {
				if _, err := os.Lstat(filepath.Join(out, dst)); err != nil {
					break
				}
				dst = conflictName(name, e.IsDir(), from, t.Add(time.Duration(i-1)*time.Second))
			}
			renamed++
		}
		if err := moveAny(filepath.Join(staging, name), filepath.Join(out, dst)); err != nil {
			continue
		}
		names = append(names, dst)
	}
	return names, renamed
}

func (x *Exchange) sleep(d time.Duration) bool {
	select {
	case <-time.After(d):
		return true
	case <-x.stopCh:
		return false
	}
}

// Stop выключает режим обмена и ждёт остановки процессов.
func (x *Exchange) Stop() {
	x.mu.Lock()
	if !x.running {
		x.mu.Unlock()
		return
	}
	x.running = false
	close(x.stopCh)
	relay, cur, stopResp := x.relay, x.cur, x.stopResp
	x.relay, x.cur, x.stopResp = nil, nil, nil
	x.mu.Unlock()
	if cur != nil {
		cur.Kill()
	}
	if stopResp != nil {
		stopResp()
	}
	done := make(chan struct{})
	go func() { x.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(8 * time.Second):
	}
	if relay != nil {
		relay.Kill()
		relay.Wait(3 * time.Second)
		relay.Cleanup()
	}
}

func mustAtoi(s string) int {
	n := 0
	for _, c := range s {
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		}
	}
	return n
}

// moveAny переносит файл или папку; если переименование невозможно (другой диск), копирует и удаляет оригинал.
func moveAny(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	if err := copyTree(src, dst); err != nil {
		_ = os.RemoveAll(dst)
		return err
	}
	return os.RemoveAll(src)
}

func copyTree(src, dst string) error {
	return filepath.Walk(src, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		t := filepath.Join(dst, rel)
		if fi.IsDir() {
			return os.MkdirAll(t, 0755)
		}
		in, err := os.Open(p)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.Create(t)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, in); err != nil {
			out.Close()
			return err
		}
		return out.Close()
	})
}

func (x *Exchange) lastFailText() string {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.lastFail
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
