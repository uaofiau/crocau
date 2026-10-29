package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// allDevices - значение поля «Кому» на вкладке «Обмен»: отправить всем найденным устройствам в режиме обмена.
const allDevices = "Все найденные устройства"

func isServiceName(n string) bool {
	return n == "" || strings.HasPrefix(n, ".") || n == textFileName || n == fromFileName
}

// pathSig - признак «файл не менялся»: размер и время изменения (для папки - сводка по всем файлам внутри).
func pathSig(p string) string {
	fi, err := os.Lstat(p)
	if err != nil {
		return ""
	}
	if !fi.IsDir() {
		return fmt.Sprintf("f:%d:%d", fi.Size(), fi.ModTime().UnixNano())
	}
	var n, sz, mt int64
	_ = filepath.Walk(p, func(_ string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		n++
		sz += info.Size()
		if m := info.ModTime().UnixNano(); m > mt {
			mt = m
		}
		return nil
	})
	return fmt.Sprintf("d:%d:%d:%d", n, sz, mt)
}

// shareSnapshot: имя верхнего уровня -> признак. Служебные и скрытые (начинаются с точки) имена пропускаются.
func shareSnapshot(dir string) map[string]string {
	m := map[string]string{}
	es, err := os.ReadDir(dir)
	if err != nil {
		return m
	}
	for _, e := range es {
		if isServiceName(e.Name()) {
			continue
		}
		if sg := pathSig(filepath.Join(dir, e.Name())); sg != "" {
			m[e.Name()] = sg
		}
	}
	return m
}

func shareNames(dir string) []string {
	var out []string
	for n := range shareSnapshot(dir) {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// shareSend по очереди отправляет перечисленные элементы папки Share каждому адресу (устройство в режиме обмена).
// Возвращает число успешных и неудачных отправок; report получает короткие сообщения.
func shareSend(cfg Settings, pw, dir string, names, addrs []string, cancel <-chan struct{}, report func(string)) (ok, fail int) {
	items := make([]string, 0, len(names))
	for _, n := range names {
		items = append(items, filepath.Join(dir, n))
	}
	for _, a := range addrs {
		select {
		case <-cancel:
			return
		default:
		}
		c := cfg
		c.Relay, c.RelayPass, c.ProxyMode, c.Proxies = a, "", modeDirect, nil
		j, err := startSend(c, pw, "", items)
		if err != nil {
			fail++
			report(a + ": " + err.Error())
			continue
		}
		deadline := time.Now().Add(30 * time.Minute)
		stopped := false
		for !j.Wait(500 * time.Millisecond) {
			select {
			case <-cancel:
				stopped = true
			default:
			}
			if stopped || time.Now().After(deadline) {
				j.Kill()
				j.Wait(3 * time.Second)
				break
			}
		}
		if !stopped && j.ExitCode() == 0 {
			ok++
		} else {
			fail++
			if !stopped {
				report(a + ": " + lastLine(j.Log()))
			}
		}
		j.Cleanup()
		if stopped {
			return
		}
	}
	return
}

// ShareWatcher следит за папкой Share: новые и изменённые элементы (стабильные два опроса подряд) передаёт функции send.
// Уже существующее на момент включения считается «базой» и само не отправляется (для этого есть кнопка).
type ShareWatcher struct {
	mu      sync.Mutex
	stopCh  chan struct{}
	wg      sync.WaitGroup
	dir     string
	snap    map[string]string // то, что уже отправлено или считается отправленным
	pend    map[string]string // признак при прошлом опросе
	retryAt map[string]time.Time
}

func (w *ShareWatcher) Running() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.stopCh != nil
}

// Mark записывает текущее состояние перечисленных элементов как «не требующее отправки» (например, только что принятые).
func (w *ShareWatcher) Mark(names []string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.stopCh == nil {
		return
	}
	for _, n := range names {
		if sg := pathSig(filepath.Join(w.dir, n)); sg != "" {
			w.snap[n] = sg
			w.pend[n] = sg
		}
	}
}

func (w *ShareWatcher) Start(dir string, interval time.Duration, send func(names []string) bool) {
	w.mu.Lock()
	if w.stopCh != nil {
		w.mu.Unlock()
		return
	}
	_ = os.MkdirAll(dir, 0755)
	w.dir = dir
	w.snap = shareSnapshot(dir)
	w.pend = map[string]string{}
	w.retryAt = map[string]time.Time{}
	stop := make(chan struct{})
	w.stopCh = stop
	w.mu.Unlock()
	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
			}
			cur := shareSnapshot(dir)
			var changed []string
			sigs := map[string]string{}
			w.mu.Lock()
			for n := range w.snap {
				if _, ok := cur[n]; !ok {
					delete(w.snap, n) // удалили: при возвращении файл снова считается новым
				}
			}
			for n, sg := range cur {
				if w.snap[n] == sg {
					delete(w.pend, n)
					continue
				}
				if w.pend[n] != sg {
					w.pend[n] = sg // ещё может копироваться: ждём следующего опроса
					continue
				}
				if time.Now().Before(w.retryAt[n]) {
					continue
				}
				changed = append(changed, n)
				sigs[n] = sg
			}
			w.mu.Unlock()
			if len(changed) == 0 {
				continue
			}
			sort.Strings(changed)
			ok := send(changed)
			w.mu.Lock()
			for _, n := range changed {
				if ok {
					w.snap[n] = sigs[n]
				} else {
					w.retryAt[n] = time.Now().Add(30 * time.Second)
				}
			}
			w.mu.Unlock()
		}
	}()
}

func (w *ShareWatcher) Stop() {
	w.mu.Lock()
	stop := w.stopCh
	w.stopCh = nil
	w.mu.Unlock()
	if stop != nil {
		close(stop)
		w.wg.Wait()
	}
}

// resolveShareTargets переводит значение поля «Кому» в адреса устройств. Пусто или «Все найденные устройства» -
// поиск в сети; иначе одно или несколько устройств (из списка или IP), разделённых «;».
func resolveShareTargets(target string, known []Peer, selfID string) []string {
	t := strings.TrimSpace(target)
	var out []string
	if t == "" || t == allDevices {
		for _, p := range discoverPeers(2*time.Second, selfID, roleRecv, planScan().Targets) {
			out = append(out, p.Addr())
		}
		return out
	}
	for _, part := range strings.Split(t, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		found := false
		for _, p := range known {
			if p.Label() == part {
				out = append(out, p.Addr())
				found = true
				break
			}
		}
		if !found {
			if a, ok := parseLANAddr(part); ok {
				out = append(out, a)
			}
		}
	}
	return out
}
