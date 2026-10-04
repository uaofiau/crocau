package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const textFileName = "crocau-text.txt"

// ---------- Пароль -> код-фраза croc ----------
// croc требует код не короче 6 символов; первые 4 символа - имя комнаты на relay (видно relay),
// всё после 5-го символа - секрет для PAKE. Короткий пароль пользователя кладём в секретную часть.
// Комната выводится из пароля (первые 4 hex-символа хэша): у разных паролей разные комнаты,
// поэтому передачи разных людей на общем relay не мешают друг другу и не упираются в общий лимит комнаты.
func makeSecret(pw string) string {
	h := sha256.Sum256([]byte("crocau-room:" + pw))
	room := hex.EncodeToString(h[:])[:4]
	return room + "-" + pw + "~crocau"
}

func randomPassword() string {
	const alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	out := make([]byte, 4)
	for i := range b {
		out[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(out)
}

// baseArgs собирает общие ключи croc. relay (если не пуст) перекрывает адрес из настроек.
// baseArgs собирает общие ключи croc. relay (если не пуст) перекрывает адрес из настроек.
func baseArgs(s Settings, relay string) []string {
	var a []string
	if relay == "" {
		relay = strings.TrimSpace(s.Relay)
	}
	if relay != "" {
		a = append(a, "--relay", relay)
	}
	if p := strings.TrimSpace(s.RelayPass); p != "" {
		a = append(a, "--pass", p)
	}
	a = append(a, "--ignore-stdin")
	if e := strings.TrimSpace(s.Extra); e != "" {
		a = append(a, strings.Fields(e)...)
	}
	return a
}

// Публичные relay croc. Первые четыре - нынешний пул автора (getcroc.com), последний - старый адрес.
var publicRelays = []string{
	"1.getcroc.com:9009",
	"2.getcroc.com:9009",
	"3.getcroc.com:9009",
	"4.getcroc.com:9009",
	"croc.schollz.com:9009",
}

// relayList возвращает relay для перебора по порядку. Порядок зависит только от секрета,
// поэтому отправитель и получатель выбирают одинаково.
func relayList(s Settings, secret string) []string {
	if r := strings.TrimSpace(s.Relay); r != "" {
		return []string{r}
	}
	if o := os.Getenv("CROCAU_RELAYS"); o != "" { // для тестов
		return strings.Split(o, ",")
	}
	h := sha256.Sum256([]byte("crocau-relay:" + secret))
	start := int(h[0]) % 4
	var order []string
	for i := 0; i < 4; i++ {
		order = append(order, publicRelays[(start+i)%4])
	}
	return append(order, publicRelays[4])
}

// ---------- Запуск croc (эта же программа в режиме --croc) ----------

type lockedBuf struct {
	mu *sync.Mutex
	b  *bytes.Buffer
}

func (l lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

type Job struct {
	mu       sync.Mutex // защищает stdout, stderr, notes, status, exit, cmd, killed
	stdout   bytes.Buffer
	stderr   bytes.Buffer
	notes    string
	status   string
	cmd      *exec.Cmd
	killed   bool
	done     chan struct{}
	exit     int
	work     string
	secret   string
	preCount int
	pre      map[string]bool // имена в папке приёма до начала (для режима обмена)
}

// JobSpec описывает задание: подготовка (архив) -> croc по очереди relay x маршрутов -> завершение (распаковка).
type JobSpec struct {
	Work       string
	Secret     string
	MkArgs     func(relay string) []string
	Relays     []string // пусто - один запуск с MkArgs("")
	Routes     []Route  // пусто - напрямую
	ProbeRelay string   // relay для быстрой проверки маршрутов (если маршрутов больше одного)
	Prep       func(j *Job) error
	Post       func(j *Job) error
}

func newWork() (string, error) { return os.MkdirTemp("", "crocau-") }

func (j *Job) isKilled() bool {
	if j == nil {
		return false
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.killed
}

func (j *Job) addNote(s string) {
	if j == nil {
		return
	}
	j.mu.Lock()
	j.notes += s + "\r\n"
	j.mu.Unlock()
}

func (j *Job) setStatus(s string) {
	if j == nil {
		return
	}
	j.mu.Lock()
	j.status = s
	j.mu.Unlock()
}

// childEnv: окружение для croc без чужих настроек прокси/croc; прокси задаётся только нами.
func childEnv(work, secret, proxyURL string) []string {
	var env []string
	for _, kv := range os.Environ() {
		i := strings.IndexByte(kv, '=')
		if i > 0 {
			k := strings.ToUpper(kv[:i])
			if k == "SOCKS5_PROXY" || k == "HTTP_PROXY" || k == "HTTPS_PROXY" || k == "ALL_PROXY" || strings.HasPrefix(k, "CROC_") {
				continue
			}
		}
		env = append(env, kv)
	}
	env = append(env, "CROC_CONFIG_DIR="+filepath.Join(work, "cfg"))
	if secret != "" {
		env = append(env, "CROC_SECRET="+secret)
	}
	if proxyURL != "" {
		env = append(env, "SOCKS5_PROXY="+proxyURL)
	}
	return env
}

// spawn запускает один процесс croc; буферы вывода очищаются.
func (j *Job) spawn(args []string, proxyURL string) (*exec.Cmd, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(exe, append([]string{"--croc"}, args...)...)
	cmd.Dir = j.work
	cmd.Env = childEnv(j.work, j.secret, proxyURL)
	j.mu.Lock()
	j.stdout.Reset()
	j.stderr.Reset()
	j.mu.Unlock()
	cmd.Stdout = lockedBuf{&j.mu, &j.stdout}
	cmd.Stderr = lockedBuf{&j.mu, &j.stderr}
	hideWindow(cmd)
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	j.mu.Lock()
	j.cmd = cmd
	j.mu.Unlock()
	return cmd, nil
}

func exitCodeOf(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}

func isConnectError(text string) bool {
	return strings.Contains(text, "could not connect")
}

// startJob запускает задание в фоне и сразу возвращает Job.
func startJob(spec JobSpec) *Job {
	j := &Job{done: make(chan struct{}), work: spec.Work, secret: spec.Secret}
	go func() {
		code := j.run(spec)
		j.mu.Lock()
		j.exit = code
		j.status = ""
		j.mu.Unlock()
		close(j.done)
	}()
	return j
}

type attemptT struct {
	relay string
	route Route
}

func (a attemptT) describe() string {
	s := a.relay
	if s == "" {
		s = "relay из настроек"
	}
	if a.route.P != nil {
		s += " через " + a.route.Name()
	}
	return s
}

func (j *Job) run(spec JobSpec) int {
	if spec.Prep != nil {
		if err := spec.Prep(j); err != nil {
			if !j.isKilled() {
				j.addNote("Ошибка подготовки: " + err.Error())
			}
			return -1
		}
	}
	relays := spec.Relays
	if len(relays) == 0 {
		relays = []string{""}
	}
	routes := spec.Routes
	if len(routes) == 0 {
		routes = []Route{{}}
	}
	if len(routes) > 1 && spec.ProbeRelay != "" && !j.isKilled() {
		j.setStatus("Проверка соединения...")
		routes = orderRoutes(routes, spec.ProbeRelay, 3*time.Second)
		j.setStatus("")
	}
	var atts []attemptT
	for _, rl := range relays {
		for _, rt := range routes {
			atts = append(atts, attemptT{rl, rt})
		}
	}
	code := -1
	for i, a := range atts {
		if j.isKilled() {
			return -1
		}
		var errText string
		code, errText = j.attempt(spec, a)
		if code == 0 {
			break
		}
		if j.isKilled() || i+1 >= len(atts) || !isConnectError(errText) {
			break
		}
		reason := "нет соединения"
		if strings.Contains(errText, "rate limited") {
			reason = "лимит подключений"
		}
		j.addNote(fmt.Sprintf("%s: %s. Пробую %s", a.describe(), reason, atts[i+1].describe()))
	}
	if code == 0 && spec.Post != nil {
		if err := spec.Post(j); err != nil {
			j.addNote("Ошибка: " + err.Error())
			return 2
		}
	}
	return code
}

// attempt делает одну попытку (relay, маршрут); возвращает код выхода и stderr croc.
func (j *Job) attempt(spec JobSpec, a attemptT) (int, string) {
	proxyURL := ""
	var br *Bridge
	if a.route.P != nil {
		var err error
		br, err = startBridge(a.route)
		if err != nil {
			j.addNote("Не удалось запустить локальный мост для прокси: " + err.Error())
			return -1, "could not connect: " + err.Error()
		}
		defer br.Close()
		proxyURL = br.URL
	}
	if a.relay != "" {
		n := "Relay: " + a.relay
		if a.route.P != nil {
			n += " (через " + a.route.Name() + ")"
		}
		j.addNote(n)
	}
	if j.isKilled() {
		return -1, ""
	}
	cmd, err := j.spawn(spec.MkArgs(a.relay), proxyURL)
	if err != nil {
		j.addNote("Не удалось запустить croc: " + err.Error())
		return -1, ""
	}
	code := exitCodeOf(cmd.Wait())
	j.mu.Lock()
	errText := j.stderr.String()
	j.mu.Unlock()
	if code != 0 && br != nil {
		if e := br.LastError(); e != "" {
			j.addNote("Прокси: " + e)
		}
	}
	return code, errText
}

func (j *Job) Running() bool {
	select {
	case <-j.done:
		return false
	default:
		return true
	}
}

func (j *Job) Kill() {
	j.mu.Lock()
	j.killed = true
	cmd := j.cmd
	j.mu.Unlock()
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}

// Wait ждёт завершения до d; по таймауту убивает процесс и возвращает false.
func (j *Job) Wait(d time.Duration) bool {
	select {
	case <-j.done:
		return true
	case <-time.After(d):
		j.Kill()
		select {
		case <-j.done:
		case <-time.After(5 * time.Second):
		}
		return false
	}
}

func (j *Job) ExitCode() int {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.exit
}

func (j *Job) Stdout() string {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.stdout.String()
}

func (j *Job) Log() string {
	j.mu.Lock()
	raw := j.stderr.String()
	notes := j.notes
	status := j.status
	j.mu.Unlock()
	body := formatLog(raw, j.secret)
	out := notes
	if status != "" {
		out += status + "\r\n"
	}
	return strings.TrimRight(out+body, "\r\n")
}

func (j *Job) Cleanup() {
	if j.work != "" {
		_ = os.RemoveAll(j.work)
	}
}

var ansiRe = regexp.MustCompile("\x1b\\[[0-9;?]*[A-Za-z]")

func formatLog(raw, secret string) string {
	raw = ansiRe.ReplaceAllString(raw, "")
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	var out []string
	for _, l := range strings.Split(raw, "\n") {
		if i := strings.LastIndex(l, "\r"); i >= 0 {
			l = l[i+1:]
		}
		if secret != "" && strings.Contains(l, secret) {
			continue
		}
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "Code is:") || strings.HasPrefix(t, "On the other computer run") ||
			t == "(For Windows)" || t == "(For Linux/OSX)" || strings.HasPrefix(t, "CROC_SECRET") {
			continue
		}
		out = append(out, l)
	}
	if len(out) > 200 {
		out = out[len(out)-200:]
	}
	return strings.Join(out, "\r\n")
}

// ---------- Отправка / получение ----------

// startSend отправляет текст и/или файлы и папки одной передачей (по желанию - в zip-архиве).
func startSend(s Settings, pw, text string, items []string) (*Job, error) {
	if strings.TrimSpace(text) == "" {
		text = ""
	}
	if text == "" && len(items) == 0 {
		return nil, errors.New("нечего отправлять")
	}
	routes, err := routesFor(s)
	if err != nil {
		return nil, err
	}
	work, err := newWork()
	if err != nil {
		return nil, err
	}
	secret := makeSecret(pw)
	relays := relayList(s, secret)
	var paths []string
	compress := s.Compress
	if !compress {
		if text != "" {
			tp := filepath.Join(work, textFileName)
			if err := os.WriteFile(tp, []byte(text), 0600); err != nil {
				os.RemoveAll(work)
				return nil, err
			}
			paths = append(paths, tp)
		}
		paths = append(paths, items...)
	}
	spec := JobSpec{
		Work: work, Secret: secret, Relays: relays, Routes: routes, ProbeRelay: relays[0],
		MkArgs: func(relay string) []string {
			// --no-local: без него отправитель при недоступном relay молча ждёт локальную сеть и не сообщает об ошибке
			args := append(baseArgs(s, relay), "send", "--no-local")
			return append(args, paths...)
		},
	}
	if compress {
		spec.Prep = func(j *Job) error {
			j.setStatus("Архивирование...")
			p, err := buildArchive(j, work, text, items)
			if err != nil {
				return err
			}
			paths = []string{p}
			return nil
		}
	}
	return startJob(spec), nil
}

func countEntries(dir string) int {
	e, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	return len(e)
}

// startReceive принимает всё в папку out (архивы crocau распаковываются автоматически).
// Второе значение - была ли папка создана нами.
func startReceive(s Settings, pw, out string) (*Job, bool, error) {
	routes, err := routesFor(s)
	if err != nil {
		return nil, false, err
	}
	created := false
	if _, err := os.Stat(out); os.IsNotExist(err) {
		created = true
	}
	if err := os.MkdirAll(out, 0755); err != nil {
		return nil, false, err
	}
	pre := listNames(out)
	work, err := newWork()
	if err != nil {
		return nil, false, err
	}
	secret := makeSecret(pw)
	relays := relayList(s, secret)
	spec := JobSpec{
		Work: work, Secret: secret, Relays: relays, Routes: routes, ProbeRelay: relays[0],
		MkArgs: func(relay string) []string {
			return append(baseArgs(s, relay), "--yes", "--overwrite", "--out", out)
		},
		Post: func(j *Job) error { return extractArchives(j, out, pre) },
	}
	j := startJob(spec)
	j.preCount = len(pre)
	j.pre = pre
	return j, created, nil
}

type RecvResult struct {
	Text     string
	HasFiles bool
}

// finalizeReceive достаёт присланный текст из служебного файла и убирает пустую папку,
// если её создали мы.
func finalizeReceive(j *Job, out string, created bool) RecvResult {
	var r RecvResult
	tf := filepath.Join(out, textFileName)
	gotTextFile := false
	if b, err := os.ReadFile(tf); err == nil {
		r.Text = strings.TrimPrefix(string(b), "\ufeff")
		_ = os.Remove(tf)
		gotTextFile = true
	} else if s := j.Stdout(); strings.TrimSpace(s) != "" {
		r.Text = s // текст от обычного croc (--text)
	}
	n := countEntries(out)
	if r.Text == "" || gotTextFile && n > j.preCount || !gotTextFile && n > j.preCount {
		r.HasFiles = n > 0
	}
	if created && n == 0 {
		_ = os.Remove(out)
	}
	return r
}
