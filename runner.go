package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const textFileName = "crocau-text.txt"

// ---------- Настройки (crocau.ini рядом с exe) ----------

type Settings struct {
	Relay, RelayPass, Proxy, Extra, OutDir string
}

func exeDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(exe)
}

func iniPath() string { return filepath.Join(exeDir(), "crocau.ini") }

func loadSettings() Settings {
	s := Settings{OutDir: filepath.Join(exeDir(), "received")}
	data, err := os.ReadFile(iniPath())
	if err != nil {
		return s
	}
	text := strings.TrimPrefix(string(data), "\ufeff")
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, "\r")
		i := strings.Index(line, "=")
		if i <= 0 {
			continue
		}
		k, v := strings.TrimSpace(line[:i]), line[i+1:]
		switch k {
		case "Relay":
			s.Relay = v
		case "RelayPass":
			s.RelayPass = v
		case "Proxy":
			s.Proxy = v
		case "Extra":
			s.Extra = v
		case "OutDir":
			s.OutDir = v
		}
	}
	return s
}

func saveSettings(s Settings) {
	text := "Relay=" + s.Relay + "\r\nRelayPass=" + s.RelayPass + "\r\nProxy=" + s.Proxy +
		"\r\nExtra=" + s.Extra + "\r\nOutDir=" + s.OutDir + "\r\n"
	if old, err := os.ReadFile(iniPath()); err == nil && string(old) == text {
		return
	}
	_ = os.WriteFile(iniPath(), []byte(text), 0644)
}

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

func baseArgs(s Settings) []string {
	var a []string
	if r := strings.TrimSpace(s.Relay); r != "" {
		a = append(a, "--relay", r)
	}
	if p := strings.TrimSpace(s.RelayPass); p != "" {
		a = append(a, "--pass", p)
	}
	if p := strings.TrimSpace(s.Proxy); p != "" {
		lp := strings.ToLower(p)
		if strings.HasPrefix(lp, "http://") || strings.HasPrefix(lp, "https://") {
			a = append(a, "--connect", p)
		} else {
			a = append(a, "--socks5", p)
		}
	}
	a = append(a, "--ignore-stdin")
	if e := strings.TrimSpace(s.Extra); e != "" {
		a = append(a, strings.Fields(e)...)
	}
	return a
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
	cmd      *exec.Cmd
	mu       sync.Mutex
	stdout   bytes.Buffer
	stderr   bytes.Buffer
	done     chan struct{}
	exit     int
	work     string
	secret   string
	preCount int
}

func newWork() (string, error) { return os.MkdirTemp("", "crocau-") }

func startCroc(args []string, secret, work string) (*Job, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	j := &Job{done: make(chan struct{}), work: work, secret: secret}
	cmd := exec.Command(exe, append([]string{"--croc"}, args...)...)
	cmd.Dir = work
	env := append(os.Environ(), "CROC_CONFIG_DIR="+filepath.Join(work, "cfg"))
	if secret != "" {
		env = append(env, "CROC_SECRET="+secret)
	}
	cmd.Env = env
	cmd.Stdout = lockedBuf{&j.mu, &j.stdout}
	cmd.Stderr = lockedBuf{&j.mu, &j.stderr}
	hideWindow(cmd)
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	j.cmd = cmd
	go func() {
		err := cmd.Wait()
		code := 0
		if err != nil {
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				code = ee.ExitCode()
			} else {
				code = -1
			}
		}
		j.mu.Lock()
		j.exit = code
		j.mu.Unlock()
		close(j.done)
	}()
	return j, nil
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
	if j.cmd != nil && j.cmd.Process != nil {
		_ = j.cmd.Process.Kill()
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
	j.mu.Unlock()
	return formatLog(raw, j.secret)
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

// startSend отправляет текст (как служебный файл) и/или файлы и папки одной передачей.
func startSend(s Settings, pw, text string, items []string) (*Job, error) {
	work, err := newWork()
	if err != nil {
		return nil, err
	}
	var paths []string
	if strings.TrimSpace(text) != "" {
		tp := filepath.Join(work, textFileName)
		if err := os.WriteFile(tp, []byte(text), 0600); err != nil {
			os.RemoveAll(work)
			return nil, err
		}
		paths = append(paths, tp)
	}
	paths = append(paths, items...)
	if len(paths) == 0 {
		os.RemoveAll(work)
		return nil, errors.New("нечего отправлять")
	}
	args := append(baseArgs(s), "send")
	args = append(args, paths...)
	j, err := startCroc(args, makeSecret(pw), work)
	if err != nil {
		os.RemoveAll(work)
		return nil, err
	}
	return j, nil
}

func countEntries(dir string) int {
	e, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	return len(e)
}

// startReceive принимает всё в папку out. Второе значение - была ли папка создана нами.
func startReceive(s Settings, pw, out string) (*Job, bool, error) {
	created := false
	if _, err := os.Stat(out); os.IsNotExist(err) {
		created = true
	}
	if err := os.MkdirAll(out, 0755); err != nil {
		return nil, false, err
	}
	pre := countEntries(out)
	work, err := newWork()
	if err != nil {
		return nil, false, err
	}
	args := append(baseArgs(s), "--yes", "--overwrite", "--out", out)
	j, err := startCroc(args, makeSecret(pw), work)
	if err != nil {
		os.RemoveAll(work)
		return nil, false, err
	}
	j.preCount = pre
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
	if r.Text == "" || (!gotTextFile && n > j.preCount) || (gotTextFile && n > j.preCount) {
		r.HasFiles = n > 0
	}
	if created && n == 0 {
		_ = os.Remove(out)
	}
	return r
}
