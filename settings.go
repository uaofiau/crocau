package main

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

const (
	modeDirect = "direct"
	modeAuto   = "auto"
	modeProxy  = "proxy"

	maxProxies = 8
)

// ProxyCfg - один прокси из списка. Type: socks5, socks4 или http.
type ProxyCfg struct {
	Type string
	Addr string
	Auth bool
	User string
	Pass string
}

type Settings struct {
	Relay     string
	RelayPass string
	Extra     string
	OutDir    string
	Compress  bool
	// Сохранённые пароли передачи (хранятся защищёнными, только если стоит галочка).
	SaveSendPw bool
	SendPw     string
	SaveRecvPw bool
	RecvPw     string
	// SecretNote - предупреждение при загрузке (не сохраняется в файл).
	SecretNote string
	// Мастер-пароль: Protect = "account" (по умолчанию) или "master"; соль и контрольное значение лежат в файле.
	Protect     string
	MasterSalt  string
	MasterCheck string
	// Locked - файл защищён мастер-паролем, а он не введён (не сохраняется в файл).
	Locked    bool
	ProxyMode string
	ProxySel  int
	Proxies   []ProxyCfg
}

func exeDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(exe)
}

func iniPath() string { return filepath.Join(exeDir(), "crocau.ini") }

func normType(t string) string {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "socks4", "socks4a":
		return "socks4"
	case "http", "https":
		return "http"
	default:
		return "socks5"
	}
}

func encodeProxy(p ProxyCfg, seal func(string) string) string {
	a := "0"
	if p.Auth {
		a = "1"
	}
	parts := []string{normType(p.Type), p.Addr, a, p.User, seal(p.Pass)}
	for i := range parts {
		parts[i] = url.QueryEscape(parts[i])
	}
	return strings.Join(parts, "|")
}

// decodeProxy: lost != nil, если пароль не удалось расшифровать (он тогда пустой).
func decodeProxy(v string) (p ProxyCfg, ok bool, lost error) {
	parts := strings.Split(v, "|")
	if len(parts) != 5 {
		return ProxyCfg{}, false, nil
	}
	for i := range parts {
		u, err := url.QueryUnescape(parts[i])
		if err != nil {
			return ProxyCfg{}, false, nil
		}
		parts[i] = u
	}
	pass, err := openSecret(parts[4])
	if err != nil {
		pass, lost = "", err
	}
	return ProxyCfg{Type: normType(parts[0]), Addr: parts[1], Auth: parts[2] == "1", User: parts[3], Pass: pass}, true, lost
}

// legacyProxy разбирает старый формат одной строки: socks5://user:pass@host:port или host:port.
func legacyProxy(v string) (ProxyCfg, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return ProxyCfg{}, false
	}
	t := "socks5"
	if i := strings.Index(v, "://"); i >= 0 {
		t = normType(v[:i])
		v = v[i+3:]
	}
	p := ProxyCfg{Type: t}
	if at := strings.LastIndex(v, "@"); at >= 0 {
		cred := v[:at]
		v = v[at+1:]
		p.Auth = true
		if c := strings.Index(cred, ":"); c >= 0 {
			p.User, p.Pass = cred[:c], cred[c+1:]
		} else {
			p.User = cred
		}
	}
	p.Addr = strings.TrimRight(v, "/")
	return p, p.Addr != ""
}

func loadSettingsFrom(path string) Settings {
	s := Settings{OutDir: filepath.Join(exeDir(), "received"), ProxyMode: modeAuto, Protect: "account"}
	data, err := os.ReadFile(path)
	if err != nil {
		return s
	}
	legacy := ""
	lostAny, lockedAny := false, false
	open := func(v string) string {
		plain, err := openSecret(v)
		if err == errLocked {
			lockedAny = true
			return ""
		}
		if err != nil {
			lostAny = true
			return ""
		}
		return plain
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
		case "Protect":
			if masterMode(v) {
				s.Protect = "master"
			}
		case "MasterSalt":
			s.MasterSalt = v
		case "MasterCheck":
			s.MasterCheck = v
		case "RelayPass":
			s.RelayPass = open(v)
		case "SaveSendPw":
			s.SaveSendPw = v == "1"
		case "SendPw":
			s.SendPw = open(v)
		case "SaveRecvPw":
			s.SaveRecvPw = v == "1"
		case "RecvPw":
			s.RecvPw = open(v)
		case "Extra":
			s.Extra = v
		case "OutDir":
			s.OutDir = v
		case "Compress":
			s.Compress = v == "1"
		case "ProxyMode":
			if v == modeDirect || v == modeAuto || v == modeProxy {
				s.ProxyMode = v
			}
		case "ProxySel":
			n := 0
			for _, c := range v {
				if c < '0' || c > '9' {
					n = 0
					break
				}
				n = n*10 + int(c-'0')
			}
			s.ProxySel = n
		case "ProxyEntry":
			if p, ok, lost := decodeProxy(v); ok && len(s.Proxies) < maxProxies {
				s.Proxies = append(s.Proxies, p)
				if lost == errLocked {
					lockedAny = true
				} else if lost != nil {
					lostAny = true
				}
			}
		case "Proxy": // формат старых версий
			legacy = v
		}
	}
	if len(s.Proxies) == 0 && legacy != "" {
		if p, ok := legacyProxy(legacy); ok {
			s.Proxies = []ProxyCfg{p}
			s.ProxyMode = modeProxy
			s.ProxySel = 0
		}
	}
	if s.ProxySel < 0 || s.ProxySel >= len(s.Proxies) {
		s.ProxySel = 0
	}
	if !s.SaveSendPw {
		s.SendPw = ""
	}
	if !s.SaveRecvPw {
		s.RecvPw = ""
	}
	s.Locked = lockedAny || (s.Protect == "master" && !vaultUnlocked())
	if lostAny {
		s.SecretNote = "Не удалось расшифровать сохранённые пароли: файл настроек создан на другом компьютере " +
			"или под другим пользователем Windows. Введите пароли заново."
	}
	return s
}

// saveSettingsTo пишет настройки; пароли - только в защищённом виде. Если защитить не удалось,
// пароли не сохраняются (открытым текстом не пишутся никогда), а возвращается ошибка.
func saveSettingsTo(path string, s Settings) error {
	var firstErr error
	seal := func(plain string) string {
		v, err := sealSecret(plain)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			return ""
		}
		return v
	}
	b2s := func(b bool) string {
		if b {
			return "1"
		}
		return "0"
	}
	mode := s.ProxyMode
	if mode != modeDirect && mode != modeProxy {
		mode = modeAuto
	}
	sendPw, recvPw := "", ""
	if s.SaveSendPw {
		sendPw = seal(s.SendPw)
	}
	if s.SaveRecvPw {
		recvPw = seal(s.RecvPw)
	}
	protect, masterLines := "account", ""
	if vaultIsMaster() {
		protect = "master"
		masterLines = "MasterSalt=" + vaultSaltB64() + "\r\nMasterCheck=" + seal(masterCheckPlain) + "\r\n"
	}
	text := "Protect=" + protect + "\r\n" + masterLines +
		"Relay=" + s.Relay + "\r\nRelayPass=" + seal(s.RelayPass) + "\r\nExtra=" + s.Extra +
		"\r\nOutDir=" + s.OutDir + "\r\nCompress=" + b2s(s.Compress) + "\r\nProxyMode=" + mode +
		"\r\nProxySel=" + itoa(s.ProxySel) +
		"\r\nSaveSendPw=" + b2s(s.SaveSendPw) + "\r\nSendPw=" + sendPw +
		"\r\nSaveRecvPw=" + b2s(s.SaveRecvPw) + "\r\nRecvPw=" + recvPw + "\r\n"
	for _, p := range s.Proxies {
		text += "ProxyEntry=" + encodeProxy(p, seal) + "\r\n"
	}
	if old, err := os.ReadFile(path); err == nil && string(old) == text {
		return firstErr
	}
	if err := os.WriteFile(path, []byte(text), 0644); err != nil {
		return err
	}
	return firstErr
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}

func loadSettings() Settings { return loadSettingsFrom(iniPath()) }

// settingsReadOnly: файл защищён мастер-паролем, а он не введён - в этом сеансе ничего не пишем,
// чтобы не затереть сохранённые пароли.
var settingsReadOnly bool

func saveSettingsGuarded(path string, s Settings) error {
	if settingsReadOnly {
		return nil
	}
	return saveSettingsTo(path, s)
}

func saveSettings(s Settings) error { return saveSettingsGuarded(iniPath(), s) }
