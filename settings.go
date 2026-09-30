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

func encodeProxy(p ProxyCfg) string {
	a := "0"
	if p.Auth {
		a = "1"
	}
	parts := []string{normType(p.Type), p.Addr, a, p.User, p.Pass}
	for i := range parts {
		parts[i] = url.QueryEscape(parts[i])
	}
	return strings.Join(parts, "|")
}

func decodeProxy(v string) (ProxyCfg, bool) {
	parts := strings.Split(v, "|")
	if len(parts) != 5 {
		return ProxyCfg{}, false
	}
	for i := range parts {
		u, err := url.QueryUnescape(parts[i])
		if err != nil {
			return ProxyCfg{}, false
		}
		parts[i] = u
	}
	return ProxyCfg{Type: normType(parts[0]), Addr: parts[1], Auth: parts[2] == "1", User: parts[3], Pass: parts[4]}, true
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
	s := Settings{OutDir: filepath.Join(exeDir(), "received"), ProxyMode: modeAuto}
	data, err := os.ReadFile(path)
	if err != nil {
		return s
	}
	legacy := ""
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
			if p, ok := decodeProxy(v); ok && len(s.Proxies) < maxProxies {
				s.Proxies = append(s.Proxies, p)
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
	return s
}

func saveSettingsTo(path string, s Settings) {
	c := "0"
	if s.Compress {
		c = "1"
	}
	mode := s.ProxyMode
	if mode != modeDirect && mode != modeProxy {
		mode = modeAuto
	}
	text := "Relay=" + s.Relay + "\r\nRelayPass=" + s.RelayPass + "\r\nExtra=" + s.Extra +
		"\r\nOutDir=" + s.OutDir + "\r\nCompress=" + c + "\r\nProxyMode=" + mode +
		"\r\nProxySel=" + itoa(s.ProxySel) + "\r\n"
	for _, p := range s.Proxies {
		text += "ProxyEntry=" + encodeProxy(p) + "\r\n"
	}
	if old, err := os.ReadFile(path); err == nil && string(old) == text {
		return
	}
	_ = os.WriteFile(path, []byte(text), 0644)
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

func loadSettings() Settings  { return loadSettingsFrom(iniPath()) }
func saveSettings(s Settings) { saveSettingsTo(iniPath(), s) }
