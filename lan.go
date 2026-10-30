package main

import (
	"bytes"
	"encoding/json"
	"net"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Порты режима обмена. Переменные - чтобы тесты могли подставить свободные.
var (
	lanDiscPort   = 29008
	lanRelayPorts = []string{"29009", "29010", "29011", "29012", "29013"}
)

// instanceID отличает этот запущенный экземпляр программы от других (чтобы не находить самого себя).
var instanceID = randHex(4)

const (
	discQuery = "CROCAU1?"
	discReply = "CROCAU1!"
)

// Роли устройства в сети:
//
//	roleRecv - принимает (режим обмена): отправитель находит его и присылает данные;
//	roleSend - ждёт получателя (отправитель держит у себя порт): получатель находит его и забирает данные.
const (
	roleRecv = "recv"
	roleSend = "send"
)

// Peer - устройство в локальной сети с включённым режимом обмена или ожидающий отправитель.
type Peer struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Port int    `json:"port"`
	Role string `json:"role"`
	IP   string `json:"-"`
}

func (p Peer) Addr() string { return net.JoinHostPort(p.IP, itoa(p.Port)) }

func (p Peer) Label() string {
	l := p.Name + " (" + p.IP
	if itoa(p.Port) != lanRelayPorts[0] {
		l += ":" + itoa(p.Port)
	}
	return l + ")"
}

// startResponder отвечает на поисковые запросы по UDP от имени устройства в роли role.
// Возвращает функцию остановки. Один UDP-порт: одновременно возможна только одна роль на компьютере.
func startResponder(id, role, name string, relayPort int) (func(), error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: lanDiscPort})
	if err != nil {
		return nil, err
	}
	reply, _ := json.Marshal(Peer{ID: id, Name: name, Port: relayPort, Role: role})
	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			msg := string(buf[:n])
			if !strings.HasPrefix(msg, discQuery) {
				continue
			}
			// запрос: CROCAU1?<id спрашивающего>|<нужная роль или пусто>
			asker, want := strings.TrimPrefix(msg, discQuery), ""
			if i := strings.Index(asker, "|"); i >= 0 {
				asker, want = asker[:i], asker[i+1:]
			}
			if strings.TrimSpace(asker) == id {
				continue // собственный запрос
			}
			if w := strings.TrimSpace(want); w != "" && w != role {
				continue // ищут другую роль
			}
			_, _ = conn.WriteToUDP(append([]byte(discReply), reply...), addr)
		}
	}()
	return func() { _ = conn.Close() }, nil
}

// discoverPeers рассылает запрос по targets (host:port) и собирает ответы в течение wait.
// wantRole: roleRecv, roleSend или пусто (любая роль).
func discoverPeers(wait time.Duration, selfID, wantRole string, targets []string) []Peer {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return nil
	}
	defer conn.Close()
	query := []byte(discQuery + selfID + "|" + wantRole)
	seen := map[string]bool{}
	var out []Peer
	buf := make([]byte, 1024)
	for round := 0; round < 2; round++ { // второй раз - на случай потери пакета
		for _, t := range targets {
			if a, err := net.ResolveUDPAddr("udp4", t); err == nil {
				_, _ = conn.WriteToUDP(query, a)
			}
		}
		_ = conn.SetReadDeadline(time.Now().Add(wait / 2))
		for {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				break
			}
			msg := buf[:n]
			if !bytes.HasPrefix(msg, []byte(discReply)) {
				continue
			}
			var p Peer
			if json.Unmarshal(msg[len(discReply):], &p) != nil || p.Port <= 0 || p.Port > 65535 {
				continue
			}
			if p.ID == selfID || (wantRole != "" && p.Role != wantRole) {
				continue
			}
			p.IP = addr.IP.String()
			key := p.IP + "|" + p.ID
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name+out[i].IP < out[j].Name+out[j].IP })
	return out
}

func bcastOf(ip net.IP, mask net.IPMask) net.IP {
	ip4 := ip.To4()
	if ip4 == nil {
		return nil
	}
	if len(mask) == 16 {
		mask = mask[12:]
	}
	if len(mask) != 4 {
		return nil
	}
	b := make(net.IP, 4)
	for i := range b {
		b[i] = ip4[i] | ^mask[i]
	}
	return b
}

// broadcastTargets - широковещательные адреса всех активных интерфейсов (и общий 255.255.255.255).
func broadcastTargets() []string {
	set := map[string]bool{"255.255.255.255": true}
	if ifs, err := net.Interfaces(); err == nil {
		for _, ifc := range ifs {
			if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
				continue
			}
			addrs, _ := ifc.Addrs()
			for _, a := range addrs {
				if n, ok := a.(*net.IPNet); ok {
					if b := bcastOf(n.IP, n.Mask); b != nil {
						set[b.String()] = true
					}
				}
			}
		}
	}
	var out []string
	for ip := range set {
		out = append(out, net.JoinHostPort(ip, itoa(lanDiscPort)))
	}
	sort.Strings(out)
	return out
}

// localIPv4s - адреса этого компьютера в локальных сетях (без loopback).
func localIPv4s() []string {
	var out []string
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				if ip4 := n.IP.To4(); ip4 != nil && !ip4.IsLinkLocalUnicast() {
					out = append(out, ip4.String())
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

var addrRe = regexp.MustCompile(`(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?`)

// parseLANAddr достаёт адрес вида ip[:порт] из текста ("Имя (192.168.1.5)", "192.168.1.5:29009").
func parseLANAddr(text string) (string, bool) {
	m := addrRe.FindStringSubmatch(text)
	if m == nil || net.ParseIP(m[1]) == nil {
		return "", false
	}
	port := lanRelayPorts[0]
	if m[2] != "" {
		n := 0
		for _, c := range m[2] {
			n = n*10 + int(c-'0')
		}
		if n < 1 || n > 65535 {
			return "", false
		}
		port = m[2]
	}
	return net.JoinHostPort(m[1], port), true
}

// ScanPlan - что именно проверяется при поиске устройств: широковещательные и одиночные адреса подсетей.
// Одиночные (unicast) запросы нужны, потому что ответ на широковещательный запрос брандмауэр Windows часто отбрасывает
// (ответ приходит не с того адреса, на который был отправлен запрос), а ответ на адресный запрос пропускает.
type ScanPlan struct {
	Targets []string // host:port для отправки запроса
	Lines   []string // человекочитаемое описание (интерфейсы и диапазоны)
	Hosts   int      // число проверяемых одиночных адресов
}

// hostsIn перечисляет адреса подсети ip/mask (без адреса сети и широковещательного). Широкие сети (шире /22) сужаются
// до /24 вокруг адреса ip, чтобы не рассылать тысячи пакетов.
func hostsIn(ip net.IP, mask net.IPMask) []net.IP {
	ip4 := ip.To4()
	if ip4 == nil {
		return nil
	}
	if len(mask) == 16 {
		mask = mask[12:]
	}
	ones, bits := mask.Size()
	if bits != 32 || ones >= 31 {
		return nil
	}
	if ones < 22 {
		ones = 24
		mask = net.CIDRMask(24, 32)
	}
	base := ip4.Mask(mask)
	count := 1 << uint(32-ones)
	var out []net.IP
	for i := 1; i < count-1; i++ {
		h := make(net.IP, 4)
		copy(h, base)
		v := uint32(i)
		h[0] |= byte(v >> 24)
		h[1] |= byte(v >> 16)
		h[2] |= byte(v >> 8)
		h[3] |= byte(v)
		out = append(out, h)
	}
	return out
}

func planScan() ScanPlan { return planScanPort(lanDiscPort) }

func planScanPort(port int) ScanPlan {
	var plan ScanPlan
	own := map[string]bool{}
	seen := map[string]bool{}
	add := func(host string) {
		if !seen[host] {
			seen[host] = true
			plan.Targets = append(plan.Targets, net.JoinHostPort(host, itoa(port)))
		}
	}
	type ifa struct {
		name string
		n    *net.IPNet
	}
	var list []ifa
	if ifs, err := net.Interfaces(); err == nil {
		for _, ifc := range ifs {
			if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
				continue
			}
			addrs, _ := ifc.Addrs()
			for _, a := range addrs {
				if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil {
					own[n.IP.To4().String()] = true
					list = append(list, ifa{ifc.Name, n})
				}
			}
		}
	}
	add("255.255.255.255")
	for _, it := range list {
		if b := bcastOf(it.n.IP, it.n.Mask); b != nil {
			add(b.String())
		}
	}
	for _, it := range list {
		hs := hostsIn(it.n.IP, it.n.Mask)
		n := 0
		first, last := "", ""
		for _, h := range hs {
			if own[h.String()] {
				continue
			}
			add(h.String())
			n++
			if first == "" {
				first = h.String()
			}
			last = h.String()
		}
		ones, _ := it.n.Mask.Size()
		line := it.name + ": " + it.n.IP.String() + "/" + itoa(ones)
		if n > 0 {
			line += " - проверяю " + itoa(n) + " адресов (" + first + " - " + last + ")"
		} else {
			line += " - только широковещательный запрос"
		}
		plan.Lines = append(plan.Lines, line)
		plan.Hosts += n
	}
	sort.Strings(plan.Targets)
	return plan
}
