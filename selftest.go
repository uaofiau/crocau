package main

import (
	"archive/zip"
	"bytes"
	crand "crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

func testLogf(format string, a ...interface{}) {
	line := fmt.Sprintf(format, a...)
	fmt.Println(line)
	if p := os.Getenv("CROCAU_TESTLOG"); p != "" {
		if f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
			f.WriteString(line + "\r\n")
			f.Close()
		}
	}
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = crand.Read(b)
	return b
}

func fileEquals(path string, want []byte) bool {
	got, err := os.ReadFile(path)
	return err == nil && bytes.Equal(got, want)
}

func startTestRelay() (*Job, error) {
	work, err := newWork()
	if err != nil {
		return nil, err
	}
	j := startJob(JobSpec{Work: work, MkArgs: func(string) []string {
		return []string{"relay", "--port", "19009", "--ports", "19009,19010,19011,19012,19013"}
	}})
	time.Sleep(2 * time.Second)
	return j, nil
}

// transfer отправляет и принимает одной парой процессов, возвращает результат приёма.
func transfer(s Settings, sendPw, recvPw, text string, items []string, dst string, recvWait time.Duration) (ok bool, res RecvResult, snd, rcv *Job) {
	snd, err := startSend(s, sendPw, text, items)
	if err != nil {
		testLogf("startSend error: %v", err)
		return false, res, nil, nil
	}
	time.Sleep(1500 * time.Millisecond)
	rcv, created, err := startReceive(s, recvPw, dst)
	if err != nil {
		testLogf("startReceive error: %v", err)
		snd.Kill()
		return false, res, snd, nil
	}
	ok = rcv.Wait(recvWait)
	snd.Wait(30 * time.Second)
	res = finalizeReceive(rcv, dst, created)
	return ok && rcv.ExitCode() == 0, res, snd, rcv
}

func selfTest() int {
	fails := 0
	relay, err := startTestRelay()
	if err != nil {
		testLogf("relay start error: %v", err)
		return 1
	}
	defer relay.Kill()
	s := Settings{Relay: "127.0.0.1:19009"}

	src, _ := newWork()
	f1 := filepath.Join(src, "файл один.bin")
	data := randBytes(1 << 20)
	_ = os.WriteFile(f1, data, 0644)
	dir := filepath.Join(src, "папка")
	_ = os.MkdirAll(filepath.Join(dir, "sub"), 0755)
	_ = os.WriteFile(filepath.Join(dir, "sub", "a.txt"), []byte("hello"), 0644)
	text := "Привет, мир!\r\nСтрока 2 \"кавычки\" & % ^ \\ конец"

	// 1) текст + файл + папка одной передачей, пароль из 3 символов
	dst1, _ := newWork()
	ok, res, snd, rcv := transfer(s, "abc", "abc", text, []string{f1, dir}, dst1, 90*time.Second)
	if ok && res.Text == text && fileEquals(filepath.Join(dst1, "файл один.bin"), data) &&
		fileEquals(filepath.Join(dst1, "папка", "sub", "a.txt"), []byte("hello")) && !fileExists(filepath.Join(dst1, textFileName)) {
		testLogf("MIXED (text+file+folder, pw 3 chars): OK")
	} else {
		fails++
		testLogf("MIXED: FAIL text=%q", res.Text)
		dumpLogs(snd, rcv)
	}

	// 2) только текст, пароль из 3 символов
	dst2, _ := newWork()
	ok, res, snd, rcv = transfer(s, "q7z", "q7z", "только текст", nil, dst2, 60*time.Second)
	if ok && res.Text == "только текст" && !res.HasFiles && !fileExists(dst2) {
		testLogf("TEXT ONLY: OK")
	} else if ok && res.Text == "только текст" && !res.HasFiles {
		testLogf("TEXT ONLY: OK (dir kept)")
	} else {
		fails++
		testLogf("TEXT ONLY: FAIL text=%q hasFiles=%v", res.Text, res.HasFiles)
		dumpLogs(snd, rcv)
	}

	// 3) только файл, длинный пароль (комната по хэшу)
	dst3, _ := newWork()
	ok, res, snd, rcv = transfer(s, "длинный-пароль-123", "длинный-пароль-123", "", []string{f1}, dst3, 90*time.Second)
	if ok && res.Text == "" && res.HasFiles && fileEquals(filepath.Join(dst3, "файл один.bin"), data) {
		testLogf("FILE ONLY (long password): OK")
	} else {
		fails++
		testLogf("FILE ONLY: FAIL")
		dumpLogs(snd, rcv)
	}

	// 4) неверный пароль: ничего не должно прийти
	dst4, _ := newWork()
	_, res, snd, rcv = transfer(s, "aaa", "bbb", "секрет", nil, dst4, 25*time.Second)
	if snd != nil {
		snd.Kill()
	}
	if res.Text == "" && countEntries(dst4) == 0 {
		testLogf("WRONG PASSWORD: OK (nothing received)")
	} else {
		fails++
		testLogf("WRONG PASSWORD: FAIL text=%q", res.Text)
	}

	// 4b) перебор relay: первый адрес мёртв, второй - наш тестовый relay
	os.Setenv("CROCAU_RELAYS", "127.0.0.1:19008,127.0.0.1:19009")
	dstF, _ := newWork()
	ok, res, snd, rcv = transfer(Settings{}, "fb1", "fb1", "через запасной relay", nil, dstF, 60*time.Second)
	os.Unsetenv("CROCAU_RELAYS")
	if ok && res.Text == "через запасной relay" {
		testLogf("RELAY FALLBACK: OK")
	} else {
		fails++
		testLogf("RELAY FALLBACK: FAIL text=%q", res.Text)
		dumpLogs(snd, rcv)
	}

	// 6) сжатие: единый архив, смешанное содержимое, автоматическая распаковка
	{
		asrc, _ := newWork()
		comp := bytes.Repeat([]byte("строка для сжатия 0123456789\n"), 20000)
		rnd := randBytes(300000)
		_ = os.WriteFile(filepath.Join(asrc, "текст.txt"), comp, 0644)
		_ = os.WriteFile(filepath.Join(asrc, "случайный.bin"), rnd, 0644)
		_ = os.WriteFile(filepath.Join(asrc, "video.mp4"), comp, 0644)
		_ = os.MkdirAll(filepath.Join(asrc, "папка2", "вложенная"), 0755)
		_ = os.WriteFile(filepath.Join(asrc, "папка2", "вложенная", "i.txt"), []byte("inner"), 0644)
		atext := "текст вместе с архивом\r\nвторая строка"
		items := []string{filepath.Join(asrc, "текст.txt"), filepath.Join(asrc, "случайный.bin"),
			filepath.Join(asrc, "video.mp4"), filepath.Join(asrc, "папка2")}

		// 6a) методы сжатия внутри архива
		zp, err := buildArchive(nil, asrc, atext, items)
		methodsOK := false
		if err == nil {
			if zr, e2 := zip.OpenReader(zp); e2 == nil {
				m := map[string]*zip.File{}
				for _, f := range zr.File {
					m[f.Name] = f
				}
				t, r, v := m["текст.txt"], m["случайный.bin"], m["video.mp4"]
				methodsOK = t != nil && r != nil && v != nil && m[textFileName] != nil &&
					t.Method == zip.Deflate && t.CompressedSize64 < t.UncompressedSize64/5 &&
					r.Method == zip.Store && v.Method == zip.Store
				zr.Close()
			}
		}
		if methodsOK {
			testLogf("ARCHIVE METHODS (deflate / store by content / store by extension): OK")
		} else {
			fails++
			testLogf("ARCHIVE METHODS: FAIL err=%v", err)
		}

		// 6b) полная передача со сжатием
		sc := s
		sc.Compress = true
		dstA, _ := newWork()
		ok, res, snd, rcv := transfer(sc, "zip", "zip", atext, items, dstA, 90*time.Second)
		leftover := false
		if es, e := os.ReadDir(dstA); e == nil {
			for _, e := range es {
				if strings.HasSuffix(e.Name(), archiveSuffix) {
					leftover = true
				}
			}
		}
		if ok && res.Text == atext && !leftover &&
			fileEquals(filepath.Join(dstA, "текст.txt"), comp) && fileEquals(filepath.Join(dstA, "случайный.bin"), rnd) &&
			fileEquals(filepath.Join(dstA, "video.mp4"), comp) &&
			fileEquals(filepath.Join(dstA, "папка2", "вложенная", "i.txt"), []byte("inner")) &&
			snd != nil && strings.Contains(snd.Log(), "Архив:") {
			testLogf("COMPRESSED TRANSFER (auto unpack): OK")
		} else {
			fails++
			testLogf("COMPRESSED TRANSFER: FAIL text=%q leftover=%v", res.Text, leftover)
			dumpLogs(snd, rcv)
		}

		// 6c) защита от записи за пределы папки (zip-slip)
		base, _ := newWork()
		out := filepath.Join(base, "out")
		_ = os.MkdirAll(out, 0755)
		bad := []string{"../evil.txt", "..\\evil2.txt", "/abs.txt", "C:/x.txt", "ok/../../evil5.txt"}
		slipOK := true
		for _, name := range bad {
			zf := filepath.Join(base, "bad.zip")
			f, _ := os.Create(zf)
			zw := zip.NewWriter(f)
			w, _ := zw.Create(name)
			_, _ = w.Write([]byte("x"))
			_ = zw.Close()
			_ = f.Close()
			if err := extractZip(nil, zf, out); err == nil {
				slipOK = false
			}
		}
		for _, n := range []string{"evil.txt", "evil2.txt", "evil5.txt", "abs.txt", "x.txt"} {
			if fileExists(filepath.Join(base, n)) || fileExists(filepath.Join(out, n)) {
				slipOK = false
			}
		}
		if slipOK {
			testLogf("ZIP-SLIP PROTECTION: OK")
		} else {
			fails++
			testLogf("ZIP-SLIP PROTECTION: FAIL")
		}
	}

	// 7) сохранение настроек (включая спецсимволы) и перенос старого формата
	{
		tmp, _ := newWork()
		ini := filepath.Join(tmp, "t.ini")
		orig := Settings{Relay: "a:1", RelayPass: "x", Extra: "--no-multi", OutDir: `C:\Тест`, Compress: true,
			ProxyMode: modeProxy, ProxySel: 1, Proxies: []ProxyCfg{
				{Type: "socks5", Addr: "1.2.3.4:1080"},
				{Type: "http", Addr: "h.example:8080", Auth: true, User: "u|s er", Pass: "p&a=s%s|"},
				{Type: "socks4", Addr: "5.6.7.8:1081", Auth: true, User: "id"}}}
		saveSettingsTo(ini, orig)
		got := loadSettingsFrom(ini)
		ini2 := filepath.Join(tmp, "old.ini")
		_ = os.WriteFile(ini2, []byte("Relay=z\r\nProxy=socks5://bob:pw@9.9.9.9:1080\r\n"), 0644)
		old := loadSettingsFrom(ini2)
		if reflect.DeepEqual(orig, got) && old.ProxyMode == modeProxy && len(old.Proxies) == 1 &&
			old.Proxies[0] == (ProxyCfg{Type: "socks5", Addr: "9.9.9.9:1080", Auth: true, User: "bob", Pass: "pw"}) {
			testLogf("SETTINGS SAVE/LOAD + LEGACY MIGRATION: OK")
		} else {
			fails++
			testLogf("SETTINGS: FAIL got=%+v old=%+v", got, old)
		}
	}

	// 8) прокси: SOCKS5 (логин), SOCKS4, HTTP (логин), авто-режим, неверный пароль, проверка доступности
	{
		resolve := map[string]string{"relay.test": "127.0.0.1"}
		p5 := startTestSocks5("u5", "p5", resolve)
		p4 := startTestSocks4("id4", resolve)
		ph := startTestHTTP("uh", "ph", resolve)
		if p5 == nil || p4 == nil || ph == nil {
			fails++
			testLogf("PROXY: test servers failed to start")
		} else {
			defer p5.Close()
			defer p4.Close()
			defer ph.Close()
			relayName := "relay.test:19009"
			c5 := ProxyCfg{Type: "socks5", Addr: p5.Addr, Auth: true, User: "u5", Pass: "p5"}
			c4 := ProxyCfg{Type: "socks4", Addr: p4.Addr, Auth: true, User: "id4"}
			ch := ProxyCfg{Type: "http", Addr: ph.Addr, Auth: true, User: "uh", Pass: "ph"}
			dead := ProxyCfg{Type: "socks5", Addr: "127.0.0.1:1"}
			bad5 := ProxyCfg{Type: "socks5", Addr: p5.Addr, Auth: true, User: "u5", Pass: "WRONG"}

			run := func(name string, st Settings, pw string, wantOK bool, wait time.Duration) {
				st.Relay = relayName
				dst, _ := newWork()
				ok, res, snd, rcv := transfer(st, pw, pw, "через прокси: "+name, nil, dst, wait)
				got := ok && res.Text == "через прокси: "+name
				if snd != nil && !wantOK {
					snd.Kill()
				}
				if got == wantOK {
					testLogf("PROXY %s: OK", name)
				} else {
					fails++
					testLogf("PROXY %s: FAIL (ok=%v text=%q)", name, ok, res.Text)
					dumpLogs(snd, rcv)
				}
			}
			run("socks5+auth", Settings{ProxyMode: modeProxy, Proxies: []ProxyCfg{c5}}, "px5", true, 60*time.Second)
			run("socks4", Settings{ProxyMode: modeProxy, Proxies: []ProxyCfg{c4}}, "px4", true, 60*time.Second)
			run("http+auth", Settings{ProxyMode: modeProxy, Proxies: []ProxyCfg{ch}}, "pxh", true, 60*time.Second)
			run("auto (direct fails, dead proxy, http works)", Settings{ProxyMode: modeAuto, Proxies: []ProxyCfg{dead, ch}}, "pxa", true, 90*time.Second)
			run("direct mode cannot reach relay.test", Settings{ProxyMode: modeDirect, Proxies: []ProxyCfg{c5}}, "pxd", false, 30*time.Second)
			run("wrong password on proxy", Settings{ProxyMode: modeProxy, Proxies: []ProxyCfg{bad5}}, "pxw", false, 30*time.Second)

			// проверка доступности
			okProbe := true
			for _, c := range []ProxyCfg{c5, c4, ch} {
				cc := c
				if _, err := probe(Route{P: &cc}, relayName, 4*time.Second); err != nil {
					okProbe = false
					testLogf("probe via %s failed: %v", cc.Type, err)
				}
			}
			if _, err := probe(Route{}, "127.0.0.1:19009", 4*time.Second); err != nil {
				okProbe = false
				testLogf("direct probe failed: %v", err)
			}
			if _, err := probe(Route{}, relayName, 2*time.Second); err == nil {
				okProbe = false
				testLogf("direct probe to relay.test unexpectedly succeeded")
			}
			b5 := bad5
			if _, err := probe(Route{P: &b5}, relayName, 4*time.Second); err == nil || !strings.Contains(err.Error(), "логин") {
				okProbe = false
				testLogf("wrong-auth probe: %v", err)
			}
			if okProbe {
				testLogf("PROXY CHECK (probe): OK")
			} else {
				fails++
				testLogf("PROXY CHECK (probe): FAIL")
			}
		}
	}

	// 5) не должно появляться croc-config рядом с exe
	if fileExists(filepath.Join(exeDir(), "croc-config")) {
		fails++
		testLogf("NO croc-config: FAIL")
	} else {
		testLogf("NO croc-config: OK")
	}

	if fails == 0 {
		testLogf("SELFTEST PASSED")
		return 0
	}
	testLogf("SELFTEST FAILED (%d)", fails)
	return 1
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func dumpLogs(snd, rcv *Job) {
	if snd != nil {
		testLogf("--- sender log ---\r\n%s", snd.Log())
	}
	if rcv != nil {
		testLogf("--- receiver log ---\r\n%s", rcv.Log())
	}
}

// netTest - передача текста через реальные публичные relay (для диагностики из CI).
func netTest() int {
	probes := checkAll([]Route{{}}, publicRelays, 4*time.Second)
	for k, r := range publicRelays {
		if probes[0][k].Err != nil {
			testLogf("probe %s: FAIL %v", r, probes[0][k].Err)
		} else {
			testLogf("probe %s: OK %d ms", r, probes[0][k].RTT.Milliseconds())
		}
	}
	text := "проверка публичных relay"
	dst, _ := newWork()
	pw := "net" + randomPassword()
	ok, res, snd, rcv := transfer(Settings{}, pw, pw, text, nil, dst, 90*time.Second)
	if snd != nil {
		testLogf("--- sender ---\r\n%s", snd.Log())
	}
	if rcv != nil {
		testLogf("--- receiver ---\r\n%s", rcv.Log())
	}
	if ok && res.Text == text {
		testLogf("NETTEST: OK")
		return 0
	}
	testLogf("NETTEST: FAIL")
	return 1
}
