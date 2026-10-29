package main

import (
	"archive/zip"
	"bytes"
	"context"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
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

// fakeSeal/fakeOpen - обратимая подделка защиты для систем без DPAPI (только для самотеста).
func fakeSeal(plain string) (string, error) {
	b := []byte(plain)
	sum := sha256.Sum256(b)
	out := append(append([]byte{}, sum[:4]...), b...)
	for i := range out {
		out[i] ^= 0x5A
	}
	return sealPrefix + base64.StdEncoding.EncodeToString(out), nil
}

func fakeOpen(v string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(v, sealPrefix))
	if err != nil || len(raw) < 4 {
		return "", errors.New("повреждённые данные")
	}
	for i := range raw {
		raw[i] ^= 0x5A
	}
	sum := sha256.Sum256(raw[4:])
	if !bytes.Equal(sum[:4], raw[:4]) {
		return "", errors.New("повреждённые данные")
	}
	return string(raw[4:]), nil
}

func selfTest() int {
	fails := 0
	if _, err := platformSeal("проверка"); err != nil {
		sealImpl, openImpl = fakeSeal, fakeOpen
		testLogf("SECRETS: платформенной защиты здесь нет, используется тестовая подделка")
	} else {
		testLogf("SECRETS: используется настоящая защита системы (DPAPI)")
	}
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
		zp, err := buildArchive(nil, asrc, atext, "", items)
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

		// 6b2) только текст (300 КБ), со сжатием: тоже уходит архивом и приходит целым
		{
			big := strings.Repeat("длинный текст для проверки сжатия и размера 0123456789\r\n", 6000)
			dstT, _ := newWork()
			ok, res, snd, rcv := transfer(sc, "tz1", "tz1", big, nil, dstT, 90*time.Second)
			if ok && res.Text == big && !res.HasFiles && snd != nil && strings.Contains(snd.Log(), "Архив:") {
				testLogf("COMPRESSED TEXT ONLY (%d chars): OK", len([]rune(big)))
			} else {
				fails++
				testLogf("COMPRESSED TEXT ONLY: FAIL (len=%d, files=%v)", len(res.Text), res.HasFiles)
				dumpLogs(snd, rcv)
			}
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
		orig := Settings{Relay: "a:1", RelayPass: "r&p|=%", Extra: "--no-multi", OutDir: `C:\Тест`, Compress: true,
			SaveSendPw: true, SendPw: "s3nd pw+я",
			ProxyMode: modeProxy, ProxySel: 1, Protect: "account", Proxies: []ProxyCfg{
				{Type: "socks5", Addr: "1.2.3.4:1080"},
				{Type: "http", Addr: "h.example:8080", Auth: true, User: "u|s er", Pass: "p&a=s%s|"},
				{Type: "socks4", Addr: "5.6.7.8:1081", Auth: true, User: "id"}}}
		if err := saveSettingsTo(ini, orig); err != nil {
			testLogf("save error: %v", err)
		}
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

	// 7b) пароли в файле только в защищённом виде; старый открытый формат переносится; порча/чужой компьютер
	{
		tmp, _ := newWork()
		ini := filepath.Join(tmp, "p.ini")
		st := Settings{RelayPass: "relay-secret-1", SaveSendPw: true, SendPw: "send-secret-2", SaveRecvPw: false, RecvPw: "recv-secret-3",
			ProxyMode: modeAuto, Proxies: []ProxyCfg{{Type: "http", Addr: "h:1", Auth: true, User: "u", Pass: "proxy-secret-4"}}}
		_ = saveSettingsTo(ini, st)
		raw, _ := os.ReadFile(ini)
		leak := false
		for _, w := range []string{"relay-secret-1", "send-secret-2", "recv-secret-3", "proxy-secret-4"} {
			if strings.Contains(string(raw), w) {
				leak = true
			}
		}
		back := loadSettingsFrom(ini)
		restored := back.RelayPass == "relay-secret-1" && back.SendPw == "send-secret-2" && back.RecvPw == "" &&
			len(back.Proxies) == 1 && back.Proxies[0].Pass == "proxy-secret-4" && back.SecretNote == ""

		// старый формат (открытый текст) читается и после сохранения больше не лежит открытым
		legacy := filepath.Join(tmp, "legacy.ini")
		_ = os.WriteFile(legacy, []byte("RelayPass=oldplain-5\r\nProxyEntry=http|h%3A1|1|u|oldplain-6\r\n"), 0644)
		lg := loadSettingsFrom(legacy)
		legacyOK := lg.RelayPass == "oldplain-5" && len(lg.Proxies) == 1 && lg.Proxies[0].Pass == "oldplain-6" && lg.SecretNote == ""
		_ = saveSettingsTo(legacy, lg)
		raw2, _ := os.ReadFile(legacy)
		if strings.Contains(string(raw2), "oldplain-5") || strings.Contains(string(raw2), "oldplain-6") {
			legacyOK = false
		}

		// порча защищённого значения (так же выглядит файл с другого компьютера)
		lines := strings.Split(string(raw), "\r\n")
		for i, l := range lines {
			if strings.HasPrefix(l, "SendPw="+sealPrefix) {
				r := []rune(l)
				mid := len(r) - 12
				if r[mid] == 'A' {
					r[mid] = 'B'
				} else {
					r[mid] = 'A'
				}
				lines[i] = string(r)
			}
		}
		bad := filepath.Join(tmp, "bad.ini")
		_ = os.WriteFile(bad, []byte(strings.Join(lines, "\r\n")), 0644)
		bd := loadSettingsFrom(bad)
		tamperOK := bd.SendPw == "" && bd.SecretNote != "" && bd.RelayPass == "relay-secret-1"

		// если защита недоступна, пароли не пишутся вообще (и не открытым текстом)
		realSeal, realOpen := sealImpl, openImpl
		sealImpl = func(string) (string, error) { return "", errors.New("нет защиты") }
		noSeal := filepath.Join(tmp, "noseal.ini")
		errSave := saveSettingsTo(noSeal, st)
		raw3, _ := os.ReadFile(noSeal)
		sealImpl, openImpl = realSeal, realOpen
		noPlain := errSave != nil && !strings.Contains(string(raw3), "secret")

		if !leak && restored && legacyOK && tamperOK && noPlain {
			testLogf("PASSWORD PROTECTION (no plaintext, legacy migration, tamper, no-seal): OK")
		} else {
			fails++
			testLogf("PASSWORD PROTECTION: FAIL leak=%v restored=%v legacy=%v tamper=%v noPlain=%v", leak, restored, legacyOK, tamperOK, noPlain)
		}
	}

	// 7e) путь приёма относительно программы: переносится вместе с папкой программы
	{
		tmp, _ := newWork()
		appA := filepath.Join(tmp, "A", "app")
		appB := filepath.Join(tmp, "B", "другое место")
		_ = os.MkdirAll(appA, 0755)
		_ = os.MkdirAll(appB, 0755)
		ini := filepath.Join(tmp, "o.ini")
		oldOverride := exeDirOverride
		exeDirOverride = appA
		inside := filepath.Join(appA, "received")
		outside := filepath.Join(tmp, "A", "общая загрузка")
		_ = saveSettingsTo(ini, Settings{OutDir: inside, OutRel: true})
		raw1, _ := os.ReadFile(ini)
		relStored := strings.Contains(string(raw1), "OutDir=received\r\n") && strings.Contains(string(raw1), "OutDirRelative=1")
		_ = saveSettingsTo(ini, Settings{OutDir: outside, OutRel: true})
		upStored := loadSettingsFrom(ini).OutDir == filepath.Join("..", "общая загрузка")
		_ = saveSettingsTo(ini, Settings{OutDir: inside, OutRel: false})
		absStored := loadSettingsFrom(ini).OutDir == inside && !loadSettingsFrom(ini).OutRel
		_ = saveSettingsTo(ini, Settings{OutDir: inside, OutRel: true})
		// "перенос": тот же файл настроек, но программа лежит в другом месте
		exeDirOverride = appB
		moved := resolveOutDir(loadSettingsFrom(ini).OutDir) == filepath.Join(appB, "received")
		exeDirOverride = appA
		_ = saveSettingsTo(ini, Settings{OutDir: outside, OutRel: true})
		exeDirOverride = appB
		movedUp := resolveOutDir(loadSettingsFrom(ini).OutDir) == filepath.Join(tmp, "B", "общая загрузка")
		exeDirOverride = appA
		emptyOK := resolveOutDir("") == filepath.Join(appA, "received") && resolveOutDir("sub") == filepath.Join(appA, "sub")
		exeDirOverride = oldOverride
		if relStored && upStored && absStored && moved && movedUp && emptyOK {
			testLogf("PORTABLE RECEIVE FOLDER (relative to program, follows the program, absolute when unticked): OK")
		} else {
			fails++
			testLogf("PORTABLE RECEIVE FOLDER: FAIL stored=%v up=%v abs=%v moved=%v movedUp=%v empty=%v", relStored, upStored, absStored, moved, movedUp, emptyOK)
		}
	}

	// 7c) мастер-пароль: шифрование, блокировка, неверный пароль, переносимость, смена, отключение, режим "только чтение"
	{
		tmp, _ := newWork()
		ini := filepath.Join(tmp, "m.ini")
		base := Settings{RelayPass: "relay-secret-1", SaveSendPw: true, SendPw: "send-secret-2", ProxyMode: modeAuto,
			Proxies: []ProxyCfg{{Type: "http", Addr: "h:1", Auth: true, User: "u", Pass: "proxy-secret-4"}}}
		_ = saveSettingsTo(ini, base) // сначала защита системой
		loaded := loadSettingsFrom(ini)
		migrateStart := loaded.SendPw == "send-secret-2"
		if err := masterEnable("мастер-пароль-1"); err != nil {
			testLogf("masterEnable: %v", err)
		}
		_ = saveSettingsTo(ini, loaded) // пере-шифровано мастер-паролем
		raw, _ := os.ReadFile(ini)
		txt := string(raw)
		formatOK := strings.Contains(txt, "Protect=master") && strings.Contains(txt, "MasterSalt=") &&
			strings.Contains(txt, "MasterCheck="+mkPrefix) && !strings.Contains(txt, sealPrefix) &&
			!strings.Contains(txt, "secret-")
		// "перезапуск": сейф закрыт
		masterDisable()
		lk := loadSettingsFrom(ini)
		lockedOK := lk.Locked && lk.Protect == "master" && lk.SendPw == "" && lk.RelayPass == "" && lk.SecretNote == "" &&
			len(lk.Proxies) == 1 && lk.Proxies[0].Addr == "h:1" && lk.Proxies[0].Pass == ""
		wrongOK := masterUnlock("не тот пароль", lk.MasterSalt, lk.MasterCheck) == errWrongMaster && !vaultUnlocked()
		rightErr := masterUnlock("мастер-пароль-1", lk.MasterSalt, lk.MasterCheck)
		un := loadSettingsFrom(ini)
		unlockOK := rightErr == nil && !un.Locked && un.SendPw == "send-secret-2" && un.RelayPass == "relay-secret-1" &&
			len(un.Proxies) == 1 && un.Proxies[0].Pass == "proxy-secret-4"
		// переносимость: копия файла в другой папке открывается тем же паролем
		other := filepath.Join(tmp, "elsewhere.ini")
		_ = os.WriteFile(other, raw, 0644)
		masterDisable()
		lk2 := loadSettingsFrom(other)
		portOK := masterUnlock("мастер-пароль-1", lk2.MasterSalt, lk2.MasterCheck) == nil && loadSettingsFrom(other).SendPw == "send-secret-2"
		// смена мастер-пароля
		_ = masterEnable("новый-пароль-2")
		_ = saveSettingsTo(ini, un)
		raw2, _ := os.ReadFile(ini)
		masterDisable()
		lk3 := loadSettingsFrom(ini)
		changeOK := string(raw2) != txt && masterUnlock("мастер-пароль-1", lk3.MasterSalt, lk3.MasterCheck) == errWrongMaster &&
			masterUnlock("новый-пароль-2", lk3.MasterSalt, lk3.MasterCheck) == nil && loadSettingsFrom(ini).SendPw == "send-secret-2"
		// порча значения
		lines := strings.Split(string(raw2), "\r\n")
		for i, l := range lines {
			if strings.HasPrefix(l, "SendPw="+mkPrefix) {
				r := []rune(l)
				mid := len(r) - 12
				if r[mid] == 'A' {
					r[mid] = 'B'
				} else {
					r[mid] = 'A'
				}
				lines[i] = string(r)
			}
		}
		bad := filepath.Join(tmp, "bad.ini")
		_ = os.WriteFile(bad, []byte(strings.Join(lines, "\r\n")), 0644)
		bd := loadSettingsFrom(bad)
		tamperOK := bd.SendPw == "" && bd.SecretNote != "" && bd.RelayPass == "relay-secret-1"
		// режим "только чтение" (мастер-пароль не введён): файл не меняется
		settingsReadOnly = true
		before, _ := os.ReadFile(ini)
		_ = saveSettingsGuarded(ini, Settings{})
		after, _ := os.ReadFile(ini)
		settingsReadOnly = false
		roOK := bytes.Equal(before, after)
		// отключение: пароли снова защищены системой и читаются без мастер-пароля
		masterDisable()
		_ = saveSettingsTo(ini, un)
		raw3, _ := os.ReadFile(ini)
		offOK := strings.Contains(string(raw3), "Protect=account") && strings.Contains(string(raw3), sealPrefix) &&
			!strings.Contains(string(raw3), mkPrefix) && loadSettingsFrom(ini).SendPw == "send-secret-2"
		masterDisable()
		if migrateStart && formatOK && lockedOK && wrongOK && unlockOK && portOK && changeOK && tamperOK && roOK && offOK {
			testLogf("MASTER PASSWORD (encrypt, lock, wrong pw, portable, change, tamper, read-only, disable): OK")
		} else {
			fails++
			testLogf("MASTER PASSWORD: FAIL migrate=%v format=%v locked=%v wrong=%v unlock=%v portable=%v change=%v tamper=%v readonly=%v off=%v",
				migrateStart, formatOK, lockedOK, wrongOK, unlockOK, portOK, changeOK, tamperOK, roOK, offOK)
		}
	}

	// 7d) подсказка к умному сжатию перечисляет все не сжимаемые расширения
	{
		h := smartCompressHint()
		all := true
		for e := range storedExt {
			if !strings.Contains(h, e) {
				all = false
			}
		}
		if all && len(storedExt) > 40 && strings.Count(h, "\r\n") >= 6 {
			testLogf("SMART COMPRESSION HINT (%d extensions listed): OK", len(storedExt))
		} else {
			fails++
			testLogf("SMART COMPRESSION HINT: FAIL")
		}
	}

	// 9) локальная сеть: поиск устройств, передача через сетевой адрес, режим непрерывного обмена
	{
		oldPorts, oldDisc := lanRelayPorts, lanDiscPort
		lanRelayPorts = []string{"29109", "29110", "29111", "29112", "29113"}
		lanDiscPort = 29108
		skipFirewall = true

		// 9a) поиск устройств (ответчик + запрос), расчёт широковещательных адресов, разбор адреса
		stopResp, rerr := startResponder("peer-1", roleRecv, "Тестовый ПК", 29109)
		peers := discoverPeers(1200*time.Millisecond, "me-1", roleRecv, []string{"127.0.0.1:29108"})
		wrongRole := discoverPeers(800*time.Millisecond, "me-1", roleSend, []string{"127.0.0.1:29108"})
		anyRole := discoverPeers(800*time.Millisecond, "me-1", "", []string{"127.0.0.1:29108"})
		own := discoverPeers(800*time.Millisecond, "peer-1", roleRecv, []string{"127.0.0.1:29108"})
		if stopResp != nil {
			stopResp()
		}
		discOK := rerr == nil && len(peers) == 1 && peers[0].Name == "Тестовый ПК" && peers[0].Port == 29109 &&
			peers[0].IP == "127.0.0.1" && peers[0].Role == roleRecv && len(own) == 0 && len(wrongRole) == 0 && len(anyRole) == 1
		bc1, bc2 := bcastOf(net.ParseIP("192.168.1.37"), net.CIDRMask(24, 32)), bcastOf(net.ParseIP("10.1.2.3"), net.CIDRMask(20, 32))
		bcOK := bc1 != nil && bc1.String() == "192.168.1.255" && bc2 != nil && bc2.String() == "10.1.15.255"
		a1, ok1 := parseLANAddr("Мой ПК (192.168.1.5)")
		a2, ok2 := parseLANAddr("10.0.0.2:3000")
		_, ok3 := parseLANAddr("не адрес")
		_, ok4 := parseLANAddr("300.1.1.1")
		parseOK := ok1 && a1 == "192.168.1.5:29109" && ok2 && a2 == "10.0.0.2:3000" && !ok3 && !ok4
		if discOK && bcOK && parseOK {
			testLogf("LAN DISCOVERY (responder, query, self-filter, broadcast calc, address parse): OK")
		} else {
			fails++
			testLogf("LAN DISCOVERY: FAIL disc=%v(%d peers) bcast=%v parse=%v err=%v", discOK, len(peers), bcOK, parseOK, rerr)
		}

		// 9b) передача через сетевой (не loopback) адрес этого компьютера
		lsrc, _ := newWork()
		lf := filepath.Join(lsrc, "lan файл.bin")
		ldata := randBytes(500000)
		_ = os.WriteFile(lf, ldata, 0644)
		if ips := localIPv4s(); len(ips) == 0 {
			testLogf("LAN TRANSFER via network address: пропущено (нет сетевых адресов)")
		} else {
			lwork, _ := newWork()
			lrelay := startJob(JobSpec{Work: lwork, MkArgs: func(string) []string {
				return []string{"relay", "--port", "29109", "--ports", "29109,29110,29111,29112,29113"}
			}})
			up := waitTCP(ips[0]+":29109", 5*time.Second, lrelay)
			lan := Settings{Relay: ips[0] + ":29109", ProxyMode: modeDirect}
			ldst, _ := newWork()
			ok, res, snd, rcv := transfer(lan, "lan-pass-123", "lan-pass-123", "по локальной сети", []string{lf}, ldst, 60*time.Second)
			lrelay.Kill()
			lrelay.Wait(3 * time.Second)
			if up && ok && res.Text == "по локальной сети" && fileEquals(filepath.Join(ldst, "lan файл.bin"), ldata) {
				testLogf("LAN TRANSFER via network address %s: OK", ips[0])
			} else {
				fails++
				testLogf("LAN TRANSFER via %s: FAIL (relay up=%v text=%q)", ips[0], up, res.Text)
				dumpLogs(snd, rcv)
			}
		}

		// 9b2) много мелких файлов подряд и один побольше, несколько раз (регрессия: гонка в croc между файлами)
		{
			many, _ := newWork()
			mdir := filepath.Join(many, "мелочь")
			_ = os.MkdirAll(mdir, 0755)
			for i := 0; i < 60; i++ {
				_ = os.WriteFile(filepath.Join(mdir, fmt.Sprintf("f%02d.txt", i)), []byte(fmt.Sprintf("файл %d", i)), 0644)
			}
			bigM := randBytes(1 << 20)
			_ = os.WriteFile(filepath.Join(mdir, "zzz-big.bin"), bigM, 0644)
			mwork, _ := newWork()
			mrelay := startJob(JobSpec{Work: mwork, MkArgs: func(string) []string {
				return []string{"relay", "--port", "29109", "--ports", "29109,29110,29111,29112,29113"}
			}})
			mup := waitTCP("127.0.0.1:29109", 5*time.Second, mrelay)
			good := 0
			var lastS, lastR *Job
			for round := 0; round < 3; round++ {
				mdst, _ := newWork()
				ok, res, snd, rcv := transfer(Settings{Relay: "127.0.0.1:29109", ProxyMode: modeDirect}, "many-pw", "many-pw",
					"текст вместе с мелочью", []string{mdir}, mdst, 90*time.Second)
				entries, _ := os.ReadDir(filepath.Join(mdst, "мелочь"))
				if ok && res.Text == "текст вместе с мелочью" && len(entries) == 61 && fileEquals(filepath.Join(mdst, "мелочь", "zzz-big.bin"), bigM) {
					good++
				}
				lastS, lastR = snd, rcv
			}
			mrelay.Kill()
			mrelay.Wait(3 * time.Second)
			if mup && good == 3 {
				testLogf("MANY SMALL FILES + BIG FILE x3 (croc file-switch race fixed): OK")
			} else {
				fails++
				testLogf("MANY SMALL FILES: FAIL good=%d/3 relayUp=%v", good, mup)
				dumpLogs(lastS, lastR)
			}
		}

		// 9c) режим непрерывного обмена: две передачи подряд, поиск устройства, короткий пароль, остановка
		events := make(chan ExchangeEvent, 32)
		var x Exchange
		dstX, _ := newWork()
		xerr := x.Start("exchange-pw-1", dstX, "ТестОбмен", func(ev ExchangeEvent) { events <- ev })
		waitEv := func(kind string, d time.Duration) (ExchangeEvent, bool) {
			end := time.After(d)
			for {
				select {
				case ev := <-events:
					if ev.Kind == kind {
						return ev, true
					}
				case <-end:
					return ExchangeEvent{}, false
				}
			}
		}
		if xerr != nil {
			fails++
			testLogf("EXCHANGE start: FAIL %v", xerr)
		} else {
			cfg := Settings{Relay: "127.0.0.1:29109", ProxyMode: modeDirect}
			s1, _ := startSend(cfg, "exchange-pw-1", "первое сообщение", []string{lf})
			ev1, got1 := waitEv("received", 40*time.Second)
			if s1 != nil {
				s1.Wait(20 * time.Second)
			}
			s2, _ := startSend(cfg, "exchange-pw-1", "второе сообщение", nil)
			ev2, got2 := waitEv("received", 40*time.Second)
			if s2 != nil {
				s2.Wait(20 * time.Second)
			}
			// чужой пароль не должен ничего доставить
			s3, _ := startSend(cfg, "wrong-password-xx", "чужое", nil)
			_, got3 := waitEv("received", 6*time.Second)
			if s3 != nil {
				s3.Kill()
			}
			// конфликт имён: файл с тем же именем уже есть в Share - он остаётся, новый получает пометку CONFLICT
			cfgC := cfg
			cfgC.ExchName = "Ноут/1"
			lf2 := filepath.Join(filepath.Dir(lf), "lan файл.bin")
			s4, _ := startSend(cfgC, "exchange-pw-1", "", []string{lf2})
			ev4, got4 := waitEv("received", 40*time.Second)
			if s4 != nil {
				s4.Wait(20 * time.Second)
			}
			if !got4 {
				// возможно, приёмник в этот момент перезапускался: повтор, как сделал бы пользователь
				testLogf("  conflict: first attempt failed, retrying; sender log: %s", s4.Log())
				s4, _ = startSend(cfgC, "exchange-pw-1", "", []string{lf2})
				ev4, got4 = waitEv("received", 40*time.Second)
				if s4 != nil {
					s4.Wait(20 * time.Second)
				}
			}
			x.mu.Lock()
			lastFail := x.lastFail
			x.mu.Unlock()
			conflictOK := got4 && len(ev4.Names) == 1 && strings.Contains(ev4.Names[0], "lan файл-CONFLICT-Ноут_1_") &&
				strings.HasSuffix(ev4.Names[0], ".bin") && fileEquals(filepath.Join(dstX, ev4.Names[0]), ldata) &&
				fileEquals(filepath.Join(dstX, "lan файл.bin"), ldata) && !fileExists(filepath.Join(dstX, fromFileName)) &&
				true
			if !conflictOK {
				fails++
				testLogf("EXCHANGE CONFLICT: FAIL got=%v names=%v", got4, ev4.Names)
				if s4 != nil {
					testLogf("  sender log: %s", s4.Log())
				}
				testLogf("  receiver last failure log: %s", lastFail)
			drain:
				for {
					select {
					case ev := <-events:
						testLogf("  event %s: %s", ev.Kind, ev.Msg)
					default:
						break drain
					}
				}
				ents, _ := os.ReadDir(dstX)
				for _, e := range ents {
					testLogf("  dst: %s", e.Name())
				}
			} else {
				testLogf("EXCHANGE CONFLICT rename (name-CONFLICT-device_date-time.ext): OK")
			}
			// отправка из Share кнопкой: всё содержимое одной передачей на устройство в режиме обмена
			{
				shareDir, _ := newWork()
				_ = os.WriteFile(filepath.Join(shareDir, "s1 файл.txt"), []byte("share one"), 0644)
				_ = os.MkdirAll(filepath.Join(shareDir, "папка Share"), 0755)
				_ = os.WriteFile(filepath.Join(shareDir, "папка Share", "a.txt"), []byte("in dir"), 0644)
				_ = os.WriteFile(filepath.Join(shareDir, ".скрытый"), []byte("x"), 0644)
				names := shareNames(shareDir)
				sok, sfail := shareSend(Settings{ExchName: "ШареТест", ProxyMode: modeDirect}, "exchange-pw-1", shareDir, names, []string{"127.0.0.1:29109"}, nil, func(string) {})
				evS, gotS := waitEv("received", 40*time.Second)
				shareOK := len(names) == 2 && sok == 1 && sfail == 0 && gotS && len(evS.Names) == 2 &&
					fileEquals(filepath.Join(dstX, "s1 файл.txt"), []byte("share one")) &&
					fileEquals(filepath.Join(dstX, "папка Share", "a.txt"), []byte("in dir")) && !fileExists(filepath.Join(dstX, ".скрытый"))
				if shareOK {
					testLogf("SHARE SEND (button: all of Share in one transfer, hidden skipped): OK")
				} else {
					fails++
					testLogf("SHARE SEND: FAIL names=%v ok=%d fail=%d got=%v ev=%v", names, sok, sfail, gotS, evS.Names)
				}
			}
			// слежение за Share: база не отправляется, новое/изменённое/вернувшееся уходит, принятое (Mark) - нет
			{
				wdir, _ := newWork()
				_ = os.WriteFile(filepath.Join(wdir, "old.txt"), []byte("old"), 0644)
				var wmu sync.Mutex
				var sent []string
				var w ShareWatcher
				w.Start(wdir, 150*time.Millisecond, func(n []string) bool {
					wmu.Lock()
					sent = append(sent, strings.Join(n, ","))
					wmu.Unlock()
					return true
				})
				count := func(name string) int {
					wmu.Lock()
					defer wmu.Unlock()
					c := 0
					for _, x := range sent {
						if x == name {
							c++
						}
					}
					return c
				}
				waitCount := func(name string, n int) bool {
					end := time.Now().Add(4 * time.Second)
					for time.Now().Before(end) {
						if count(name) >= n {
							return true
						}
						time.Sleep(50 * time.Millisecond)
					}
					return false
				}
				time.Sleep(500 * time.Millisecond)
				baseOK := count("old.txt") == 0
				_ = os.WriteFile(filepath.Join(wdir, "new.txt"), []byte("n1"), 0644)
				newOK := waitCount("new.txt", 1)
				_ = os.WriteFile(filepath.Join(wdir, "rcv.txt"), []byte("received"), 0644)
				w.Mark([]string{"rcv.txt"})
				time.Sleep(900 * time.Millisecond)
				markOK := count("rcv.txt") == 0
				_ = os.WriteFile(filepath.Join(wdir, "new.txt"), []byte("n1 changed longer"), 0644)
				chgOK := waitCount("new.txt", 2)
				_ = os.Remove(filepath.Join(wdir, "new.txt"))
				time.Sleep(600 * time.Millisecond)
				_ = os.WriteFile(filepath.Join(wdir, "new.txt"), []byte("again"), 0644)
				backOK := waitCount("new.txt", 3)
				w.Stop()
				if baseOK && newOK && markOK && chgOK && backOK && !w.Running() {
					testLogf("SHARE WATCH (baseline kept, new/changed/re-added sent, received skipped): OK")
				} else {
					fails++
					testLogf("SHARE WATCH: FAIL base=%v new=%v mark=%v changed=%v readded=%v sent=%v", baseOK, newOK, markOK, chgOK, backOK, sent)
				}
			}
			found := discoverPeers(1200*time.Millisecond, "me-2", roleRecv, []string{"127.0.0.1:29108"})
			shortErr := (&Exchange{}).Start("ab", dstX, "x", func(ExchangeEvent) {})
			x.Stop()
			closed := !waitTCP("127.0.0.1:29109", 1500*time.Millisecond, nil)
			exchOK := got1 && ev1.Text == "первое сообщение" && len(ev1.Names) == 1 && ev1.Names[0] == "lan файл.bin" &&
				fileEquals(filepath.Join(dstX, "lan файл.bin"), ldata) &&
				got2 && ev2.Text == "второе сообщение" && len(ev2.Names) == 0 && !got3 &&
				len(found) == 1 && found[0].Name == "ТестОбмен" && shortErr != nil && closed && !x.Running()
			if exchOK {
				testLogf("EXCHANGE MODE (2 transfers in a row, wrong password ignored, discovery, short pw rejected, stop): OK")
			} else {
				fails++
				testLogf("EXCHANGE MODE: FAIL got1=%v got2=%v wrongDelivered=%v found=%d shortErr=%v closed=%v", got1, got2, got3, len(found), shortErr, closed)
			}
		}
		// 9d) отправитель ждёт получателя: объявляется, получатель находит его и забирает данные
		{
			recvAddr := "127.0.0.1:29109"
			if ips := localIPv4s(); len(ips) > 0 {
				recvAddr = ips[0] + ":29109" // получатель идёт по сетевому адресу отправителя
			}
			hjob, host, note, herr := startHostedSend(Settings{}, "host-pw", "из режима ожидания", []string{lf}, "ХостТест")
			if herr != nil {
				fails++
				testLogf("HOSTED SEND: FAIL start %v", herr)
			} else {
				senders := discoverPeers(1200*time.Millisecond, "me-3", roleSend, []string{"127.0.0.1:29108"})
				asRecv := discoverPeers(800*time.Millisecond, "me-3", roleRecv, []string{"127.0.0.1:29108"})
				hdst, _ := newWork()
				time.Sleep(1500 * time.Millisecond)
				rcv, created, rerr := startReceive(Settings{Relay: recvAddr, ProxyMode: modeDirect}, "host-pw", hdst)
				okR := false
				var res RecvResult
				if rerr == nil {
					okR = rcv.Wait(60 * time.Second)
					res = finalizeReceive(rcv, hdst, created)
				}
				hjob.Wait(30 * time.Second)
				host.Close()
				gone := !waitTCP("127.0.0.1:29109", 1500*time.Millisecond, nil)
				after := discoverPeers(800*time.Millisecond, "me-3", roleSend, []string{"127.0.0.1:29108"})
				if okR && rcv.ExitCode() == 0 && res.Text == "из режима ожидания" && fileEquals(filepath.Join(hdst, "lan файл.bin"), ldata) &&
					len(senders) == 1 && senders[0].Name == "ХостТест" && senders[0].Role == roleSend && len(asRecv) == 0 && gone && len(after) == 0 &&
					strings.Contains(note, "Ждём получателя") {
					testLogf("HOSTED SEND (sender waits, announced as 'send', receiver pulls via %s, cleaned up): OK", recvAddr)
				} else {
					fails++
					testLogf("HOSTED SEND: FAIL ok=%v text=%q senders=%d asRecv=%d portClosed=%v after=%d", okR, res.Text, len(senders), len(asRecv), gone, len(after))
					dumpLogs(hjob, rcv)
				}
			}
		}

		lanRelayPorts, lanDiscPort = oldPorts, oldDisc
		skipFirewall = false
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

	// 4b) обменники: отправка и приём по ссылке через локальный сервер-имитатор (без настоящих сервисов)
	{
		var mu sync.Mutex
		store := map[string][]byte{}
		mux := http.NewServeMux()
		var tsURL string
		mux.HandleFunc("/up", func(w http.ResponseWriter, r *http.Request) {
			if err := r.ParseMultipartForm(64 << 20); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			f, hdr, err := r.FormFile("fileToUpload")
			if err != nil {
				http.Error(w, "no file", 400)
				return
			}
			b, _ := io.ReadAll(f)
			id := randHex(4)
			mu.Lock()
			store["/f/"+id+"/"+hdr.Filename] = b
			mu.Unlock()
			fmt.Fprint(w, tsURL+"/f/"+id+"/"+url.PathEscape(hdr.Filename)+"\n")
		})
		mux.HandleFunc("/f/", func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			b, ok := store[r.URL.Path]
			mu.Unlock()
			if !ok {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write(b)
		})
		ts := httptest.NewServer(mux)
		tsURL = ts.URL
		saved := xProviders
		xProviders = []xProvider{{name: "mock", max: 1 << 30, keep: "тест", upload: func(ctx context.Context, c *http.Client, file, name string, size int64, prog func(int64)) (string, error) {
			body, err := postMultipart(ctx, c, ts.URL+"/up", map[string]string{"reqtype": "fileupload"}, "fileToUpload", file, name, size, prog)
			if err != nil {
				return "", err
			}
			return uploadTextURL(body)
		}}}
		cfg := Settings{ProxyMode: modeDirect, ExchName: "Тест/Хост"}
		xsrc, _ := newWork()
		xfile := filepath.Join(xsrc, "док ф.bin")
		xdata := bytes.Repeat([]byte("exchanger-data-"), 40000)
		_ = os.WriteFile(xfile, xdata, 0644)
		xdir := filepath.Join(xsrc, "папка Х", "под")
		_ = os.MkdirAll(xdir, 0755)
		_ = os.WriteFile(filepath.Join(xdir, "a.txt"), []byte("hello"), 0644)
		runRecv := func(pw, link string) (*Job, string, RecvResult, bool) {
			dst, _ := newWork()
			rj, created, err := startExchRecv(cfg, pw, link, dst)
			if err != nil {
				return nil, dst, RecvResult{}, false
			}
			ok := rj.Wait(60*time.Second) && rj.ExitCode() == 0
			return rj, dst, finalizeReceive(rj, dst, created), ok
		}
		runSend := func(c Settings, pw, text string, items []string, exe bool) (*Job, bool) {
			sj, err := startExchSend(c, pw, text, items, exe)
			if err != nil {
				return nil, false
			}
			return sj, sj.Wait(90*time.Second) && sj.ExitCode() == 0
		}
		xok := true
		xfail := func(what string, sj, rj *Job) {
			xok = false
			testLogf("EXCHANGERS: FAIL %s", what)
			if sj != nil {
				testLogf("  send: %s", sj.Log())
			}
			if rj != nil {
				testLogf("  recv: %s", rj.Log())
			}
		}
		// а) с паролем: текст + файл + папка
		sj, ok1 := runSend(cfg, "парoль1", "текст для обменника", []string{xfile, filepath.Join(xsrc, "папка Х")}, false)
		link := ""
		if sj != nil {
			link = sj.Result()
		}
		rj, dst, res, ok2 := runRecv("парoль1", link)
		if !(ok1 && ok2 && res.Text == "текст для обменника" && fileEquals(filepath.Join(dst, "док ф.bin"), xdata) &&
			fileEquals(filepath.Join(dst, "папка Х", "под", "a.txt"), []byte("hello")) && !fileExists(filepath.Join(dst, fromFileName))) {
			xfail("password archive round trip", sj, rj)
		}
		// б) неверный пароль и отсутствие пароля: ничего не извлекается
		rj2, dst2, _, ok3 := runRecv("не-тот", link)
		rj3, dst3, _, ok4 := runRecv("", link)
		if ok3 || ok4 || fileExists(filepath.Join(dst2, "док ф.bin")) || fileExists(filepath.Join(dst3, "док ф.bin")) ||
			!strings.Contains(rj2.Log(), "неверный пароль") || !strings.Contains(rj3.Log(), "защищён паролем") {
			xfail("wrong/missing password must be rejected", nil, rj2)
			testLogf("  nopw: %s", rj3.Log())
		}
		// в) без пароля, со сжатием
		cz := cfg
		cz.Compress = true
		sj4, ok5 := runSend(cz, "", "", []string{xfile}, false)
		rj4, dst4, _, ok6 := runRecv("", sj4.Result())
		if !(ok5 && ok6 && fileEquals(filepath.Join(dst4, "док ф.bin"), xdata)) {
			xfail("compressed archive without password", sj4, rj4)
		}
		// г) один файл без пароля и без сжатия уходит как есть, под своим именем
		sj5, ok7 := runSend(cfg, "", "", []string{xfile}, false)
		rj5, dst5, _, ok8 := runRecv("", sj5.Result())
		if !(ok7 && ok8 && fileEquals(filepath.Join(dst5, "док ф.bin"), xdata) && strings.HasSuffix(sj5.Result(), "/"+url.PathEscape("док ф.bin"))) {
			xfail("single file as is", sj5, rj5)
		}
		// д) программа в том же архиве, что и файлы (одна ссылка); с паролем - традиционное шифрование для Проводника
		selfExe, _ := os.Executable()
		fiExe, _ := os.Stat(selfExe)
		exeName := filepath.Base(selfExe)
		sj6, ok9 := runSend(cz, "", "", []string{xfile}, true)
		rj6, dst6, _, ok10 := runRecv("", sj6.Result())
		exeOK := ok9 && ok10 && !strings.Contains(sj6.Result(), "\n") && fiExe != nil &&
			fileEquals(filepath.Join(dst6, "док ф.bin"), xdata) && fileExists(filepath.Join(dst6, exeName))
		if fi, err := os.Stat(filepath.Join(dst6, exeName)); err != nil || fiExe == nil || fi.Size() != fiExe.Size() {
			exeOK = false
		}
		sj7, ok11 := runSend(cz, "Pass123", "", []string{xfile}, true)
		_, dst7, _, ok12 := runRecv("Pass123", sj7.Result())
		rj8, dst8, _, ok13 := runRecv("wrong1", sj7.Result())
		if ok9 && ok10 && exeOK && ok11 && ok12 && fileEquals(filepath.Join(dst7, "док ф.bin"), xdata) && fileExists(filepath.Join(dst7, exeName)) &&
			!ok13 && !fileExists(filepath.Join(dst8, "док ф.bin")) && strings.Contains(rj8.Log(), "неверный пароль") {
			// архив с программой читается стандартным zip без AES-расширений (как Проводник)
			zdir, _ := newWork()
			zp, _ := downloadLink(context.Background(), Route{}, strings.TrimSpace(sj7.Result()), zdir, func(int64, int64) {})
			stdOK := false
			if zr, err := zip.OpenReader(zp); err == nil {
				stdOK = len(zr.File) >= 2
				for _, f := range zr.File {
					if f.Method == 99 || f.Flags&1 == 0 {
						stdOK = false
					}
				}
				zr.Close()
			}
			if !stdOK {
				exeOK = false
			}
		} else {
			exeOK = false
		}
		// только программа (без файлов и текста): одна ссылка на zip с exe
		sj9, ok14 := runSend(cz, "", "", nil, true)
		_, dst9, _, ok15 := runRecv("", sj9.Result())
		zpOnly := ""
		if es, _ := os.ReadDir(dst9); len(es) == 1 {
			zpOnly = es[0].Name()
		}
		onlyOK := false
		if ok14 && ok15 && strings.HasSuffix(zpOnly, ".zip") {
			if zr, err := zip.OpenReader(filepath.Join(dst9, zpOnly)); err == nil {
				onlyOK = len(zr.File) == 1 && zr.File[0].Name == exeName && zr.File[0].UncompressedSize64 == uint64(fiExe.Size())
				zr.Close()
			}
		}
		if !exeOK || !onlyOK {
			xfail("program inside the archive", sj6, rj6)
			testLogf("  exeOK=%v onlyOK=%v ok9=%v ok10=%v ok11=%v ok12=%v ok13=%v ok14=%v ok15=%v only=%q", exeOK, onlyOK, ok9, ok10, ok11, ok12, ok13, ok14, ok15, zpOnly)
		}
		// е) ссылка в сообщении с текстом и tmpfiles-страница нормализуются
		l1, e1 := normalizeLink("Файлы: https://example.org/a/b.zip  (litterbox)")
		l2, _ := normalizeLink("https://tmpfiles.org/123/x.zip")
		if e1 != nil || l1 != "https://example.org/a/b.zip" || l2 != "https://tmpfiles.org/dl/123/x.zip" {
			xfail("link normalization", nil, nil)
		}
		xProviders = saved
		ts.Close()
		if xok {
			testLogf("EXCHANGERS (mock server: AES password archive, wrong/missing password, compressed, single file as is, program in the same archive with classic password, links): OK")
		} else {
			fails++
		}
	}

	// 4d) план поиска в сети: перечень адресов подсети
	{
		h24 := hostsIn(net.ParseIP("192.168.1.5"), net.CIDRMask(24, 32))
		h16 := hostsIn(net.ParseIP("10.1.7.9"), net.CIDRMask(16, 32))
		h22 := hostsIn(net.ParseIP("10.1.5.9"), net.CIDRMask(22, 32))
		h30 := hostsIn(net.ParseIP("10.0.0.1"), net.CIDRMask(30, 32))
		plan := planScan()
		okPlan := len(h24) == 254 && h24[0].String() == "192.168.1.1" && h24[253].String() == "192.168.1.254" &&
			len(h16) == 254 && h16[0].String() == "10.1.7.1" && len(h22) == 1022 && len(h30) == 2 && len(plan.Targets) >= 1
		for _, tg := range plan.Targets {
			if !strings.HasSuffix(tg, ":"+itoa(lanDiscPort)) {
				okPlan = false
			}
		}
		for _, ip := range localIPv4s() {
			for _, tg := range plan.Targets {
				if tg == net.JoinHostPort(ip, itoa(lanDiscPort)) {
					okPlan = false // себя не опрашиваем
				}
			}
		}
		if okPlan {
			testLogf("LAN SCAN PLAN (unicast sweep of subnet, /16 narrowed to /24, own addresses skipped): OK %d targets", len(plan.Targets))
		} else {
			fails++
			testLogf("LAN SCAN PLAN: FAIL %d/%d/%d/%d targets=%d", len(h24), len(h16), len(h22), len(h30), len(plan.Targets))
		}
	}
	// 4c) меню Проводника и пересылка путей в уже открытое окно
	{
		okReg, msg := shellSelfTest()
		ln, lerr := net.Listen("tcp", "127.0.0.1:0")
		got := make(chan []string, 4)
		if lerr == nil {
			serveShell(ln, func(ps []string) { got <- ps })
			ferr1 := forwardPaths(ln.Addr().String(), []string{`C:\папка с пробелом\файл ф.txt`})
			ferr2 := forwardPaths(ln.Addr().String(), []string{`D:\x`, `E:\y z`})
			var all []string
			for i := 0; i < 2; i++ {
				select {
				case ps := <-got:
					all = append(all, ps...)
				case <-time.After(3 * time.Second):
				}
			}
			ln.Close()
			okFwd := ferr1 == nil && ferr2 == nil && len(all) == 3 && all[0] == `C:\папка с пробелом\файл ф.txt` && all[2] == `E:\y z`
			// второй процесс при занятом порте пересылает и завершается, первый становится окном
			ln2, _ := net.Listen("tcp", "127.0.0.1:0")
			addr2 := ln2.Addr().String()
			ln2.Close()
			c1 := shellSendAt(addr2, []string{"p1"})
			own := shellListener
			shellListener = nil
			serveShell(own, func(ps []string) { got <- ps })
			c2 := shellSendAt(addr2, []string{"p2"})
			var p2 []string
			select {
			case p2 = <-got:
			case <-time.After(3 * time.Second):
			}
			own.Close()
			shellInitPaths = nil
			if okReg && okFwd && c1 == -1 && c2 == 0 && len(p2) == 1 && p2[0] == "p2" {
				testLogf("EXPLORER MENU (register/detect/unregister, path forwarding, single window for many files): OK")
			} else {
				fails++
				testLogf("EXPLORER MENU: FAIL reg=%v(%s) fwd=%v c1=%d c2=%d p2=%v", okReg, msg, okFwd, c1, c2, p2)
			}
		} else {
			fails++
			testLogf("EXPLORER MENU: FAIL listen %v", lerr)
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
	// файлообменники: загрузка небольшого файла и скачивание обратно
	{
		tdir, _ := newWork()
		tf := filepath.Join(tdir, "crocau-nettest.txt")
		payload := []byte("crocau exchanger test " + randHex(4))
		_ = os.WriteFile(tf, payload, 0644)
		saved := xProviders
		for _, pr := range saved {
			xProviders = []xProvider{pr}
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
			link, _, err := uploadChain(ctx, Route{}, tf, "crocau-nettest.txt", func(int64, int64) {}, func(string) {})
			if err != nil {
				cancel()
				testLogf("EXCHANGER %s: FAIL upload: %v", pr.name, err)
				continue
			}
			p, derr := downloadLink(ctx, Route{}, link, filepath.Join(tdir, "dl-"+pr.name), func(int64, int64) {})
			cancel()
			if derr != nil {
				testLogf("EXCHANGER %s: FAIL download %s: %v", pr.name, link, derr)
			} else if !fileEquals(p, payload) {
				b, _ := os.ReadFile(p)
				if len(b) > 120 {
					b = b[:120]
				}
				testLogf("EXCHANGER %s: FAIL content differs (%s) got %q", pr.name, link, string(b))
			} else {
				testLogf("EXCHANGER %s: OK %s", pr.name, link)
			}
		}
		xProviders = saved
	}
	// полный путь через настоящие обменники: архив с паролем -> ссылка -> скачивание -> распаковка
	{
		xs := Settings{ProxyMode: modeDirect, ExchName: "CI"}
		sj, err := startExchSend(xs, "net123", "текст через обменник", nil, false)
		if err != nil {
			testLogf("EXCHANGE FULL: FAIL %v", err)
		} else {
			okS := sj.Wait(150*time.Second) && sj.ExitCode() == 0
			link := sj.Result()
			dst, _ := newWork()
			var res RecvResult
			okR := false
			var rj *Job
			if okS {
				var created bool
				rj, created, err = startExchRecv(xs, "net123", link, dst)
				if err == nil {
					okR = rj.Wait(120*time.Second) && rj.ExitCode() == 0
					res = finalizeReceive(rj, dst, created)
				}
			}
			if okS && okR && res.Text == "текст через обменник" {
				testLogf("EXCHANGE FULL (real exchanger, AES password, text): OK %s", link)
			} else {
				testLogf("EXCHANGE FULL: FAIL send=%v recv=%v text=%q", okS, okR, res.Text)
				testLogf("  send log: %s", sj.Log())
				if rj != nil {
					testLogf("  recv log: %s", rj.Log())
				}
			}
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
