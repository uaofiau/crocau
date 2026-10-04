package main

import (
	"archive/zip"
	"bytes"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
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
		stopResp, rerr := startResponder("peer-1", "Тестовый ПК", 29109)
		peers := discoverPeers(1200*time.Millisecond, "me-1", []string{"127.0.0.1:29108"})
		own := discoverPeers(800*time.Millisecond, "peer-1", []string{"127.0.0.1:29108"})
		if stopResp != nil {
			stopResp()
		}
		discOK := rerr == nil && len(peers) == 1 && peers[0].Name == "Тестовый ПК" && peers[0].Port == 29109 &&
			peers[0].IP == "127.0.0.1" && len(own) == 0
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
			found := discoverPeers(1200*time.Millisecond, "me-2", []string{"127.0.0.1:29108"})
			shortErr := (&Exchange{}).Start("short", dstX, "x", func(ExchangeEvent) {})
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
