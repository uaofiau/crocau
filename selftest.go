package main

import (
	"bytes"
	crand "crypto/rand"
	"fmt"
	"os"
	"path/filepath"
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
	j, err := startCroc(func(string) []string {
		return []string{"relay", "--port", "19009", "--ports", "19009,19010,19011,19012,19013"}
	}, nil, "", work)
	if err != nil {
		return nil, err
	}
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
