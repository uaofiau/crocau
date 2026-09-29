//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
	"github.com/lxn/win"
)

func crlf(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\n", "\r\n")
}

func guiMain(test bool) int {
	st := loadSettings()
	var (
		mw          *walk.MainWindow
		sendText    *walk.TextEdit
		fileList    *walk.ListBox
		sendPw      *walk.LineEdit
		recvPw      *walk.LineEdit
		outLE       *walk.LineEdit
		recvText    *walk.TextEdit
		relayLE     *walk.LineEdit
		relayPassLE *walk.LineEdit
		proxyLE     *walk.LineEdit
		extraLE     *walk.LineEdit
		logTE       *walk.TextEdit
		sendBtn     *walk.PushButton
		recvBtn     *walk.PushButton
		stopBtn     *walk.PushButton
	)
	var items []string
	var curJob *Job
	var curMode, curOut string
	var curCreated bool
	testExit := 0

	warn := func(msg string) {
		if test {
			testLogf("WARN: %s", msg)
			return
		}
		walk.MsgBox(mw, "crocau", msg, walk.MsgBoxIconWarning)
	}
	collect := func() Settings {
		return Settings{Relay: relayLE.Text(), RelayPass: relayPassLE.Text(), Proxy: proxyLE.Text(),
			Extra: extraLE.Text(), OutDir: outLE.Text()}
	}
	setLog := func(s string) {
		if logTE.Text() == s {
			return
		}
		logTE.SetText(s)
		n := len(utf16.Encode([]rune(s)))
		logTE.SetTextSelection(n, n)
		logTE.SendMessage(win.EM_SCROLLCARET, 0, 0)
	}
	setBusy := func(b bool) {
		sendBtn.SetEnabled(!b)
		recvBtn.SetEnabled(!b)
		stopBtn.SetEnabled(b)
	}
	refreshList := func() { fileList.SetModel(append([]string{}, items...)) }
	addPaths := func(ps []string) {
		for _, p := range ps {
			dup := false
			for _, q := range items {
				if strings.EqualFold(p, q) {
					dup = true
					break
				}
			}
			if !dup {
				items = append(items, p)
			}
		}
		refreshList()
	}

	var finish func(job *Job)
	begin := func(job *Job, mode, out string, created bool) {
		curJob, curMode, curOut, curCreated = job, mode, out, created
		setBusy(true)
		go func() {
			tk := time.NewTicker(300 * time.Millisecond)
			defer tk.Stop()
			for {
				select {
				case <-tk.C:
					mw.Synchronize(func() {
						if curJob == job {
							setLog(job.Log())
						}
					})
				case <-job.done:
					mw.Synchronize(func() { finish(job) })
					return
				}
			}
		}()
	}
	finish = func(job *Job) {
		if curJob != job {
			return
		}
		tail := ""
		code := job.ExitCode()
		if code == 0 {
			tail = "\r\n=== Готово ==="
		} else {
			tail = fmt.Sprintf("\r\n=== Остановлено или ошибка (код %d) ===", code)
		}
		if curMode == "recv" {
			res := finalizeReceive(job, curOut, curCreated)
			if code == 0 {
				if res.Text != "" {
					recvText.SetText(crlf(res.Text))
					tail += "\r\nПолучен текст."
				}
				if res.HasFiles {
					tail += "\r\nФайлы сохранены в: " + curOut
				}
			}
		}
		setLog(job.Log() + tail)
		job.Cleanup()
		curJob = nil
		setBusy(false)
	}

	doSend := func() {
		if curJob != nil {
			return
		}
		pw := strings.TrimSpace(sendPw.Text())
		if utf8.RuneCountInString(pw) < 3 {
			warn("Пароль должен быть не короче 3 символов.")
			return
		}
		text := sendText.Text()
		if strings.TrimSpace(text) == "" {
			text = ""
		}
		if text == "" && len(items) == 0 {
			warn("Введите текст и/или добавьте файлы или папки (можно перетащить их в окно).")
			return
		}
		for _, p := range items {
			if _, err := os.Stat(p); err != nil {
				warn("Не найден: " + p)
				return
			}
		}
		cur := collect()
		saveSettings(cur)
		j, err := startSend(cur, pw, text, items)
		if err != nil {
			warn(err.Error())
			return
		}
		setLog("Отправка запущена. Передайте получателю пароль и дождитесь подключения...")
		begin(j, "send", "", false)
	}
	doReceive := func() {
		if curJob != nil {
			return
		}
		pw := strings.TrimSpace(recvPw.Text())
		if utf8.RuneCountInString(pw) < 3 {
			warn("Пароль должен быть не короче 3 символов.")
			return
		}
		out := strings.TrimSpace(outLE.Text())
		if out == "" {
			warn("Укажите папку для сохранения.")
			return
		}
		cur := collect()
		cur.OutDir = out
		saveSettings(cur)
		recvText.SetText("")
		j, created, err := startReceive(cur, pw, out)
		if err != nil {
			warn(err.Error())
			return
		}
		setLog("Ожидание отправителя...")
		begin(j, "recv", out, created)
	}

	err := MainWindow{
		AssignTo: &mw,
		Title:    "crocau - передача файлов, папок и текста",
		MinSize:  Size{Width: 640, Height: 640},
		Size:     Size{Width: 700, Height: 700},
		Layout:   VBox{},
		Children: []Widget{
			TabWidget{
				Pages: []TabPage{
					{
						Title:  "Отправить",
						Layout: VBox{},
						Children: []Widget{
							Label{Text: "Текст (необязательно):"},
							TextEdit{AssignTo: &sendText, VScroll: true, MinSize: Size{Height: 90}},
							Label{Text: "Файлы и папки (необязательно; можно перетащить в окно):"},
							Composite{
								Layout: HBox{MarginsZero: true},
								Children: []Widget{
									ListBox{AssignTo: &fileList, MultiSelection: true, MinSize: Size{Height: 100}},
									Composite{
										Layout: VBox{MarginsZero: true},
										Children: []Widget{
											PushButton{Text: "Файлы...", OnClicked: func() {
												dlg := new(walk.FileDialog)
												dlg.Title = "Выберите файлы"
												dlg.Filter = "Все файлы (*.*)|*.*"
												if ok, err := dlg.ShowOpenMultiple(mw); err == nil && ok {
													addPaths(dlg.FilePaths)
												}
											}},
											PushButton{Text: "Папка...", OnClicked: func() {
												dlg := new(walk.FileDialog)
												dlg.Title = "Выберите папку"
												if ok, err := dlg.ShowBrowseFolder(mw); err == nil && ok {
													addPaths([]string{dlg.FilePath})
												}
											}},
											PushButton{Text: "Убрать", OnClicked: func() {
												mark := map[int]bool{}
												for _, i := range fileList.SelectedIndexes() {
													mark[i] = true
												}
												var nn []string
												for i, p := range items {
													if !mark[i] {
														nn = append(nn, p)
													}
												}
												items = nn
												refreshList()
											}},
											PushButton{Text: "Очистить", OnClicked: func() {
												items = nil
												refreshList()
											}},
											PushButton{Text: "Текст из буфера", OnClicked: func() {
												if t, err := walk.Clipboard().Text(); err == nil {
													sendText.SetText(t)
												}
											}},
											VSpacer{},
										},
									},
								},
							},
							Composite{
								Layout: HBox{MarginsZero: true},
								Children: []Widget{
									Label{Text: "Пароль (от 3 символов):"},
									LineEdit{AssignTo: &sendPw, MaxSize: Size{Width: 160}},
									PushButton{Text: "Случайный", OnClicked: func() { sendPw.SetText(randomPassword()) }},
									HSpacer{},
									PushButton{AssignTo: &sendBtn, Text: "Отправить", MinSize: Size{Width: 130}, OnClicked: doSend},
								},
							},
						},
					},
					{
						Title:  "Получить",
						Layout: VBox{},
						Children: []Widget{
							Label{Text: "Пароль (тот, что задал отправитель):"},
							LineEdit{AssignTo: &recvPw, MaxSize: Size{Width: 200}},
							Label{Text: "Папка для сохранения файлов:"},
							Composite{
								Layout: HBox{MarginsZero: true},
								Children: []Widget{
									LineEdit{AssignTo: &outLE, Text: st.OutDir},
									PushButton{Text: "Обзор...", OnClicked: func() {
										dlg := new(walk.FileDialog)
										dlg.Title = "Папка для сохранения"
										if ok, err := dlg.ShowBrowseFolder(mw); err == nil && ok {
											outLE.SetText(dlg.FilePath)
										}
									}},
								},
							},
							Label{Text: "Полученный текст:"},
							Composite{
								Layout: HBox{MarginsZero: true},
								Children: []Widget{
									TextEdit{AssignTo: &recvText, ReadOnly: true, VScroll: true, MinSize: Size{Height: 110}},
									Composite{
										Layout: VBox{MarginsZero: true},
										Children: []Widget{
											PushButton{Text: "Копировать", OnClicked: func() {
												if t := recvText.Text(); t != "" {
													_ = walk.Clipboard().SetText(t)
												}
											}},
											VSpacer{},
										},
									},
								},
							},
							Composite{
								Layout: HBox{MarginsZero: true},
								Children: []Widget{
									PushButton{AssignTo: &recvBtn, Text: "Получить", MinSize: Size{Width: 130}, OnClicked: doReceive},
									HSpacer{},
								},
							},
						},
					},
					{
						Title:  "Настройки",
						Layout: VBox{},
						Children: []Widget{
							Label{Text: "Адрес relay (host:порт). Пусто = публичный relay croc:"},
							LineEdit{AssignTo: &relayLE, Text: st.Relay},
							Label{Text: "Пароль relay (пусто = по умолчанию):"},
							LineEdit{AssignTo: &relayPassLE, Text: st.RelayPass},
							Label{Text: "Прокси: socks5://host:port или http://host:port (пусто = без прокси):"},
							LineEdit{AssignTo: &proxyLE, Text: st.Proxy},
							Label{Text: "Доп. общие ключи croc через пробел (например: --internal-dns --no-multi):"},
							LineEdit{AssignTo: &extraLE, Text: st.Extra},
							Label{Text: "Настройки хранятся в crocau.ini рядом с программой. Пароль передачи нигде не сохраняется."},
							VSpacer{},
						},
					},
				},
			},
			Label{Text: "Ход передачи:"},
			TextEdit{AssignTo: &logTE, ReadOnly: true, VScroll: true, MinSize: Size{Height: 150},
				Font: Font{Family: "Consolas", PointSize: 9}},
			Composite{
				Layout: HBox{MarginsZero: true},
				Children: []Widget{
					PushButton{Text: "Копировать журнал", OnClicked: func() {
						if t := logTE.Text(); t != "" {
							_ = walk.Clipboard().SetText(t)
						}
					}},
					PushButton{AssignTo: &stopBtn, Text: "Стоп", Enabled: false, OnClicked: func() {
						if curJob != nil {
							curJob.Kill()
						}
					}},
					HSpacer{},
				},
			},
		},
	}.Create()
	if err != nil {
		msg := "crocau: не удалось создать окно: " + err.Error()
		_ = os.WriteFile(filepath.Join(exeDir(), "crocau-error.log"), []byte(msg), 0644)
		if test {
			testLogf("%s", msg)
		}
		return 1
	}

	win.DragAcceptFiles(mw.Handle(), true)
	mw.DropFiles().Attach(func(files []string) { addPaths(files) })
	mw.Closing().Attach(func(canceled *bool, reason walk.CloseReason) {
		saveSettings(collect())
		if curJob != nil {
			curJob.Kill()
			time.Sleep(300 * time.Millisecond)
			curJob.Cleanup()
		}
	})

	if test {
		testLogf("GUITEST: window created, starting steps")
		go func() {
			time.Sleep(500 * time.Millisecond)
			testExit = guiTestSteps(mw, func() bool { return curJob != nil }, func(f func()) {
				ch := make(chan struct{})
				mw.Synchronize(func() {
					defer close(ch)
					f()
				})
				<-ch
			}, guiHooks{
				setRelay: func(s string) { relayLE.SetText(s) },
				setSendText: func(s string) { sendText.SetText(s) },
				addFiles:    addPaths,
				setSendPw:   func(s string) { sendPw.SetText(s) },
				send:        doSend,
				setRecvPw:   func(s string) { recvPw.SetText(s) },
				setOut:      func(s string) { outLE.SetText(s) },
				recv:        doReceive,
				recvText:    func() string { return recvText.Text() },
			})
		}()
		go func() {
			time.Sleep(150 * time.Second)
			testLogf("GUITEST: WATCHDOG TIMEOUT")
			os.Exit(1)
		}()
	}

	mw.Run()
	return testExit
}

type guiHooks struct {
	setRelay, setSendText, setSendPw, setRecvPw, setOut func(string)
	addFiles                                            func([]string)
	send, recv                                          func()
	recvText                                            func() string
}

// guiTestSteps выполняется в отдельной горутине; всё, что трогает окно, идёт через ui().
func guiTestSteps(mw *walk.MainWindow, busy func() bool, ui func(func()), h guiHooks) int {
	fails := 0
	waitIdle := func(sec int) bool {
		dl := time.Now().Add(time.Duration(sec) * time.Second)
		for time.Now().Before(dl) {
			var b bool
			ui(func() { b = busy() })
			if !b {
				return true
			}
			time.Sleep(300 * time.Millisecond)
		}
		return false
	}
	finishTest := func() int {
		ui(func() { mw.Close() })
		if fails == 0 {
			testLogf("GUITEST PASSED")
			return 0
		}
		testLogf("GUITEST FAILED")
		return 1
	}

	testLogf("step0: starting relay")
	relay, err := startTestRelay()
	if err != nil {
		testLogf("relay error: %v", err)
		fails++
		return finishTest()
	}
	defer relay.Kill()
	s := Settings{Relay: "127.0.0.1:19009"}
	ui(func() { h.setRelay("127.0.0.1:19009") })
	testLogf("step0: relay ready, UI reachable")

	src, _ := newWork()
	f1 := filepath.Join(src, "gui файл.bin")
	data := randBytes(262144)
	_ = os.WriteFile(f1, data, 0644)

	// 1) окно отправляет текст + файл, принимает "внешний" процесс
	text1 := "Привет из GUI\r\nстрока 2"
	ui(func() {
		h.setSendText(text1)
		h.addFiles([]string{f1})
		h.setSendPw("abc")
		h.send()
	})
	testLogf("step1: GUI send clicked")
	time.Sleep(1500 * time.Millisecond)
	dst1, _ := newWork()
	rcv, created, err := startReceive(s, "abc", dst1)
	if err != nil {
		testLogf("startReceive error: %v", err)
		fails++
	} else {
		okR := rcv.Wait(60 * time.Second)
		res := finalizeReceive(rcv, dst1, created)
		if okR && res.Text == text1 && fileEquals(filepath.Join(dst1, "gui файл.bin"), data) {
			testLogf("GUI SEND text+file: OK")
		} else {
			fails++
			testLogf("GUI SEND text+file: FAIL text=%q", res.Text)
			testLogf("%s", rcv.Log())
		}
	}
	testLogf("step1: waiting GUI sender to finish")
	if !waitIdle(40) {
		fails++
		testLogf("GUI sender did not finish")
	}

	// 2) "внешний" процесс отправляет текст + файл, принимает окно
	text2 := "второй текст\r\nс переносом"
	snd, err := startSend(s, "xyz", text2, []string{f1})
	if err != nil {
		testLogf("startSend error: %v", err)
		fails++
		return finishTest()
	}
	testLogf("step2: external sender started")
	time.Sleep(1500 * time.Millisecond)
	dst2, _ := newWork()
	dst2 = filepath.Join(dst2, "новая папка")
	ui(func() {
		h.setRecvPw("xyz")
		h.setOut(dst2)
		h.recv()
	})
	testLogf("step2: GUI receive clicked")
	if !waitIdle(60) {
		fails++
		testLogf("GUI receiver did not finish")
		snd.Kill()
	}
	snd.Wait(20 * time.Second)
	var got string
	ui(func() { got = h.recvText() })
	if got == text2 && fileEquals(filepath.Join(dst2, "gui файл.bin"), data) && !fileExists(filepath.Join(dst2, textFileName)) {
		testLogf("GUI RECEIVE text+file: OK")
	} else {
		fails++
		testLogf("GUI RECEIVE text+file: FAIL text=%q", got)
		testLogf("%s", snd.Log())
	}
	return finishTest()
}
