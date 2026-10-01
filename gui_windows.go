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

var proxyTypeNames = []string{"socks5", "socks4", "http"}

func proxyTypeIndex(t string) int {
	for i, n := range proxyTypeNames {
		if n == t {
			return i
		}
	}
	return 0
}

type proxyRow struct {
	comp   *walk.Composite
	sel    *walk.RadioButton
	typ    *walk.ComboBox
	addr   *walk.LineEdit
	auth   *walk.CheckBox
	user   *walk.LineEdit
	pass   *walk.LineEdit
	status *walk.Label
}

func shortErr(err error) string {
	s := strings.ReplaceAll(err.Error(), "\n", " ")
	if len([]rune(s)) > 70 {
		s = string([]rune(s)[:70]) + "..."
	}
	return s
}

func guiMain(test bool) int {
	st := loadSettings()
	var (
		mw          *walk.MainWindow
		sendText    *walk.TextEdit
		fileList    *walk.ListBox
		sendPw      *walk.LineEdit
		compressCB  *walk.CheckBox
		recvPw      *walk.LineEdit
		outLE       *walk.LineEdit
		recvText    *walk.TextEdit
		relayLE     *walk.LineEdit
		relayPassLE *walk.LineEdit
		extraLE     *walk.LineEdit
		logTE       *walk.TextEdit
		sendBtn     *walk.PushButton
		recvBtn     *walk.PushButton
		stopBtn     *walk.PushButton
		addBtn      *walk.PushButton
		checkBtn    *walk.PushButton
		modeDirRB   *walk.RadioButton
		modeAutoRB  *walk.RadioButton
		modeProxyRB *walk.RadioButton
		directLbl   *walk.Label
	)
	var items []string
	var curJob *Job
	var curMode, curOut string
	var curCreated bool
	checking := false
	testExit := 0
	testDone := make(chan int, 1)

	rows := make([]*proxyRow, maxProxies)
	rowCount := 0
	var selectRow func(i int)
	var removeRow func(i int)
	var updateAuth func(i int)
	var setMode func(m string)

	warn := func(msg string) {
		if test {
			testLogf("WARN: %s", msg)
			return
		}
		walk.MsgBox(mw, "crocau", msg, walk.MsgBoxIconWarning)
	}

	// ---------- прокси: строки ----------
	collectProxies := func() []ProxyCfg {
		var out []ProxyCfg
		for i := 0; i < rowCount; i++ {
			r := rows[i]
			out = append(out, ProxyCfg{
				Type: proxyTypeNames[0],
				Addr: strings.TrimSpace(r.addr.Text()),
				Auth: r.auth.Checked(),
				User: r.user.Text(),
				Pass: r.pass.Text(),
			})
			if idx := r.typ.CurrentIndex(); idx >= 0 && idx < len(proxyTypeNames) {
				out[len(out)-1].Type = proxyTypeNames[idx]
			}
		}
		return out
	}
	selIndex := func() int {
		for i := 0; i < rowCount; i++ {
			if rows[i].sel.Checked() {
				return i
			}
		}
		return 0
	}
	applyProxies := func(list []ProxyCfg, sel int) {
		if len(list) > maxProxies {
			list = list[:maxProxies]
		}
		rowCount = len(list)
		for i, r := range rows {
			if i < len(list) {
				p := list[i]
				_ = r.typ.SetCurrentIndex(proxyTypeIndex(p.Type))
				_ = r.addr.SetText(p.Addr)
				r.auth.SetChecked(p.Auth)
				_ = r.user.SetText(p.User)
				_ = r.pass.SetText(p.Pass)
				r.user.SetEnabled(p.Auth)
				r.pass.SetEnabled(p.Auth)
				r.sel.SetChecked(i == sel)
				_ = r.status.SetText("")
				r.comp.SetVisible(true)
			} else {
				r.comp.SetVisible(false)
				_ = r.addr.SetText("")
				_ = r.user.SetText("")
				_ = r.pass.SetText("")
				r.auth.SetChecked(false)
				r.sel.SetChecked(false)
				_ = r.status.SetText("")
			}
		}
		addBtn.SetEnabled(rowCount < maxProxies)
	}
	selectRow = func(i int) {
		for k := 0; k < rowCount; k++ {
			rows[k].sel.SetChecked(k == i)
		}
	}
	updateAuth = func(i int) {
		on := rows[i].auth.Checked()
		rows[i].user.SetEnabled(on)
		rows[i].pass.SetEnabled(on)
	}
	removeRow = func(i int) {
		list := collectProxies()
		sel := selIndex()
		if i < 0 || i >= len(list) {
			return
		}
		list = append(list[:i], list[i+1:]...)
		if sel == i {
			sel = 0
		} else if sel > i {
			sel--
		}
		applyProxies(list, sel)
	}
	addRow := func() {
		if rowCount >= maxProxies {
			return
		}
		list := append(collectProxies(), ProxyCfg{Type: "socks5"})
		applyProxies(list, selIndex())
	}
	setMode = func(m string) {
		modeDirRB.SetChecked(m == modeDirect)
		modeProxyRB.SetChecked(m == modeProxy)
		modeAutoRB.SetChecked(m != modeDirect && m != modeProxy)
	}
	curProxyMode := func() string {
		if modeDirRB.Checked() {
			return modeDirect
		}
		if modeProxyRB.Checked() {
			return modeProxy
		}
		return modeAuto
	}

	collect := func() Settings {
		return Settings{
			Relay: relayLE.Text(), RelayPass: relayPassLE.Text(), Extra: extraLE.Text(), OutDir: outLE.Text(),
			Compress: compressCB.Checked(), ProxyMode: curProxyMode(), ProxySel: selIndex(), Proxies: collectProxies(),
		}
	}

	setLog := func(s string) {
		if logTE.Text() == s {
			return
		}
		_ = logTE.SetText(s)
		n := len(utf16.Encode([]rune(s)))
		logTE.SetTextSelection(n, n)
		logTE.SendMessage(win.EM_SCROLLCARET, 0, 0)
	}
	setBusy := func(b bool) {
		sendBtn.SetEnabled(!b)
		recvBtn.SetEnabled(!b)
		checkBtn.SetEnabled(!b && !checking)
		stopBtn.SetEnabled(b)
	}
	refreshList := func() { _ = fileList.SetModel(append([]string{}, items...)) }
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
					_ = recvText.SetText(crlf(res.Text))
					tail += "\r\nПолучен текст."
				}
				if res.HasFiles {
					tail += "\r\nФайлы сохранены в: " + curOut
				}
			}
		}
		if code != 0 && strings.Contains(job.Log(), "лимит подключений") {
			tail += "\r\nПубличные relay ограничили подключения с вашего IP (лимит около 30 в минуту на IP; " +
				"если обе стороны за одним IP - счёт общий). Подождите минуту и повторите. " +
				"Для постоянной работы укажите свой relay на вкладке «Настройки»."
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
		_ = recvText.SetText("")
		j, created, err := startReceive(cur, pw, out)
		if err != nil {
			warn(err.Error())
			return
		}
		setLog("Ожидание отправителя...")
		begin(j, "recv", out, created)
	}

	// ---------- проверка соединения ----------
	showCheck := func(routes []Route, rowIdx []int, relays []string, res [][]CheckResult) {
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("Проверка серверов croc (%d шт.):\r\n", len(relays)))
		for i, rt := range routes {
			okN := 0
			best := time.Duration(0)
			for k := range relays {
				if res[i][k].Err == nil {
					okN++
					if best == 0 || res[i][k].RTT < best {
						best = res[i][k].RTT
					}
				}
			}
			summary := fmt.Sprintf("✗ 0/%d", len(relays))
			if okN > 0 {
				summary = fmt.Sprintf("✓ %d/%d, %d мс", okN, len(relays), best.Milliseconds())
			}
			if rowIdx[i] < 0 {
				_ = directLbl.SetText("Напрямую: " + summary)
			} else if rowIdx[i] < rowCount {
				_ = rows[rowIdx[i]].status.SetText(summary)
			}
			sb.WriteString(fmt.Sprintf("%s: %d из %d доступно\r\n", rt.Name(), okN, len(relays)))
			for k, rl := range relays {
				if res[i][k].Err != nil {
					sb.WriteString(fmt.Sprintf("    %s  ✗ %s\r\n", rl, shortErr(res[i][k].Err)))
				} else {
					sb.WriteString(fmt.Sprintf("    %s  ✓ %d мс\r\n", rl, res[i][k].RTT.Milliseconds()))
				}
			}
		}
		setLog(strings.TrimRight(sb.String(), "\r\n"))
	}
	doCheck := func() {
		if curJob != nil || checking {
			return
		}
		cur := collect()
		saveSettings(cur)
		routes, rowIdx := checkRoutes(cur)
		relays := publicRelays
		if r := strings.TrimSpace(cur.Relay); r != "" {
			relays = []string{r}
		}
		checking = true
		checkBtn.SetEnabled(false)
		_ = directLbl.SetText("")
		for i := 0; i < rowCount; i++ {
			_ = rows[i].status.SetText("...")
		}
		setLog("Проверка соединения с серверами croc (до 4 секунд)...")
		go func() {
			res := checkAll(routes, relays, 4*time.Second)
			mw.Synchronize(func() {
				checking = false
				checkBtn.SetEnabled(curJob == nil)
				showCheck(routes, rowIdx, relays, res)
			})
		}()
	}

	// ---------- строки прокси (декларативно) ----------
	var proxyRowWidgets []Widget
	for i := 0; i < maxProxies; i++ {
		i := i
		r := &proxyRow{}
		rows[i] = r
		proxyRowWidgets = append(proxyRowWidgets, Composite{
			AssignTo: &r.comp,
			Visible:  false,
			Layout:   HBox{MarginsZero: true},
			Children: []Widget{
				RadioButton{AssignTo: &r.sel, MaxSize: Size{Width: 22}, OnClicked: func() { selectRow(i) }},
				ComboBox{AssignTo: &r.typ, Model: []string{"SOCKS5", "SOCKS4", "HTTP"}, CurrentIndex: 0, MaxSize: Size{Width: 90}},
				LineEdit{AssignTo: &r.addr, CueBanner: "адрес:порт", MinSize: Size{Width: 150}},
				CheckBox{AssignTo: &r.auth, Text: "логин", OnCheckedChanged: func() { updateAuth(i) }},
				LineEdit{AssignTo: &r.user, CueBanner: "логин", MaxSize: Size{Width: 90}, Enabled: false},
				LineEdit{AssignTo: &r.pass, CueBanner: "пароль", PasswordMode: true, MaxSize: Size{Width: 90}, Enabled: false},
				PushButton{Text: "−", MaxSize: Size{Width: 28}, OnClicked: func() { removeRow(i) }},
				Label{AssignTo: &r.status, MinSize: Size{Width: 120}},
			},
		})
	}

	err := MainWindow{
		AssignTo: &mw,
		Title:    "crocau - передача файлов, папок и текста",
		MinSize:  Size{Width: 760, Height: 660},
		Size:     Size{Width: 800, Height: 720},
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
													_ = sendText.SetText(t)
												}
											}},
											VSpacer{},
										},
									},
								},
							},
							CheckBox{AssignTo: &compressCB, Text: "Сжать перед отправкой (текст и файлы; быстрее для больших файлов и множества мелких; уже сжатые форматы не пережимаются)", Checked: st.Compress},
							Composite{
								Layout: HBox{MarginsZero: true},
								Children: []Widget{
									Label{Text: "Пароль (от 3 символов):"},
									LineEdit{AssignTo: &sendPw, MaxSize: Size{Width: 160}},
									PushButton{Text: "Случайный", OnClicked: func() { _ = sendPw.SetText(randomPassword()) }},
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
							Label{Text: "Папка для сохранения файлов (архивы распаковываются автоматически):"},
							Composite{
								Layout: HBox{MarginsZero: true},
								Children: []Widget{
									LineEdit{AssignTo: &outLE, Text: st.OutDir},
									PushButton{Text: "Обзор...", OnClicked: func() {
										dlg := new(walk.FileDialog)
										dlg.Title = "Папка для сохранения"
										if ok, err := dlg.ShowBrowseFolder(mw); err == nil && ok {
											_ = outLE.SetText(dlg.FilePath)
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
						Title:  "Прокси",
						Layout: VBox{},
						Children: append(append([]Widget{
							Label{Text: "Режим подключения:"},
							Composite{
								Layout: VBox{MarginsZero: true},
								Children: []Widget{
									RadioButton{AssignTo: &modeDirRB, Text: "Прямое соединение", OnClicked: func() { setMode(modeDirect) }},
									RadioButton{AssignTo: &modeAutoRB, Text: "Авто: сначала напрямую, если не получается - все прокси по очереди", OnClicked: func() { setMode(modeAuto) }},
									RadioButton{AssignTo: &modeProxyRB, Text: "Только прокси (отмеченный кружком)", OnClicked: func() { setMode(modeProxy) }},
								},
							},
							Label{Text: "Прокси (тип, адрес:порт, при необходимости логин и пароль). SOCKS4 - с расширением 4a:"},
						}, proxyRowWidgets...), []Widget{
							Composite{
								Layout: HBox{MarginsZero: true},
								Children: []Widget{
									PushButton{AssignTo: &addBtn, Text: "+ Добавить прокси", OnClicked: addRow},
									PushButton{AssignTo: &checkBtn, Text: "Проверить соединение", OnClicked: doCheck},
									Label{AssignTo: &directLbl},
									HSpacer{},
								},
							},
							VSpacer{},
						}...),
					},
					{
						Title:  "Настройки",
						Layout: VBox{},
						Children: []Widget{
							Label{Text: "Адрес relay (host:порт). Пусто = автоматический выбор из публичных relay croc:"},
							LineEdit{AssignTo: &relayLE, Text: st.Relay},
							Label{Text: "Пароль relay (пусто = по умолчанию):"},
							LineEdit{AssignTo: &relayPassLE, Text: st.RelayPass},
							Label{Text: "Доп. общие ключи croc через пробел (например: --internal-dns --no-multi):"},
							LineEdit{AssignTo: &extraLE, Text: st.Extra},
							Label{Text: "Настройки (включая прокси и их пароли) хранятся в crocau.ini рядом с программой. Пароль передачи нигде не сохраняется."},
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

	// У системного поля ввода по умолчанию лимит около 30 000 байт (то есть ~15 000 символов Unicode).
	for _, te := range []*walk.TextEdit{sendText, recvText, logTE} {
		te.SetMaxLength(0x7FFFFFFE)
	}

	applyProxies(st.Proxies, st.ProxySel)
	setMode(st.ProxyMode)

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
			testDone <- guiTestSteps(mw, func() bool { return curJob != nil }, func(f func()) {
				ch := make(chan struct{})
				mw.Synchronize(func() {
					defer close(ch)
					f()
				})
				<-ch
			}, guiHooks{
				setRelay:    func(s string) { _ = relayLE.SetText(s) },
				setSendText: func(s string) { _ = sendText.SetText(s) },
				addFiles:    addPaths,
				setSendPw:   func(s string) { _ = sendPw.SetText(s) },
				setCompress: func(b bool) { compressCB.SetChecked(b) },
				send:        doSend,
				setRecvPw:   func(s string) { _ = recvPw.SetText(s) },
				setOut:      func(s string) { _ = outLE.SetText(s) },
				recv:        doReceive,
				recvText:    func() string { return recvText.Text() },
				proxyRoundTrip: func() string {
					want := []ProxyCfg{
						{Type: "socks5", Addr: "1.1.1.1:1080"},
						{Type: "http", Addr: "h:8080", Auth: true, User: "u", Pass: "p"},
						{Type: "socks4", Addr: "2.2.2.2:1081"},
					}
					applyProxies(want, 1)
					setMode(modeProxy)
					got := collect()
					if len(got.Proxies) != 3 || got.ProxySel != 1 || got.ProxyMode != modeProxy {
						return fmt.Sprintf("apply/collect mismatch: %+v", got)
					}
					for i := range want {
						if got.Proxies[i] != want[i] {
							return fmt.Sprintf("row %d mismatch: %+v vs %+v", i, got.Proxies[i], want[i])
						}
					}
					addRow()
					if rowCount != 4 {
						return "add row failed"
					}
					removeRow(0)
					g2 := collect()
					if len(g2.Proxies) != 3 || g2.Proxies[0] != want[1] || g2.ProxySel != 0 {
						return fmt.Sprintf("remove row failed: %+v", g2)
					}
					selectRow(2)
					if collect().ProxySel != 2 {
						return "select row failed"
					}
					tmp := filepath.Join(os.TempDir(), "crocau-gui-rt.ini")
					saveSettingsTo(tmp, collect())
					back := loadSettingsFrom(tmp)
					_ = os.Remove(tmp)
					if len(back.Proxies) != 3 || back.ProxySel != 2 || back.ProxyMode != modeProxy || back.Proxies[0] != want[1] {
						return fmt.Sprintf("persist failed: %+v", back)
					}
					applyProxies(nil, 0)
					setMode(modeAuto)
					return ""
				},
			})
		}()
		go func() {
			time.Sleep(200 * time.Second)
			testLogf("GUITEST: WATCHDOG TIMEOUT")
			os.Exit(1)
		}()
	}

	mw.Run()
	if test {
		select {
		case testExit = <-testDone:
		case <-time.After(10 * time.Second):
			testLogf("GUITEST: no result from test goroutine")
			testExit = 1
		}
	}
	return testExit
}

// longTestText строит текст из 40 000+ символов с переводами строк (больше старого лимита поля ввода).
func longTestText(head string) string {
	var sb strings.Builder
	sb.WriteString(head + "\r\n")
	for i := 0; utf8.RuneCountInString(sb.String()) < 40000; i++ {
		fmt.Fprintf(&sb, "строка %d - проверка длинного текста\r\n", i)
	}
	return sb.String()
}

type guiHooks struct {
	setRelay, setSendText, setSendPw, setRecvPw, setOut func(string)
	addFiles                                            func([]string)
	setCompress                                         func(bool)
	send, recv                                          func()
	recvText                                            func() string
	proxyRoundTrip                                      func() string
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
	var relay *Job
	finishTest := func() int {
		if relay != nil {
			relay.Kill()
		}
		ui(func() { mw.Close() })
		if fails == 0 {
			testLogf("GUITEST PASSED")
			return 0
		}
		testLogf("GUITEST FAILED")
		return 1
	}

	// 0) строки прокси: добавление, удаление, выбор, сохранение
	var rt string
	ui(func() { rt = h.proxyRoundTrip() })
	if rt == "" {
		testLogf("GUI PROXY ROWS (add/remove/select/persist): OK")
	} else {
		fails++
		testLogf("GUI PROXY ROWS: FAIL %s", rt)
	}

	testLogf("step0: starting relay")
	var err error
	relay, err = startTestRelay()
	if err != nil {
		testLogf("relay error: %v", err)
		fails++
		return finishTest()
	}
	s := Settings{Relay: "127.0.0.1:19009"}
	ui(func() { h.setRelay("127.0.0.1:19009") })
	testLogf("step0: relay ready, UI reachable")

	src, _ := newWork()
	f1 := filepath.Join(src, "gui файл.bin")
	data := randBytes(262144)
	_ = os.WriteFile(f1, data, 0644)

	// 1) окно отправляет длинный текст (40 000+ символов) + файл (со сжатием), принимает "внешний" процесс
	text1 := longTestText("Привет из GUI")
	ui(func() {
		h.setSendText(text1)
		h.addFiles([]string{f1})
		h.setSendPw("abc")
		h.setCompress(true)
		h.send()
	})
	testLogf("step1: GUI send clicked (compression on)")
	time.Sleep(2500 * time.Millisecond)
	dst1, _ := newWork()
	rcv, created, err := startReceive(s, "abc", dst1)
	if err != nil {
		testLogf("startReceive error: %v", err)
		fails++
	} else {
		okR := rcv.Wait(60 * time.Second)
		res := finalizeReceive(rcv, dst1, created)
		if okR && res.Text == text1 && fileEquals(filepath.Join(dst1, "gui файл.bin"), data) {
			testLogf("GUI SEND text+file (compressed): OK")
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
	ui(func() { h.setCompress(false) })

	// 2) "внешний" процесс отправляет текст + файл, принимает окно
	text2 := longTestText("второй текст")
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
