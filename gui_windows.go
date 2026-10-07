//go:build windows

package main

import (
	"errors"
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

const settingsInfoText = "Настройки хранятся в crocau.ini рядом с программой. Пароли (прокси, relay и отмеченные «запомнить» " +
	"пароли передачи) сохраняются только в зашифрованном виде. Без мастер-пароля защита привязана к вашей учётной записи " +
	"Windows на этом компьютере (на другом компьютере пароли придётся ввести заново). С мастер-паролем пароли открываются " +
	"на любом компьютере, но мастер-пароль спрашивается при запуске и его нельзя восстановить."

// promptPassword показывает окно ввода пароля (при confirm - с повтором). Возвращает пароль и признак "нажали OK".
func promptPassword(owner walk.Form, title, message string, confirm bool, okText, cancelText string) (string, bool) {
	var dlg *walk.Dialog
	var pw1, pw2 *walk.LineEdit
	var okBtn, cancelBtn *walk.PushButton
	result, accepted := "", false
	children := []Widget{
		Label{Text: message},
		LineEdit{AssignTo: &pw1, PasswordMode: true},
	}
	if confirm {
		children = append(children, Label{Text: "Повторите:"}, LineEdit{AssignTo: &pw2, PasswordMode: true})
	}
	children = append(children, Composite{
		Layout: HBox{MarginsZero: true},
		Children: []Widget{
			HSpacer{},
			PushButton{AssignTo: &okBtn, Text: okText, OnClicked: func() {
				if confirm && pw1.Text() != pw2.Text() {
					walk.MsgBox(dlg, title, "Пароли не совпадают.", walk.MsgBoxIconWarning)
					return
				}
				result, accepted = pw1.Text(), true
				dlg.Accept()
			}},
			PushButton{AssignTo: &cancelBtn, Text: cancelText, OnClicked: func() { dlg.Cancel() }},
		},
	})
	if _, err := (Dialog{
		AssignTo:      &dlg,
		Title:         title,
		DefaultButton: &okBtn,
		CancelButton:  &cancelBtn,
		MinSize:       Size{Width: 380, Height: 150},
		Layout:        VBox{},
		Children:      children,
	}).Run(owner); err != nil {
		return "", false
	}
	return result, accepted
}

const (
	destInternet = "Через интернет"
	destWait     = "Ждать получателя в сети"
)

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
	if st.Locked {
		if st.MasterSalt == "" || test {
			settingsReadOnly = true
		} else {
			for {
				pw, ok := promptPassword(nil, "crocau", "Мастер-пароль для сохранённых настроек:", false, "Разблокировать", "Пропустить")
				if !ok {
					settingsReadOnly = true
					break
				}
				if err := masterUnlock(pw, st.MasterSalt, st.MasterCheck); err != nil {
					walk.MsgBox(nil, "crocau", err.Error(), walk.MsgBoxIconWarning)
					continue
				}
				st = loadSettings()
				break
			}
		}
	}
	var (
		mw              *walk.MainWindow
		sendText        *walk.TextEdit
		fileList        *walk.ListBox
		sendPw          *walk.LineEdit
		compressCB      *walk.CheckBox
		saveSendCB      *walk.CheckBox
		saveRecvCB      *walk.CheckBox
		recvPw          *walk.LineEdit
		outLE           *walk.LineEdit
		recvText        *walk.TextEdit
		relayLE         *walk.LineEdit
		relayPassLE     *walk.LineEdit
		extraLE         *walk.LineEdit
		logTE           *walk.TextEdit
		sendBtn         *walk.PushButton
		recvBtn         *walk.PushButton
		stopBtn         *walk.PushButton
		addBtn          *walk.PushButton
		checkBtn        *walk.PushButton
		modeDirRB       *walk.RadioButton
		modeAutoRB      *walk.RadioButton
		modeProxyRB     *walk.RadioButton
		directLbl       *walk.Label
		tabs            *walk.TabWidget
		masterStatusLbl *walk.Label
		masterSetBtn    *walk.PushButton
		masterOffBtn    *walk.PushButton
		ni              *walk.NotifyIcon
		destCB          *walk.ComboBox
		srcCB           *walk.ComboBox
		outRelCB        *walk.CheckBox
		exchNameLE      *walk.LineEdit
		exchPwLE        *walk.LineEdit
		saveExchCB      *walk.CheckBox
		exchAutoCB      *walk.CheckBox
		exchBtn         *walk.PushButton
		exchStatusLbl   *walk.Label
		fwStatusLbl     *walk.Label
		histLB          *walk.ListBox
		exchText        *walk.TextEdit
	)
	var items []string
	var curJob *Job
	var curMode, curOut string
	var curCreated bool
	checking := false
	var exch Exchange
	var peers []Peer
	var curHost *HostSession
	var history, histTexts []string
	curLAN := false
	hostName, _ := os.Hostname()
	if st.ExchName == "" {
		st.ExchName = hostName
	}
	trayHidden := false
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

	sealWarned := false
	saveNow := func(cur Settings) {
		if err := saveSettings(cur); err != nil && !sealWarned {
			sealWarned = true
			warn("Не удалось сохранить пароли в защищённом виде: " + err.Error() +
				"\n\nОстальные настройки сохранены, пароли - нет.")
		}
	}
	savedPw := func(cb *walk.CheckBox, le *walk.LineEdit) string {
		if cb.Checked() {
			return strings.TrimSpace(le.Text())
		}
		return ""
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
			Compress:   compressCB.Checked(),
			OutRel:     outRelCB.Checked(),
			SaveSendPw: saveSendCB.Checked(), SendPw: savedPw(saveSendCB, sendPw),
			SaveRecvPw: saveRecvCB.Checked(), RecvPw: savedPw(saveRecvCB, recvPw),
			ExchName: strings.TrimSpace(exchNameLE.Text()), ExchAuto: exchAutoCB.Checked(),
			SaveExchPw: saveExchCB.Checked(), ExchPw: savedPw(saveExchCB, exchPwLE), ProxyMode: curProxyMode(), ProxySel: selIndex(), Proxies: collectProxies(),
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
		if code != 0 && curLAN && strings.Contains(job.Log(), "could not connect") {
			if curMode == "recv" {
				tail += "\r\nОтправитель не отвечает. На его устройстве на вкладке «Отправить» выберите «Ждать получателя в сети» " +
					"и нажмите «Отправить»; проверьте брандмауэр (кнопка «Открыть порты» на вкладке «Обмен» там же)."
			} else {
				tail += "\r\nУстройство не отвечает. На нём должен быть включён режим обмена (вкладка «Обмен»), " +
					"а брандмауэр должен пропускать порты (кнопка «Открыть порты» на том устройстве)."
			}
		}
		if curHost != nil {
			h := curHost
			curHost = nil
			go h.Close()
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
		saveNow(cur)
		target := strings.TrimSpace(destCB.Text())
		if target == destWait {
			if exch.Running() {
				warn(errBusyRole.Error())
				return
			}
			name := strings.TrimSpace(exchNameLE.Text())
			if name == "" {
				name = hostName
			}
			j, host, note, err := startHostedSend(cur, pw, text, items, name)
			if err != nil {
				warn(err.Error())
				return
			}
			curHost, curLAN = host, false
			setLog("Ожидание получателя в локальной сети...\r\n" + note)
			begin(j, "send", "", false)
			return
		}
		lan := target != "" && !strings.HasPrefix(target, destInternet)
		lanAddr := ""
		if lan {
			a, ok := "", false
			for _, p := range peers {
				if p.Label() == target {
					a, ok = p.Addr(), true
					break
				}
			}
			if !ok {
				a, ok = parseLANAddr(target)
			}
			if !ok {
				warn("Укажите IP-адрес устройства (например 192.168.1.5), выберите его из списка или выберите «Через интернет».")
				return
			}
			lanAddr = a
			cur.Relay, cur.RelayPass, cur.ProxyMode, cur.Proxies = a, "", modeDirect, nil
		}
		j, err := startSend(cur, pw, text, items)
		if err != nil {
			warn(err.Error())
			return
		}
		curLAN = lan
		if lan {
			setLog("Отправка по локальной сети на " + lanAddr + "...\r\nНа том устройстве должен быть включён режим обмена с тем же паролем. " +
				"Если ничего не происходит, проверьте пароль.")
		} else {
			setLog("Отправка запущена. Передайте получателю пароль и дождитесь подключения...")
		}
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
		saveNow(cur)
		_ = recvText.SetText("")
		source := strings.TrimSpace(srcCB.Text())
		lan := source != "" && !strings.HasPrefix(source, destInternet)
		lanAddr := ""
		if lan {
			a, ok := "", false
			for _, p := range peers {
				if p.Label() == source {
					a, ok = p.Addr(), true
					break
				}
			}
			if !ok {
				a, ok = parseLANAddr(source)
			}
			if !ok {
				warn("Укажите IP-адрес отправителя (например 192.168.1.5), выберите его из списка или выберите «Через интернет».")
				return
			}
			lanAddr = a
			cur.Relay, cur.RelayPass, cur.ProxyMode, cur.Proxies = a, "", modeDirect, nil
		}
		j, created, err := startReceive(cur, pw, out)
		if err != nil {
			warn(err.Error())
			return
		}
		curLAN = lan
		if lan {
			setLog("Подключение к отправителю " + lanAddr + "...\r\nПароль должен совпадать с паролем отправителя.")
		} else {
			setLog("Ожидание отправителя...")
		}
		begin(j, "recv", out, created)
	}

	// ---------- трей ----------
	// notify показывает стандартное уведомление, но только если окно свёрнуто в трей.
	notify := func(title, msg string) {
		if trayHidden && ni != nil {
			_ = ni.ShowInfo(title, msg)
		}
	}
	_ = notify
	restoreFromTray := func() {
		if ni != nil {
			_ = ni.SetVisible(false)
		}
		trayHidden = false
		mw.SetVisible(true)
		win.ShowWindow(mw.Handle(), win.SW_RESTORE)
		win.SetForegroundWindow(mw.Handle())
	}
	hideToTray := func() error {
		if ni == nil {
			return errors.New("значок в области уведомлений недоступен")
		}
		if err := ni.SetVisible(true); err != nil {
			return err
		}
		trayHidden = true
		mw.SetVisible(false)
		return nil
	}

	// ---------- локальная сеть и режим обмена ----------
	refreshPeers := func() {
		go func() {
			found := discoverPeers(1500*time.Millisecond, instanceID, "", broadcastTargets())
			mw.Synchronize(func() {
				peers = found
				destItems := []string{destInternet, destWait}
				srcItems := []string{destInternet}
				for _, p := range found {
					if p.Role == roleRecv {
						destItems = append(destItems, p.Label())
					} else if p.Role == roleSend {
						srcItems = append(srcItems, p.Label())
					}
				}
				for _, c := range []struct {
					cb    *walk.ComboBox
					items []string
				}{{destCB, destItems}, {srcCB, srcItems}} {
					cur := c.cb.Text()
					_ = c.cb.SetModel(c.items)
					if cur != "" {
						_ = c.cb.SetText(cur)
					} else {
						_ = c.cb.SetCurrentIndex(0)
					}
				}
			})
		}()
	}
	exchStatus := func(full string) {
		short := full
		if r := []rune(short); len(r) > 64 {
			short = string(r[:64]) + "..."
		}
		_ = exchStatusLbl.SetText(short)
		_ = exchStatusLbl.SetToolTipText(full)
	}
	refreshFW := func() {
		go func() {
			ok := fwPresent()
			mw.Synchronize(func() {
				if ok {
					_ = fwStatusLbl.SetText("Брандмауэр: порты открыты")
				} else {
					_ = fwStatusLbl.SetText("Брандмауэр: порты не открыты")
				}
			})
		}()
	}
	showHist := func() {
		i := histLB.CurrentIndex()
		if i >= 0 && i < len(histTexts) {
			_ = exchText.SetText(crlf(histTexts[i]))
		}
	}
	handleExch := func(ev ExchangeEvent) {
		switch ev.Kind {
		case "received":
			var parts []string
			if ev.Text != "" {
				parts = append(parts, fmt.Sprintf("текст (%d симв.)", utf8.RuneCountInString(ev.Text)))
			}
			if len(ev.Names) > 0 {
				names := ev.Names
				more := ""
				if len(names) > 3 {
					more = fmt.Sprintf(" и ещё %d", len(names)-3)
					names = names[:3]
				}
				parts = append(parts, "файлы: "+strings.Join(names, ", ")+more)
			} else if ev.Files {
				parts = append(parts, "файлы")
			}
			summary := strings.Join(parts, "; ")
			if summary == "" {
				summary = "данные"
			}
			history = append([]string{ev.Time.Format("15:04:05") + "  " + summary}, history...)
			histTexts = append([]string{ev.Text}, histTexts...)
			_ = histLB.SetModel(append([]string{}, history...))
			_ = histLB.SetCurrentIndex(0)
			_ = exchText.SetText(crlf(ev.Text))
			exchStatus("Получено: " + summary)
			notify("crocau: получено", summary)
		default:
			exchStatus(ev.Msg)
		}
	}
	startExchange := func() {
		pw := strings.TrimSpace(exchPwLE.Text())
		name := strings.TrimSpace(exchNameLE.Text())
		if name == "" {
			name = hostName
		}
		saveNow(collect())
		err := exch.Start(pw, strings.TrimSpace(outLE.Text()), name, func(ev ExchangeEvent) {
			mw.Synchronize(func() { handleExch(ev) })
		})
		if err != nil {
			warn(err.Error())
			return
		}
		_ = exchBtn.SetText("Выключить обмен")
		refreshFW()
	}
	toggleExchange := func() {
		if exch.Running() {
			exch.Stop()
			_ = exchBtn.SetText("Включить обмен")
			exchStatus("Выключен")
			return
		}
		startExchange()
	}
	fwAction := func(open bool) {
		_ = fwStatusLbl.SetText("Брандмауэр: ждём подтверждение администратора...")
		go func() {
			var err error
			if open {
				err = fwEnsure()
			} else {
				err = fwRemove()
			}
			mw.Synchronize(func() {
				if err != nil {
					warn("Брандмауэр: " + err.Error())
				}
				refreshFW()
			})
		}()
	}

	// ---------- мастер-пароль ----------
	refreshMasterUI := func() {
		switch {
		case settingsReadOnly:
			_ = masterStatusLbl.SetText("Не введён: в этом сеансе настройки не сохраняются")
			masterSetBtn.SetEnabled(false)
			masterOffBtn.SetEnabled(false)
		case vaultIsMaster():
			_ = masterStatusLbl.SetText("Включён (переносимо, спрашивается при запуске)")
			_ = masterSetBtn.SetText("Сменить мастер-пароль...")
			masterSetBtn.SetEnabled(true)
			masterOffBtn.SetEnabled(true)
		default:
			_ = masterStatusLbl.SetText("Выключен (защита привязана к этому компьютеру)")
			_ = masterSetBtn.SetText("Задать мастер-пароль...")
			masterSetBtn.SetEnabled(true)
			masterOffBtn.SetEnabled(false)
		}
	}
	masterSet := func() {
		if settingsReadOnly {
			return
		}
		pw, ok := promptPassword(mw, "Мастер-пароль", "Новый мастер-пароль (не короче 6 символов):", true, "OK", "Отмена")
		if !ok {
			return
		}
		if utf8.RuneCountInString(pw) < 6 {
			warn("Мастер-пароль должен быть не короче 6 символов.")
			return
		}
		if err := masterEnable(pw); err != nil {
			warn(err.Error())
			return
		}
		saveNow(collect())
		refreshMasterUI()
		setLog("Мастер-пароль включён: сохранённые пароли зашифрованы им и открываются на любом компьютере. Не забудьте его - восстановить нельзя.")
	}
	masterOff := func() {
		if settingsReadOnly || !vaultIsMaster() {
			return
		}
		if walk.MsgBox(mw, "Мастер-пароль", "Выключить мастер-пароль? Сохранённые пароли будут привязаны к этому компьютеру и перестанут открываться на других.",
			walk.MsgBoxYesNo|walk.MsgBoxIconQuestion) != walk.DlgCmdYes {
			return
		}
		masterDisable()
		saveNow(collect())
		refreshMasterUI()
		setLog("Мастер-пароль выключен.")
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
		saveNow(cur)
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
				LineEdit{AssignTo: &r.addr, CueBanner: "адрес:порт", MinSize: Size{Width: 120}},
				CheckBox{AssignTo: &r.auth, Text: "логин", OnCheckedChanged: func() { updateAuth(i) }},
				LineEdit{AssignTo: &r.user, CueBanner: "логин", MinSize: Size{Width: 60}, MaxSize: Size{Width: 100}, Enabled: false},
				LineEdit{AssignTo: &r.pass, CueBanner: "пароль", PasswordMode: true, MinSize: Size{Width: 60}, MaxSize: Size{Width: 100}, Enabled: false},
				PushButton{Text: "−", MaxSize: Size{Width: 28}, OnClicked: func() { removeRow(i) }},
				Label{AssignTo: &r.status, MinSize: Size{Width: 100}},
			},
		})
	}

	err := MainWindow{
		AssignTo: &mw,
		Title:    "crocau - передача файлов, папок и текста",
		MinSize:  Size{Width: 650, Height: 600},
		Size:     Size{Width: 740, Height: 660},
		Layout:   VBox{},
		Children: []Widget{
			TabWidget{
				AssignTo: &tabs,
				Pages: []TabPage{
					{
						Title:  "Отправить",
						Layout: VBox{},
						Children: []Widget{
							Label{Text: "Текст (необязательно):"},
							TextEdit{AssignTo: &sendText, VScroll: true, MinSize: Size{Height: 60}},
							Label{Text: "Файлы и папки (необязательно; можно перетащить в окно):"},
							Composite{
								Layout: HBox{MarginsZero: true},
								Children: []Widget{
									ListBox{AssignTo: &fileList, MultiSelection: true, MinSize: Size{Height: 70}},
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
							Composite{
								Layout: HBox{MarginsZero: true},
								Children: []Widget{
									Label{Text: "Куда:"},
									ComboBox{AssignTo: &destCB, Editable: true, Model: []string{destInternet}, CurrentIndex: 0, MinSize: Size{Width: 180},
										ToolTipText: "«Через интернет» - публичные relay.\r\n«Ждать получателя в сети» - это устройство открывает порт и ждёт, получатель находит его на вкладке «Получить» или вводит ваш IP.\r\nУстройство из списка - получатель в режиме обмена (вкладка «Обмен»). Можно вписать IP вручную, например 192.168.1.5."},
									PushButton{Text: "Найти в сети", OnClicked: refreshPeers},
									HSpacer{},
								},
							},
							CheckBox{AssignTo: &compressCB, Text: "Умное сжатие", ToolTipText: smartCompressHint(), Checked: st.Compress},
							Composite{
								Layout: HBox{MarginsZero: true},
								Children: []Widget{
									Label{Text: "Пароль:", ToolTipText: "От 3 символов"},
									LineEdit{AssignTo: &sendPw, Text: st.SendPw, MinSize: Size{Width: 90}, MaxSize: Size{Width: 160}, ToolTipText: "Пароль передачи: от 3 символов"},
									CheckBox{AssignTo: &saveSendCB, Text: "запомнить", Checked: st.SaveSendPw},
									PushButton{Text: "Случайный", OnClicked: func() { _ = sendPw.SetText(randomPassword()) }},
									HSpacer{},
									PushButton{AssignTo: &sendBtn, Text: "Отправить", MinSize: Size{Width: 110}, OnClicked: doSend},
								},
							},
						},
					},
					{
						Title:  "Получить",
						Layout: VBox{},
						Children: []Widget{
							Composite{
								Layout: HBox{MarginsZero: true},
								Children: []Widget{
									Label{Text: "Откуда:"},
									ComboBox{AssignTo: &srcCB, Editable: true, Model: []string{destInternet}, CurrentIndex: 0, MinSize: Size{Width: 180},
										ToolTipText: "«Через интернет» - публичные relay.\r\nИли отправитель в вашей сети (он выбрал «Ждать получателя в сети»): найдите его кнопкой «Найти в сети» или впишите его IP, например 192.168.1.5."},
									PushButton{Text: "Найти в сети", OnClicked: refreshPeers},
									HSpacer{},
								},
							},
							Label{Text: "Пароль (тот, что задал отправитель):"},
							Composite{
								Layout: HBox{MarginsZero: true},
								Children: []Widget{
									LineEdit{AssignTo: &recvPw, Text: st.RecvPw, MaxSize: Size{Width: 200}},
									CheckBox{AssignTo: &saveRecvCB, Text: "запомнить", Checked: st.SaveRecvPw},
									HSpacer{},
								},
							},
							Label{Text: "Папка для сохранения (архивы распаковываются сами):"},
							Composite{
								Layout: HBox{MarginsZero: true},
								Children: []Widget{
									LineEdit{AssignTo: &outLE, Text: resolveOutDir(st.OutDir)},
									CheckBox{AssignTo: &outRelCB, Text: "от программы", Checked: st.OutRel,
										ToolTipText: "Хранить путь папки относительно crocau.exe: папку программы можно переносить на другие устройства, и приём сразу пойдёт в её же подпапку. Если папка на другом диске, путь остаётся полным."},
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
									TextEdit{AssignTo: &recvText, ReadOnly: true, VScroll: true, MinSize: Size{Height: 70}},
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
									PushButton{AssignTo: &recvBtn, Text: "Получить", MinSize: Size{Width: 110}, OnClicked: doReceive},
									HSpacer{},
								},
							},
						},
					},
					{
						Title:  "Обмен",
						Layout: VBox{},
						Children: []Widget{
							Label{Text: "Принимает файлы и текст от устройств в вашей сети.", ToolTipText: "Режим непрерывного обмена: устройство остаётся на связи, другие устройства сети находят его (кнопка «Найти в сети» на вкладке «Отправить») и присылают данные с этим же паролем. Файлы сохраняются в папку со вкладки «Получить»."},
							Composite{
								Layout: HBox{MarginsZero: true},
								Children: []Widget{
									Label{Text: "Имя:"},
									LineEdit{AssignTo: &exchNameLE, Text: st.ExchName, MinSize: Size{Width: 80}, MaxSize: Size{Width: 130}, ToolTipText: "Так это устройство будет называться в списке у других"},
									Label{Text: "Пароль:"},
									LineEdit{AssignTo: &exchPwLE, Text: st.ExchPw, MinSize: Size{Width: 90}, MaxSize: Size{Width: 140}, ToolTipText: "От 3 символов, одинаковый на всех ваших устройствах"},
									CheckBox{AssignTo: &saveExchCB, Text: "запомнить", Checked: st.SaveExchPw},
									PushButton{Text: "Случайный", OnClicked: func() { _ = exchPwLE.SetText(randomPassword()) }},
									HSpacer{},
								},
							},
							Composite{
								Layout: HBox{MarginsZero: true},
								Children: []Widget{
									CheckBox{AssignTo: &exchAutoCB, Text: "Включать при запуске", Checked: st.ExchAuto, ToolTipText: "Нужен запомненный пароль"},
									HSpacer{},
									PushButton{AssignTo: &exchBtn, Text: "Включить обмен", MinSize: Size{Width: 130}, OnClicked: toggleExchange},
								},
							},
							Label{AssignTo: &exchStatusLbl, Text: "Выключен"},
							Composite{
								Layout: HBox{MarginsZero: true},
								Children: []Widget{
									Label{AssignTo: &fwStatusLbl, Text: "Брандмауэр: проверяем..."},
									PushButton{Text: "Открыть порты", ToolTipText: "Создать правила Windows для crocau.exe (TCP 29009-29013, UDP 29008). Один раз попросит подтверждение администратора", OnClicked: func() { fwAction(true) }},
									PushButton{Text: "Закрыть порты", ToolTipText: "Удалить созданные правила", OnClicked: func() { fwAction(false) }},
									HSpacer{},
								},
							},
							Label{Text: "Получено (щёлкните строку, чтобы увидеть текст):"},
							ListBox{AssignTo: &histLB, MinSize: Size{Height: 60}, OnCurrentIndexChanged: showHist},
							Composite{
								Layout: HBox{MarginsZero: true},
								Children: []Widget{
									TextEdit{AssignTo: &exchText, ReadOnly: true, VScroll: true, MinSize: Size{Height: 50}},
									PushButton{Text: "Копировать", OnClicked: func() {
										if t := exchText.Text(); t != "" {
											_ = walk.Clipboard().SetText(t)
										}
									}},
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
							Label{Text: "Прокси: тип, адрес:порт, логин и пароль (по галочке)", ToolTipText: "SOCKS4 работает с расширением 4a (имена серверов передаются прокси)"},
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
							Label{Text: "Адрес relay (host:порт); пусто = публичные relay croc:"},
							LineEdit{AssignTo: &relayLE, Text: st.Relay},
							Label{Text: "Пароль relay (пусто = по умолчанию):"},
							LineEdit{AssignTo: &relayPassLE, Text: st.RelayPass},
							Label{Text: "Доп. ключи croc через пробел (например: --no-multi):"},
							LineEdit{AssignTo: &extraLE, Text: st.Extra},
							Label{Text: "Мастер-пароль (по желанию):"},
							Label{AssignTo: &masterStatusLbl},
							Composite{
								Layout: HBox{MarginsZero: true},
								Children: []Widget{
									PushButton{AssignTo: &masterSetBtn, Text: "Задать мастер-пароль...", OnClicked: masterSet},
									PushButton{AssignTo: &masterOffBtn, Text: "Выключить", OnClicked: masterOff},
									HSpacer{},
								},
							},
							TextEdit{ReadOnly: true, VScroll: true, MinSize: Size{Height: 60}, Text: settingsInfoText},
						},
					},
				},
			},
			Label{Text: "Ход передачи:"},
			TextEdit{AssignTo: &logTE, ReadOnly: true, VScroll: true, MinSize: Size{Height: 90},
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
					PushButton{Text: "В трей", ToolTipText: "Свернуть в область уведомлений (значок возле часов). Вернуть окно: щелчок по значку", OnClicked: func() {
						if err := hideToTray(); err != nil {
							warn("Не удалось свернуть в трей: " + err.Error())
						}
					}},
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
	for _, te := range []*walk.TextEdit{sendText, recvText, logTE, exchText} {
		te.SetMaxLength(0x7FFFFFFE)
	}

	// Иконка окна - из ресурсов exe (rsrc: манифест = ID 1, группа иконок = ID 2).
	icon, iconErr := walk.NewIconFromResourceId(2)
	if iconErr == nil {
		_ = mw.SetIcon(icon)
	}

	// значок в области уведомлений (виден только пока окно свёрнуто в трей)
	if n, err := walk.NewNotifyIcon(mw); err == nil {
		ni = n
		if iconErr == nil {
			_ = ni.SetIcon(icon)
		}
		_ = ni.SetToolTip("crocau")
		show := walk.NewAction()
		_ = show.SetText("Показать окно")
		show.Triggered().Attach(restoreFromTray)
		quit := walk.NewAction()
		_ = quit.SetText("Выход")
		quit.Triggered().Attach(func() {
			restoreFromTray()
			_ = mw.Close()
		})
		_ = ni.ContextMenu().Actions().Add(show)
		_ = ni.ContextMenu().Actions().Add(quit)
		ni.MessageClicked().Attach(restoreFromTray)
		ni.MouseDown().Attach(func(x, y int, button walk.MouseButton) {
			if button == walk.LeftButton {
				restoreFromTray()
			}
		})
	}

	applyProxies(st.Proxies, st.ProxySel)
	setMode(st.ProxyMode)
	if st.SecretNote != "" {
		setLog(st.SecretNote)
	}
	if settingsReadOnly && !test {
		setLog("Мастер-пароль не введён: сохранённые пароли недоступны, настройки в этом сеансе не сохраняются.")
	}
	refreshMasterUI()
	widenTooltips(560, 30000)
	refreshFW()
	exchStatus("Выключен")
	if !test {
		refreshPeers() // сразу заполнить список устройств
		if st.ExchAuto && st.SaveExchPw && st.ExchPw != "" && !settingsReadOnly {
			mw.Synchronize(startExchange)
		}
	}

	win.DragAcceptFiles(mw.Handle(), true)
	mw.DropFiles().Attach(func(files []string) { addPaths(files) })
	mw.Closing().Attach(func(canceled *bool, reason walk.CloseReason) {
		exch.Stop()
		if curHost != nil {
			curHost.Close()
		}
		if ni != nil {
			_ = ni.Dispose()
		}
		_ = saveSettings(collect())
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
				iconErr:     iconErr,
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
				minSizeCheck: func() string {
					_ = tabs.SetCurrentIndex(0)
					var problems, sizes []string
					for i := 0; i < 5; i++ {
						_ = tabs.SetCurrentIndex(i)
						_ = mw.SetBounds(walk.Rectangle{X: 20, Y: 20, Width: 900, Height: 800})
						_ = mw.SetBounds(walk.Rectangle{X: 20, Y: 20, Width: 650, Height: 600})
						b := mw.Bounds()
						sizes = append(sizes, fmt.Sprintf("%dx%d", b.Width, b.Height))
						if b.Width > 652 || b.Height > 602 {
							problems = append(problems, fmt.Sprintf("tab %d: %dx%d", i, b.Width, b.Height))
						}
					}
					_ = tabs.SetCurrentIndex(0)
					_ = mw.SetBounds(walk.Rectangle{X: 20, Y: 20, Width: 800, Height: 700})
					testLogf("MINSIZE per tab at 650x600 request: %s", strings.Join(sizes, ", "))
					return strings.Join(problems, "; ")
				},
				setDest: func(t string) { _ = destCB.SetText(t) },
				setSrc:  func(t string) { _ = srcCB.SetText(t) },
				exchSetup: func(pw, name string) {
					_ = exchPwLE.SetText(pw)
					_ = exchNameLE.SetText(name)
				},
				exchToggle:  toggleExchange,
				exchRunning: exch.Running,
				exchHistory: func() (int, string) {
					if len(histTexts) == 0 {
						return 0, ""
					}
					return len(histTexts), histTexts[0]
				},
				trayHide: func() string {
					if err := hideToTray(); err != nil {
						return err.Error()
					}
					return ""
				},
				trayShow: restoreFromTray,
				trayTest: func() string {
					if ni == nil {
						return "skip: нет значка в области уведомлений"
					}
					if err := hideToTray(); err != nil {
						return "skip: " + err.Error()
					}
					hidden := !mw.Visible() && ni.Visible() && trayHidden
					notifyErr := ni.ShowInfo("crocau", "Проверка уведомления")
					restoreFromTray()
					shown := mw.Visible() && !ni.Visible() && !trayHidden
					if !hidden || !shown {
						return fmt.Sprintf("hidden=%v shown=%v", hidden, shown)
					}
					if notifyErr != nil {
						return "skip-notify: " + notifyErr.Error()
					}
					return ""
				},
				masterUITest: func() string {
					if err := masterEnable("test-master-1"); err != nil {
						return err.Error()
					}
					refreshMasterUI()
					if !strings.Contains(masterStatusLbl.Text(), "Включён") || !masterOffBtn.Enabled() {
						masterDisable()
						return "enabled state not shown"
					}
					_ = sendPw.SetText("mpw")
					saveSendCB.SetChecked(true)
					tmp := filepath.Join(os.TempDir(), "crocau-gui-master.ini")
					if err := saveSettingsTo(tmp, collect()); err != nil {
						masterDisable()
						return "save failed: " + err.Error()
					}
					masterDisable()
					locked := loadSettingsFrom(tmp)
					if !locked.Locked || locked.SendPw != "" {
						return "file not locked after restart"
					}
					if err := masterUnlock("test-master-1", locked.MasterSalt, locked.MasterCheck); err != nil {
						return "unlock failed: " + err.Error()
					}
					back := loadSettingsFrom(tmp)
					_ = os.Remove(tmp)
					masterDisable()
					refreshMasterUI()
					if back.SendPw != "mpw" || !strings.Contains(masterStatusLbl.Text(), "Выключен") {
						return "restore failed"
					}
					_ = sendPw.SetText("")
					saveSendCB.SetChecked(false)
					return ""
				},
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
					if err := saveSettingsTo(tmp, collect()); err != nil {
						return "save failed: " + err.Error()
					}
					back := loadSettingsFrom(tmp)
					_ = os.Remove(tmp)
					if len(back.Proxies) != 3 || back.ProxySel != 2 || back.ProxyMode != modeProxy || back.Proxies[0] != want[1] {
						return fmt.Sprintf("persist failed: %+v", back)
					}
					// сохранение паролей передачи по галочке
					_ = sendPw.SetText("  tpw1 ")
					saveSendCB.SetChecked(true)
					_ = recvPw.SetText("rpw2")
					saveRecvCB.SetChecked(false)
					c := collect()
					if c.SendPw != "tpw1" || !c.SaveSendPw || c.RecvPw != "" || c.SaveRecvPw {
						return fmt.Sprintf("saved password flags wrong: %+v", c)
					}
					if err := saveSettingsTo(tmp, c); err != nil {
						return "save pw failed: " + err.Error()
					}
					raw, _ := os.ReadFile(tmp)
					back = loadSettingsFrom(tmp)
					_ = os.Remove(tmp)
					if strings.Contains(string(raw), "tpw1") || strings.Contains(string(raw), "rpw2") {
						return "password leaked into ini in plain text"
					}
					if back.SendPw != "tpw1" || !back.SaveSendPw || back.RecvPw != "" || back.SecretNote != "" {
						return fmt.Sprintf("saved password not restored: %+v", back)
					}
					_ = sendPw.SetText("")
					saveSendCB.SetChecked(false)
					_ = recvPw.SetText("")
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
	iconErr                                             error
	setRelay, setSendText, setSendPw, setRecvPw, setOut func(string)
	addFiles                                            func([]string)
	setCompress                                         func(bool)
	send, recv                                          func()
	recvText                                            func() string
	proxyRoundTrip                                      func() string
	masterUITest, minSizeCheck, trayTest                func() string
	exchSetup                                           func(pw, name string)
	setDest, setSrc                                     func(string)
	exchToggle, trayShow                                func()
	exchRunning                                         func() bool
	exchHistory                                         func() (int, string)
	trayHide                                            func() string
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

	if h.iconErr == nil {
		testLogf("ICON RESOURCE (embedded in exe, loaded for window): OK")
	} else {
		fails++
		testLogf("ICON RESOURCE: FAIL %v", h.iconErr)
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

	var mt, ms string
	ui(func() { mt = h.masterUITest() })
	if mt == "" {
		testLogf("GUI MASTER PASSWORD (enable/lock/unlock/disable): OK")
	} else {
		fails++
		testLogf("GUI MASTER PASSWORD: FAIL %s", mt)
	}
	var tr string
	ui(func() { tr = h.trayTest() })
	switch {
	case tr == "":
		testLogf("GUI TRAY (hide to tray, notification, restore): OK")
	case strings.HasPrefix(tr, "skip"):
		testLogf("GUI TRAY: %s (в CI может не быть области уведомлений)", tr)
	default:
		fails++
		testLogf("GUI TRAY: FAIL %s", tr)
	}
	ui(func() { ms = h.minSizeCheck() })
	if ms == "" {
		testLogf("GUI MIN SIZE 650x600 on every tab: OK")
	} else {
		fails++
		testLogf("GUI MIN SIZE: FAIL %s", ms)
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
	// 3) режим обмена через окно: две передачи подряд, вторая - при окне, свёрнутом в трей
	oldPorts, oldDisc := lanRelayPorts, lanDiscPort
	lanRelayPorts = []string{"29309", "29310", "29311", "29312", "29313"}
	lanDiscPort = 29308
	skipFirewall = true
	dst3, _ := newWork()
	exPw := "gui-exchange-pw"
	ui(func() {
		h.setOut(dst3)
		h.exchSetup(exPw, "GuiТест")
		h.exchToggle()
	})
	var running bool
	ui(func() { running = h.exchRunning() })
	if !running {
		fails++
		testLogf("GUI EXCHANGE: FAIL mode did not start")
	} else {
		waitHist := func(n int, sec int) bool {
			dl := time.Now().Add(time.Duration(sec) * time.Second)
			for time.Now().Before(dl) {
				var cnt int
				ui(func() { cnt, _ = h.exchHistory() })
				if cnt >= n {
					return true
				}
				time.Sleep(300 * time.Millisecond)
			}
			return false
		}
		cfg := Settings{Relay: "127.0.0.1:29309", ProxyMode: modeDirect}
		t1 := "обмен из окна - первое"
		s1, _ := startSend(cfg, exPw, t1, []string{f1})
		okA := waitHist(1, 40)
		if s1 != nil {
			s1.Wait(20 * time.Second)
		}
		var trayMsg string
		ui(func() { trayMsg = h.trayHide() })
		t2 := "обмен из окна - второе, окно в трее"
		s2, _ := startSend(cfg, exPw, t2, nil)
		okB := waitHist(2, 40)
		if s2 != nil {
			s2.Wait(20 * time.Second)
		}
		ui(func() { h.trayShow() })
		var cnt int
		var top string
		ui(func() { cnt, top = h.exchHistory() })
		ui(func() { h.exchToggle() })
		ui(func() { running = h.exchRunning() })
		closed := !waitTCP("127.0.0.1:29309", 1500*time.Millisecond, nil)
		if okA && okB && cnt == 2 && top == t2 && fileEquals(filepath.Join(dst3, "gui файл.bin"), data) && !running && closed {
			note := ""
			if trayMsg != "" {
				note = " (трей недоступен: " + trayMsg + ")"
			}
			testLogf("GUI EXCHANGE MODE (2 transfers, one while hidden in tray, stop)%s: OK", note)
		} else {
			fails++
			testLogf("GUI EXCHANGE MODE: FAIL first=%v second=%v history=%d top=%q running=%v portClosed=%v", okA, okB, cnt, top, running, closed)
		}
	}
	// 4) отправитель в окне "ждёт получателя в сети": получатель находит его и забирает данные
	{
		textH := "из окна: жду получателя"
		ui(func() {
			h.setDest(destWait)
			h.setSendText(textH)
			h.addFiles([]string{f1})
			h.setSendPw("host-gui-pw")
			h.setCompress(false)
			h.send()
		})
		time.Sleep(2 * time.Second)
		found := discoverPeers(1200*time.Millisecond, "gui-recv", roleSend, []string{"127.0.0.1:29308"})
		dstH, _ := newWork()
		rcv, created, rerr := startReceive(Settings{Relay: "127.0.0.1:29309", ProxyMode: modeDirect}, "host-gui-pw", dstH)
		okR := false
		var res RecvResult
		if rerr == nil {
			okR = rcv.Wait(60 * time.Second)
			res = finalizeReceive(rcv, dstH, created)
		}
		idle := waitIdle(30)
		closed := !waitTCP("127.0.0.1:29309", 5*time.Second, nil)
		if okR && res.Text == textH && fileEquals(filepath.Join(dstH, "gui файл.bin"), data) && len(found) == 1 && found[0].Role == roleSend && idle && closed {
			testLogf("GUI SENDER WAITS FOR RECEIVER (announced, pulled, port closed after): OK")
		} else {
			fails++
			testLogf("GUI SENDER WAITS: FAIL ok=%v text=%q found=%d idle=%v portClosed=%v", okR, res.Text, len(found), idle, closed)
		}
	}

	// 5) получатель в окне вводит адрес ожидающего отправителя вручную
	{
		textP := "забираю по адресу вручную"
		hj, host, _, herr := startHostedSend(Settings{}, "pull-gui-pw", textP, []string{f1}, "ВнешнийХост")
		if herr != nil {
			fails++
			testLogf("GUI RECEIVE FROM ADDRESS: FAIL host start %v", herr)
		} else {
			time.Sleep(1500 * time.Millisecond)
			base, _ := newWork()
			dstP := filepath.Join(base, "pull")
			ui(func() {
				h.setSrc("127.0.0.1:29309")
				h.setRecvPw("pull-gui-pw")
				h.setOut(dstP)
				h.recv()
			})
			idle := waitIdle(60)
			hj.Wait(20 * time.Second)
			host.Close()
			var got string
			ui(func() { got = h.recvText() })
			if idle && got == textP && fileEquals(filepath.Join(dstP, "gui файл.bin"), data) {
				testLogf("GUI RECEIVE FROM SENDER BY MANUAL ADDRESS: OK")
			} else {
				fails++
				testLogf("GUI RECEIVE BY ADDRESS: FAIL idle=%v text=%q", idle, got)
			}
		}
	}

	lanRelayPorts, lanDiscPort = oldPorts, oldDisc
	skipFirewall = false
	return finishTest()
}
