//go:build windows

package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
	"github.com/lxn/win"
)

// Окно локального чата: сверху имя и общая комната, ниже вкладки комнат с кнопкой «+».

const (
	emCharFromPos         = 0x00D7
	emPosFromChar         = 0x00D6
	emGetFirstVisibleLine = 0x00CE
	emLineScroll          = 0x00B6
)

type chatPage struct {
	room    *ChatRoom
	pw      string
	common  bool
	page    *walk.TabPage
	te      *walk.TextEdit
	input   *walk.TextEdit
	filesCB *walk.ComboBox
	files   []ChatMsg
	info    *walk.Label
	unread  bool
	count   int
	view    chatView
	expand  map[string]bool
	swallow bool // после отправки по Enter убрать перевод строки, который вставит поле ввода
}

type chatPanel struct {
	mw      *walk.MainWindow
	kind    string
	notify  func(title, msg string)
	outDir  func() string
	isHere  func() bool // открыта ли вкладка чата и окно не в трее
	mu      sync.Mutex
	node    *ChatNode
	cfg     chatCfg
	started bool
	tw      *walk.TabWidget
	pages   map[string]*chatPage
	status  *walk.Label
	nameLE  *walk.LineEdit
	commonC *walk.CheckBox
	commonP *walk.LineEdit
	// onUnread вызывается, когда меняется набор непрочитанных вкладок (мигание значка в трее).
	onUnread func()
}

func defaultChatName() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "устройство"
}

// promptLines показывает окно с подписанными полями. Возвращает значения и признак OK.
func promptLines(owner walk.Form, title, message string, labels, initial []string, okText string) ([]string, bool) {
	var dlg *walk.Dialog
	les := make([]*walk.LineEdit, len(labels))
	var res []string
	accepted := false
	children := []Widget{Label{Text: message}}
	for i := range labels {
		i := i
		children = append(children, Label{Text: labels[i]}, LineEdit{AssignTo: &les[i], Text: initial[i]})
	}
	children = append(children, Composite{
		Layout: HBox{MarginsZero: true},
		Children: []Widget{
			HSpacer{},
			PushButton{Text: okText, OnClicked: func() {
				for _, le := range les {
					res = append(res, strings.TrimSpace(le.Text()))
				}
				accepted = true
				dlg.Accept()
			}},
			PushButton{Text: "Отмена", OnClicked: func() { dlg.Cancel() }},
		},
	})
	if _, err := (Dialog{AssignTo: &dlg, Title: title, MinSize: Size{Width: 380}, Layout: VBox{}, Children: children}).Run(owner); err != nil {
		return nil, false
	}
	return res, accepted
}

func newChatPanel(mw *walk.MainWindow, host walk.Container, kind string, notify func(string, string), outDir func() string, isHere func() bool) (*chatPanel, error) {
	p := &chatPanel{mw: mw, kind: kind, notify: notify, outDir: outDir, isHere: isHere, pages: map[string]*chatPage{}}
	p.cfg = loadChatCfg()
	kc := p.cfg.Kinds[kind]
	if kc.Name == "" {
		kc.Name = defaultChatName()
		p.cfg.Kinds[kind] = kc
	}
	ctrl, _ := walk.NewComposite(host)
	ctrl.SetLayout(walk.NewHBoxLayout())
	if bl, ok := ctrl.Layout().(*walk.BoxLayout); ok {
		_ = bl.SetMargins(walk.Margins{})
	}
	lb, _ := walk.NewLabel(ctrl)
	_ = lb.SetText("Имя:")
	p.nameLE, _ = walk.NewLineEdit(ctrl)
	_ = p.nameLE.SetText(kc.Name)
	_ = p.nameLE.SetMinMaxSize(walk.Size{Width: 90}, walk.Size{Width: 140})
	nb, _ := walk.NewPushButton(ctrl)
	_ = nb.SetText("Сменить")
	nb.Clicked().Attach(func() { p.applyName() })
	p.commonC, _ = walk.NewCheckBox(ctrl)
	_ = p.commonC.SetText("Общая комната")
	p.commonC.SetChecked(kc.Common)
	p.commonC.CheckedChanged().Attach(func() { p.toggleCommon() })
	lb2, _ := walk.NewLabel(ctrl)
	_ = lb2.SetText("пароль:")
	p.commonP, _ = walk.NewLineEdit(ctrl)
	if kc.CommonPw != "" {
		if pw, err := openSecret(kc.CommonPw); err == nil {
			_ = p.commonP.SetText(pw)
		}
	}
	_ = p.commonP.SetMinMaxSize(walk.Size{Width: 70}, walk.Size{Width: 110})
	_ = p.commonP.SetToolTipText("Пустой пароль - общая комната открыта для всех, кто её включил (по умолчанию). Свой пароль закрывает её от посторонних: задайте его до включения галочки.")
	add, _ := walk.NewPushButton(ctrl)
	_ = add.SetText("+")
	_ = add.SetMinMaxSize(walk.Size{Width: 28}, walk.Size{Width: 28})
	_ = add.SetToolTipText("Добавить комнату (вкладку) с паролем")
	add.Clicked().Attach(func() { p.addRoomDialog() })
	cl, _ := walk.NewPushButton(ctrl)
	_ = cl.SetText("Закрыть вкладку")
	cl.Clicked().Attach(func() { p.closeCurrent() })

	p.tw, _ = walk.NewTabWidget(host)
	p.tw.CurrentIndexChanged().Attach(func() { p.onTabChanged() })

	bar, _ := walk.NewComposite(host)
	bar.SetLayout(walk.NewHBoxLayout())
	if bl, ok := bar.Layout().(*walk.BoxLayout); ok {
		_ = bl.SetMargins(walk.Margins{})
	}
	p.status, _ = walk.NewLabel(bar)
	_ = p.status.SetText("Чат не запущен. Нажмите «+» или включите общую комнату.")
	find, _ := walk.NewPushButton(bar)
	_ = find.SetText("Найти устройства")
	find.Clicked().Attach(func() { p.rescan() })
	peersBtn, _ := walk.NewPushButton(bar)
	_ = peersBtn.SetText("Устройства")
	_ = peersBtn.SetToolTipText("Показать устройства на связи: имя и IP-адрес (текст можно скопировать)")
	peersBtn.Clicked().Attach(func() { p.showPeers() })
	addr, _ := walk.NewPushButton(bar)
	_ = addr.SetText("Адрес...")
	_ = addr.SetToolTipText("Добавить устройство вручную (например, адрес из ZeroTier или другой подсети)")
	addr.Clicked().Attach(func() { p.addPeerDialog() })
	return p, nil
}

// ensureStarted запускает сеть чата при первом обращении (и один раз просит права для правил брандмауэра).
func (p *chatPanel) ensureStarted() {
	if p.started {
		return
	}
	p.started = true
	kc := p.cfg.Kinds[p.kind]
	p.node = NewChatNode(chatDataDir(), p.cfg.UID, kc.Name)
	p.node.OnUpdate = func(id string) { p.mw.Synchronize(func() { p.refresh(id, true) }) }
	p.node.OnPeers = func() { p.mw.Synchronize(p.updStatus) }
	for _, rc := range kc.Rooms {
		if pw, err := openSecret(rc.Pw); err == nil && pw != "" {
			p.openRoom(rc.Label, pw, false, false)
		}
	}
	if kc.Common {
		p.openRoom("Общая", p.commonPw(), true, false)
	}
	_ = p.status.SetText("Запуск чата...")
	go func() {
		fwErr := fwEnsure()
		err := p.node.Start()
		p.mw.Synchronize(func() {
			if err != nil {
				_ = p.status.SetText("Чат не запущен: " + err.Error())
				return
			}
			if fwErr != nil {
				_ = p.status.SetText("Чат запущен, но правило брандмауэра не создано: " + fwErr.Error())
				return
			}
			p.updStatus()
		})
	}()
}

func (p *chatPanel) commonPw() string {
	if pw := strings.TrimSpace(p.commonP.Text()); pw != "" {
		return pw
	}
	return chatCommonDefaultPw
}

func (p *chatPanel) updStatus() {
	if p.node == nil {
		return
	}
	n := p.node.PeerCount()
	t := fmt.Sprintf("Устройств на связи: %d", n)
	if n == 0 {
		t += " (ищу в сети; можно добавить адрес вручную)"
	}
	_ = p.status.SetText(t)
}

func (p *chatPanel) saveCfg() {
	kc := p.cfg.Kinds[p.kind]
	kc.Name = p.node.Name()
	kc.Common = p.commonC.Checked()
	kc.CommonPw = ""
	if s := strings.TrimSpace(p.commonP.Text()); s != "" {
		if sealed, err := sealSecret(s); err == nil {
			kc.CommonPw = sealed
		}
	}
	kc.Rooms = nil
	for _, id := range p.order() {
		pg := p.pages[id]
		if pg.common {
			continue
		}
		if sealed, err := sealSecret(pg.pw); err == nil {
			kc.Rooms = append(kc.Rooms, chatRoomCfg{Label: pg.room.Label, Pw: sealed})
		}
	}
	p.cfg.Kinds[p.kind] = kc
	_ = saveChatCfg(p.cfg)
}

func (p *chatPanel) order() []string {
	var ids []string
	for i := 0; i < p.tw.Pages().Len(); i++ {
		for id, pg := range p.pages {
			if pg.page == p.tw.Pages().At(i) {
				ids = append(ids, id)
			}
		}
	}
	return ids
}

func (p *chatPanel) applyName() {
	name := strings.TrimSpace(p.nameLE.Text())
	if name == "" {
		return
	}
	p.ensureStarted()
	p.node.Rename(name)
	p.saveCfg()
}

func (p *chatPanel) toggleCommon() {
	p.ensureStarted()
	if p.commonC.Checked() {
		p.openRoom("Общая", p.commonPw(), true, true)
		p.commonP.SetEnabled(false)
	} else {
		for id, pg := range p.pages {
			if pg.common {
				p.dropPage(id)
			}
		}
		p.commonP.SetEnabled(true)
	}
	p.saveCfg()
}

func (p *chatPanel) addRoomDialog() {
	p.ensureStarted()
	res, ok := promptLines(p.mw, "Новая комната", "Комната определяется паролем: кто ввёл тот же пароль, тот и в этой комнате.",
		[]string{"Название вкладки (видно только вам):", "Пароль комнаты:"}, []string{"", randHex(4) + "-" + randHex(4)}, "Добавить")
	if !ok {
		return
	}
	label, pw := res[0], res[1]
	if len([]rune(pw)) < 3 {
		walk.MsgBox(p.mw, "Комната", "Пароль должен быть не короче 3 символов.", walk.MsgBoxIconWarning)
		return
	}
	if label == "" {
		label = "Комната"
	}
	if len([]rune(pw)) < 8 {
		walk.MsgBox(p.mw, "Комната", "Короткий пароль легко подобрать, пока сообщения хранятся на устройствах. Для рабочих разговоров это допустимо; для важного используйте длинный пароль.", walk.MsgBoxIconInformation)
	}
	p.openRoom(label, pw, false, true)
	p.saveCfg()
}

func (p *chatPanel) closeCurrent() {
	i := p.tw.CurrentIndex()
	if i < 0 {
		return
	}
	for id, pg := range p.pages {
		if pg.page == p.tw.Pages().At(i) {
			if pg.common {
				p.commonC.SetChecked(false)
				return
			}
			if walk.MsgBox(p.mw, "Закрыть вкладку", "Закрыть «"+pg.room.Label+"»?\nИстория сохранится на диске; чтобы вернуться, добавьте комнату с тем же паролем.", walk.MsgBoxYesNo|walk.MsgBoxIconQuestion) != walk.DlgCmdYes {
				return
			}
			p.dropPage(id)
			p.saveCfg()
			return
		}
	}
}

func (p *chatPanel) dropPage(id string) {
	pg := p.pages[id]
	if pg == nil {
		return
	}
	delete(p.pages, id)
	if p.node != nil {
		p.node.RemoveRoom(id)
	}
	_ = p.tw.Pages().Remove(pg.page)
	pg.page.Dispose()
}

func (p *chatPanel) rescan() {
	p.ensureStarted()
	_ = p.status.SetText("Поиск устройств...")
	go func() {
		for {
			if p.node != nil && p.node.ln != nil {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
		lines := p.node.Scan(2 * time.Second)
		p.mw.Synchronize(func() {
			p.updStatus()
			showTextDialog(p.mw, "Поиск устройств", strings.Join(lines, "\n"))
		})
	}()
}

// showTextDialog показывает текст в окне с возможностью выделить и скопировать.
func showTextDialog(owner walk.Form, title, text string) {
	var dlg *walk.Dialog
	_, _ = (Dialog{
		AssignTo: &dlg, Title: title, MinSize: Size{Width: 420, Height: 260}, Layout: VBox{},
		Children: []Widget{
			TextEdit{ReadOnly: true, VScroll: true, Text: crlf(text)},
			Composite{Layout: HBox{MarginsZero: true}, Children: []Widget{
				HSpacer{},
				PushButton{Text: "Закрыть", OnClicked: func() { dlg.Accept() }},
			}},
		},
	}).Run(owner)
}

func (p *chatPanel) showPeers() {
	p.ensureStarted()
	var sb strings.Builder
	sb.WriteString("Этот компьютер: " + p.node.Name() + "  " + strings.Join(localIPv4s(), ", ") + "\n\n")
	info := p.node.PeerInfo()
	if len(info) == 0 {
		sb.WriteString("Подключённых устройств нет.")
	} else {
		sb.WriteString("На связи:\n" + strings.Join(info, "\n"))
	}
	showTextDialog(p.mw, "Устройства на связи", sb.String())
}

func (p *chatPanel) addPeerDialog() {
	p.ensureStarted()
	res, ok := promptLines(p.mw, "Добавить устройство", "Адрес компьютера с открытым чатом (например, 172.27.10.5):", []string{"Адрес:"}, []string{""}, "Добавить")
	if !ok {
		return
	}
	if err := p.node.AddPeer(res[0]); err != nil {
		walk.MsgBox(p.mw, "Адрес", err.Error(), walk.MsgBoxIconWarning)
	}
}

func (p *chatPanel) onTabChanged() { p.onShown() }

// openRoom добавляет комнату в сеть и вкладку в окно.
func (p *chatPanel) openRoom(label, pw string, common, selectIt bool) {
	if p.node == nil {
		return
	}
	r, err := p.node.AddRoom(label, pw)
	if err != nil {
		return
	}
	if p.pages[r.ID] != nil {
		return
	}
	pg := &chatPage{room: r, pw: pw, common: common}
	page, _ := walk.NewTabPage()
	_ = page.SetTitle(label)
	page.SetLayout(walk.NewVBoxLayout())
	pg.page = page
	pg.te, _ = walk.NewTextEditWithStyle(page, win.WS_VSCROLL)
	pg.te.SetReadOnly(true)
	if bl, ok := page.Layout().(*walk.BoxLayout); ok {
		_ = bl.SetStretchFactor(pg.te, 10)
	}
	row, _ := walk.NewComposite(page)
	row.SetLayout(walk.NewHBoxLayout())
	if bl, ok := row.Layout().(*walk.BoxLayout); ok {
		_ = bl.SetMargins(walk.Margins{})
	}
	pg.input, _ = walk.NewTextEditWithStyle(row, win.WS_VSCROLL)
	_ = pg.input.SetMinMaxSize(walk.Size{Height: 46}, walk.Size{Height: 64})
	send, _ := walk.NewPushButton(row)
	_ = send.SetText("Отправить")
	_ = send.SetToolTipText("Enter - отправить сообщение, Ctrl+Enter - перенос строки")
	fb, _ := walk.NewPushButton(row)
	_ = fb.SetText("Файл...")
	doSend := func() {
		t := pg.input.Text()
		if strings.TrimSpace(t) == "" {
			return
		}
		if err := p.node.SendText(r, t); err != nil {
			walk.MsgBox(p.mw, "Чат", err.Error(), walk.MsgBoxIconWarning)
			return
		}
		pg.swallow = true
		_ = pg.input.SetText("")
	}
	send.Clicked().Attach(func() { doSend(); pg.swallow = false })
	pg.input.KeyDown().Attach(func(key walk.Key) {
		if key != walk.KeyReturn {
			return
		}
		if uint16(win.GetKeyState(win.VK_CONTROL))&0x8000 != 0 {
			// Ctrl+Enter - перенос строки; если поле само его не вставит, вставляем сами
			before := pg.input.TextLength()
			time.AfterFunc(120*time.Millisecond, func() {
				p.mw.Synchronize(func() {
					if pg.input.TextLength() == before {
						pg.input.ReplaceSelectedText("\r\n", true)
					}
				})
			})
			return
		}
		doSend()
	})
	pg.input.TextChanged().Attach(func() {
		if !pg.swallow {
			return
		}
		t := pg.input.Text()
		if strings.TrimSpace(t) == "" {
			if t != "" {
				_ = pg.input.SetText("")
			}
			return
		}
		pg.swallow = false
	})
	fb.Clicked().Attach(func() {
		dlg := new(walk.FileDialog)
		dlg.Title = "Файлы для отправки в чат"
		dlg.Filter = "Все файлы (*.*)|*.*"
		if ok, err := dlg.ShowOpenMultiple(p.mw); err == nil && ok {
			for _, f := range dlg.FilePaths {
				if err := p.node.SendFile(r, f); err != nil {
					walk.MsgBox(p.mw, "Чат", err.Error(), walk.MsgBoxIconWarning)
				}
			}
		}
	})
	row2, _ := walk.NewComposite(page)
	row2.SetLayout(walk.NewHBoxLayout())
	if bl, ok := row2.Layout().(*walk.BoxLayout); ok {
		_ = bl.SetMargins(walk.Margins{})
	}
	lf, _ := walk.NewLabel(row2)
	_ = lf.SetText("Файлы:")
	pg.filesCB, _ = walk.NewComboBox(row2)
	dl, _ := walk.NewPushButton(row2)
	_ = dl.SetText("Скачать")
	dl.Clicked().Attach(func() { p.download(pg) })
	row3, _ := walk.NewComposite(page)
	row3.SetLayout(walk.NewHBoxLayout())
	if bl, ok := row3.Layout().(*walk.BoxLayout); ok {
		_ = bl.SetMargins(walk.Margins{})
	}
	clr, _ := walk.NewPushButton(row3)
	_ = clr.SetText("Очистить чат")
	_ = clr.SetToolTipText("Очистить историю этой комнаты только на этом компьютере")
	clr.Clicked().Attach(func() {
		if walk.MsgBox(p.mw, "Очистить чат", "Очистить историю комнаты «"+r.Label+"» на этом компьютере?", walk.MsgBoxYesNo|walk.MsgBoxIconQuestion) == walk.DlgCmdYes {
			r.ClearLocal()
			pg.expand = map[string]bool{}
			p.refresh(r.ID, false)
		}
	})
	clrAll, _ := walk.NewPushButton(row3)
	_ = clrAll.SetText("Очистить чат у всех")
	_ = clrAll.SetToolTipText("Очистить историю комнаты у всех участников (у тех, кто сейчас не в сети - при следующем подключении)")
	clrAll.Clicked().Attach(func() {
		if walk.MsgBox(p.mw, "Очистить чат у всех", "Очистить историю комнаты «"+r.Label+"» у ВСЕХ участников?", walk.MsgBoxYesNo|walk.MsgBoxIconWarning) == walk.DlgCmdYes {
			p.node.ClearAll(r)
			pg.expand = map[string]bool{}
			p.refresh(r.ID, false)
		}
	})
	exp, _ := walk.NewPushButton(row3)
	_ = exp.SetText("Экспорт в txt")
	exp.Clicked().Attach(func() {
		dlg := new(walk.FileDialog)
		dlg.Title = "Сохранить чат"
		dlg.Filter = "Текст (*.txt)|*.txt"
		dlg.FilePath = "chat-" + safeFileName(r.Label) + ".txt"
		if ok, err := dlg.ShowSave(p.mw); err == nil && ok {
			path := dlg.FilePath
			if !strings.Contains(strings.ToLower(path), ".txt") {
				path += ".txt"
			}
			if err := os.WriteFile(path, []byte("\xEF\xBB\xBF"+r.ExportText()), 0o644); err != nil {
				walk.MsgBox(p.mw, "Экспорт", err.Error(), walk.MsgBoxIconWarning)
			} else {
				_ = pg.info.SetText("Чат сохранён: " + path)
			}
		}
	})
	pg.info, _ = walk.NewLabel(page)
	_ = pg.info.SetText("Клик по ссылке открывает её (длинная сначала раскрывается), по [файл...] - скачивает, по [… развернуть] - показывает всё сообщение.")
	pg.expand = map[string]bool{}
	pg.te.MouseUp().Attach(func(x, y int, button walk.MouseButton) {
		if button == walk.LeftButton {
			p.onHistoryClick(pg, x, y)
		}
	})
	// первой идёт общая комната
	idx := p.tw.Pages().Len()
	if common {
		idx = 0
	}
	_ = p.tw.Pages().Insert(idx, page)
	p.pages[r.ID] = pg
	if selectIt {
		_ = p.tw.SetCurrentIndex(idx)
	}
	p.refresh(r.ID, false)
	p.updStatus()
}

func (p *chatPanel) download(pg *chatPage) {
	i := pg.filesCB.CurrentIndex()
	if i < 0 || i >= len(pg.files) {
		return
	}
	p.downloadMsg(pg, pg.files[i])
}

func (p *chatPanel) downloadMsg(pg *chatPage, m ChatMsg) {
	if m.File == nil {
		return
	}
	if m.UID == p.cfg.UID {
		_ = pg.info.SetText("Это ваш собственный файл.")
		return
	}
	f := *m.File
	dest := p.outDir()
	_ = pg.info.SetText("Скачиваю «" + f.Name + "»...")
	go func() {
		last := time.Time{}
		path, err := p.node.Download(context.Background(), f, dest, func(done, total int64) {
			if time.Since(last) > 300*time.Millisecond {
				last = time.Now()
				p.mw.Synchronize(func() {
					_ = pg.info.SetText(fmt.Sprintf("Скачиваю «%s»: %s из %s", f.Name, humanSize(done), humanSize(total)))
				})
			}
		})
		p.mw.Synchronize(func() {
			if err != nil {
				_ = pg.info.SetText(err.Error())
			} else {
				_ = pg.info.SetText("Сохранено: " + path)
			}
		})
	}()
}

// onHistoryClick: клик по ссылке, файлу или «развернуть» в истории (выделение мышью не считается кликом).
func (p *chatPanel) onHistoryClick(pg *chatPage, x, y int) {
	if s, e := pg.te.TextSelection(); s != e {
		return
	}
	pos := int(pg.te.SendMessage(emCharFromPos, 0, uintptr(uint32(uint16(y))<<16|uint32(uint16(x)))) & 0xFFFF)
	// клик должен быть именно по тексту, а не по пустому месту справа от строки
	pp := uint32(pg.te.SendMessage(emPosFromChar, uintptr(pos), 0))
	px, py := int(int16(pp&0xFFFF)), int(int16(pp>>16))
	if dx, dy := x-px, y-py; dx < -4 || dx > 26 || dy < -4 || dy > 22 {
		return
	}
	seg := pg.view.segAt(pos)
	if seg == nil {
		return
	}
	switch seg.Kind {
	case "expand", "collapse":
		pg.expand[seg.Key] = !pg.expand[seg.Key]
		p.refreshKeep(pg)
	case "link":
		if u16len(seg.URL) > chatLinkMax && !pg.expand[seg.Key] {
			pg.expand[seg.Key] = true
			p.refreshKeep(pg)
			return
		}
		verb, _ := windows.UTF16PtrFromString("open")
		file, _ := windows.UTF16PtrFromString(seg.URL)
		_ = windows.ShellExecute(0, verb, file, nil, nil, windows.SW_SHOWNORMAL)
	case "file":
		for _, m := range pg.files {
			if m.ID == seg.MsgID {
				p.downloadMsg(pg, m)
			}
		}
	}
}

// refreshKeep перерисовывает историю, сохраняя прокрутку.
func (p *chatPanel) refreshKeep(pg *chatPage) {
	line := int(pg.te.SendMessage(emGetFirstVisibleLine, 0, 0))
	p.render(pg, false)
	pg.te.SendMessage(emLineScroll, 0, uintptr(line))
}

// render выводит историю в поле; toEnd - прокрутить к последнему сообщению.
func (p *chatPanel) render(pg *chatPage, toEnd bool) {
	msgs := pg.room.Messages()
	pg.view = renderChat(msgs, pg.expand)
	pg.files = pg.files[:0]
	var names []string
	for _, m := range msgs {
		if m.Kind == "file" && m.File != nil {
			pg.files = append(pg.files, m)
			names = append(names, m.File.Name+" ("+humanSize(m.File.Size)+") - "+m.Name)
		}
	}
	_ = pg.te.SetText(pg.view.Text)
	if toEnd {
		n := u16len(pg.view.Text)
		pg.te.SetTextSelection(n, n)
		pg.te.SendMessage(win.EM_SCROLLCARET, 0, 0)
	}
	cur := pg.filesCB.CurrentIndex()
	_ = pg.filesCB.SetModel(names)
	if len(names) > 0 {
		if cur < 0 || cur >= len(names) {
			cur = len(names) - 1
		}
		_ = pg.filesCB.SetCurrentIndex(cur)
	}
}

// refresh перерисовывает историю комнаты; если пришли новые сообщения - отмечает вкладку и показывает уведомление.
func (p *chatPanel) refresh(id string, fromNet bool) {
	pg := p.pages[id]
	if pg == nil {
		return
	}
	p.render(pg, true)
	msgs := pg.room.Messages()
	if fromNet && len(msgs) > pg.count && len(msgs) > 0 {
		last := msgs[len(msgs)-1]
		if last.UID != p.cfg.UID && !p.viewing(pg) {
			if !pg.unread {
				pg.unread = true
				_ = pg.page.SetTitle(pg.room.Label + " •")
			}
			txt := last.Text
			if last.Kind == "file" && last.File != nil {
				txt = "[файл] " + last.File.Name
			}
			if p.notify != nil {
				p.notify("Чат: "+pg.room.Label, last.Name+": "+truncRunes(txt, 80))
			}
			if p.onUnread != nil {
				p.onUnread()
			}
		}
	}
	pg.count = len(msgs)
}

// viewing: пользователь прямо сейчас видит эту комнату (окно на экране, вкладка чата и вкладка комнаты открыты).
func (p *chatPanel) viewing(pg *chatPage) bool {
	if p.isHere == nil || !p.isHere() {
		return false
	}
	i := p.tw.CurrentIndex()
	return i >= 0 && p.tw.Pages().At(i) == pg.page
}

// HasUnread - есть ли непрочитанные комнаты.
func (p *chatPanel) HasUnread() bool {
	for _, pg := range p.pages {
		if pg.unread {
			return true
		}
	}
	return false
}

// FocusUnread открывает первую (по порядку вкладок) комнату с непрочитанными сообщениями.
func (p *chatPanel) FocusUnread() {
	for i := 0; i < p.tw.Pages().Len(); i++ {
		for _, pg := range p.pages {
			if pg.page == p.tw.Pages().At(i) && pg.unread {
				_ = p.tw.SetCurrentIndex(i)
				p.onShown()
				return
			}
		}
	}
}

// onShown вызывается, когда пользователь мог увидеть текущую комнату: снимает отметку «непрочитано».
func (p *chatPanel) onShown() {
	i := p.tw.CurrentIndex()
	if i < 0 {
		return
	}
	for _, pg := range p.pages {
		if pg.page == p.tw.Pages().At(i) && pg.unread && p.viewing(pg) {
			pg.unread = false
			_ = pg.page.SetTitle(pg.room.Label)
			if p.onUnread != nil {
				p.onUnread()
			}
		}
	}
}

func truncRunes(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

func (p *chatPanel) stop() {
	if p.node != nil {
		p.node.Stop()
	}
}
