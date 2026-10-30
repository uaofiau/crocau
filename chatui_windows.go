//go:build windows

package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf16"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
	"github.com/lxn/win"
)

// Окно локального чата: сверху имя и общая комната, ниже вкладки комнат с кнопкой «+».

type chatPage struct {
	room    *ChatRoom
	pw      string
	common  bool
	page    *walk.TabPage
	te      *walk.TextEdit
	input   *walk.LineEdit
	filesCB *walk.ComboBox
	files   []ChatMsg
	info    *walk.Label
	unread  bool
	count   int
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
			walk.MsgBox(p.mw, "Поиск устройств", strings.Join(lines, "\n"), walk.MsgBoxIconInformation)
		})
	}()
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

func (p *chatPanel) onTabChanged() {
	i := p.tw.CurrentIndex()
	if i < 0 {
		return
	}
	for _, pg := range p.pages {
		if pg.page == p.tw.Pages().At(i) && pg.unread {
			pg.unread = false
			_ = pg.page.SetTitle(pg.room.Label)
		}
	}
}

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
	pg.input, _ = walk.NewLineEdit(row)
	send, _ := walk.NewPushButton(row)
	_ = send.SetText("Отправить")
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
		_ = pg.input.SetText("")
	}
	send.Clicked().Attach(doSend)
	pg.input.KeyDown().Attach(func(key walk.Key) {
		if key == walk.KeyReturn {
			doSend()
		}
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
	pg.info, _ = walk.NewLabel(page)
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
	m := pg.files[i]
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

// refresh перерисовывает историю комнаты; если пришли новые сообщения - отмечает вкладку и показывает уведомление.
func (p *chatPanel) refresh(id string, fromNet bool) {
	pg := p.pages[id]
	if pg == nil {
		return
	}
	msgs := pg.room.Messages()
	var sb strings.Builder
	pg.files = pg.files[:0]
	var names []string
	for _, m := range msgs {
		sb.WriteString(m.FormatLine())
		sb.WriteString("\r\n")
		if m.Kind == "file" && m.File != nil {
			pg.files = append(pg.files, m)
			names = append(names, m.File.Name+" ("+humanSize(m.File.Size)+") - "+m.Name)
		}
	}
	text := sb.String()
	_ = pg.te.SetText(text)
	n := len(utf16.Encode([]rune(text)))
	pg.te.SetTextSelection(n, n)
	pg.te.SendMessage(win.EM_SCROLLCARET, 0, 0)
	cur := pg.filesCB.CurrentIndex()
	_ = pg.filesCB.SetModel(names)
	if len(names) > 0 {
		if cur < 0 || cur >= len(names) {
			cur = len(names) - 1
		}
		_ = pg.filesCB.SetCurrentIndex(cur)
	}
	if fromNet && len(msgs) > pg.count && len(msgs) > 0 {
		last := msgs[len(msgs)-1]
		if last.UID != p.cfg.UID {
			cur := p.tw.CurrentIndex()
			if cur < 0 || p.tw.Pages().At(cur) != pg.page {
				pg.unread = true
				_ = pg.page.SetTitle(pg.room.Label + " •")
			}
			if p.notify != nil {
				txt := last.Text
				if last.Kind == "file" && last.File != nil {
					txt = "[файл] " + last.File.Name
				}
				p.notify("Чат: "+pg.room.Label, last.Name+": "+truncRunes(txt, 80))
			}
		}
	}
	pg.count = len(msgs)
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
