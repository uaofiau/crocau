package main

import (
	"regexp"
	"strings"
	"time"
	"unicode/utf16"
)

// Показ истории чата обычным текстовым полем: ссылки, файлы и «свернуть/развернуть» - это участки текста,
// по клику на которые окно выполняет действие. Смещения считаются в единицах UTF-16 (как в поле ввода Windows).

const (
	chatLinkMax     = 40  // длиннее - ссылка показывается обрезанной с многоточием
	chatCollapseMax = 300 // длиннее (символов) или больше 3 строк - сообщение сворачивается
	chatViewMax     = 50000
)

type chatSeg struct {
	Start, End int
	Kind       string // link, file, expand, collapse
	MsgID      string
	Key        string // ключ состояния раскрытия
	URL        string
	File       *ChatFile
	From       string // автор (для файлов)
	UID        string
}

type chatView struct {
	Text string
	Segs []chatSeg
}

var chatURLRe = regexp.MustCompile(`https?://[^\s<>"]+`)

func u16len(s string) int {
	n := 0
	for _, r := range s {
		if r > 0xFFFF {
			n += 2
		} else {
			n++
		}
	}
	return n
}

func trimURL(u string) string {
	return strings.TrimRight(u, ".,;:!?)]}»'\"")
}

func ellipsize(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "…"
}

type chatBuilder struct {
	sb   strings.Builder
	n    int
	segs []chatSeg
}

func (b *chatBuilder) add(s string) {
	b.sb.WriteString(s)
	b.n += u16len(s)
}

func (b *chatBuilder) addSeg(s string, seg chatSeg) {
	seg.Start = b.n
	b.add(s)
	seg.End = b.n
	b.segs = append(b.segs, seg)
}

func renderOne(m ChatMsg, expanded map[string]bool) (string, []chatSeg) {
	var b chatBuilder
	name := m.Name
	if name == "" {
		name = "?"
	}
	b.add(time.Unix(m.TS/1000, 0).Format("02.01 15:04") + "  " + name + ": ")
	if m.Kind == "file" && m.File != nil {
		b.addSeg("[файл: "+m.File.Name+" ("+humanSize(m.File.Size)+")]", chatSeg{Kind: "file", MsgID: m.ID, File: m.File, From: m.Name, UID: m.UID})
		b.add("\r\n")
		return b.sb.String(), b.segs
	}
	body := strings.ReplaceAll(strings.ReplaceAll(m.Text, "\r\n", "\n"), "\r", "\n")
	lines := strings.Split(body, "\n")
	collapsible := len(lines) > 3 || len([]rune(body)) > chatCollapseMax
	shown := body
	if collapsible && !expanded[m.ID] {
		if len(lines) > 3 {
			lines = lines[:3]
		}
		shown = strings.Join(lines, "\n")
		shown = ellipsize(shown, chatCollapseMax)
	}
	// ссылки внутри показанного текста
	pos := 0
	locs := chatURLRe.FindAllStringIndex(shown, -1)
	li := 0
	for _, loc := range locs {
		url := trimURL(shown[loc[0]:loc[1]])
		end := loc[0] + len(url)
		b.add(strings.ReplaceAll(shown[pos:loc[0]], "\n", "\r\n"))
		key := m.ID + "|" + url
		disp := url
		if !expanded[key] {
			disp = ellipsize(url, chatLinkMax)
		}
		b.addSeg(disp, chatSeg{Kind: "link", MsgID: m.ID, Key: key, URL: url})
		pos = end
		li++
	}
	b.add(strings.ReplaceAll(shown[pos:], "\n", "\r\n"))
	if collapsible {
		if expanded[m.ID] {
			b.add(" ")
			b.addSeg("[свернуть]", chatSeg{Kind: "collapse", MsgID: m.ID, Key: m.ID})
		} else {
			b.add(" ")
			b.addSeg("[… развернуть]", chatSeg{Kind: "expand", MsgID: m.ID, Key: m.ID})
		}
	}
	b.add("\r\n")
	return b.sb.String(), b.segs
}

// renderChat собирает текст истории (последние сообщения, пока помещается в chatViewMax единиц).
func renderChat(msgs []ChatMsg, expanded map[string]bool) chatView {
	type chunk struct {
		text string
		segs []chatSeg
		n    int
	}
	var chunks []chunk
	total := 0
	for i := len(msgs) - 1; i >= 0; i-- {
		t, sg := renderOne(msgs[i], expanded)
		n := u16len(t)
		if total+n > chatViewMax && len(chunks) > 0 {
			break
		}
		total += n
		chunks = append(chunks, chunk{t, sg, n})
	}
	var v chatView
	var sb strings.Builder
	base := 0
	for i := len(chunks) - 1; i >= 0; i-- {
		c := chunks[i]
		sb.WriteString(c.text)
		for _, s := range c.segs {
			s.Start += base
			s.End += base
			v.Segs = append(v.Segs, s)
		}
		base += c.n
	}
	v.Text = sb.String()
	return v
}

// segAt возвращает участок под позицией idx (в единицах UTF-16) или nil.
func (v chatView) segAt(idx int) *chatSeg {
	for i := range v.Segs {
		if idx >= v.Segs[i].Start && idx < v.Segs[i].End {
			return &v.Segs[i]
		}
	}
	return nil
}

var _ = utf16.Encode
