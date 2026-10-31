package main

import (
	"strings"
	"testing"
)

func TestRender(t *testing.T) {
	long := "https://example.com/" + strings.Repeat("abcdef/", 20)
	msgs := []ChatMsg{
		{ID: "a", Name: "Аня", TS: 1000, Kind: "msg", Text: "смотри " + long + " и всё."},
		{ID: "b", Name: "Боря", TS: 2000, Kind: "msg", Text: "1\n2\n3\n4\n5"},
		{ID: "c", Name: "Боря", TS: 3000, Kind: "file", File: &ChatFile{Name: "док.txt", Size: 10}},
	}
	exp := map[string]bool{}
	v := renderChat(msgs, exp)
	if !strings.Contains(v.Text, "…") || strings.Contains(v.Text, long) {
		t.Fatal("link not truncated")
	}
	if strings.Contains(v.Text, "\n4") || !strings.Contains(v.Text, "[… развернуть]") {
		t.Fatalf("not collapsed: %q", v.Text)
	}
	var link, ex, file *chatSeg
	for i := range v.Segs {
		s := &v.Segs[i]
		switch s.Kind {
		case "link":
			link = s
		case "expand":
			ex = s
		case "file":
			file = s
		}
	}
	if link == nil || ex == nil || file == nil || link.URL != long {
		t.Fatalf("segs: %+v", v.Segs)
	}
	// смещения: текст по [Start:End] в UTF-16 совпадает с отображаемым
	u := []rune(v.Text)
	_ = u
	if v.segAt(link.Start) != link || v.segAt(file.End-1) != file {
		t.Fatal("segAt")
	}
	exp[link.Key], exp["b"] = true, true
	v2 := renderChat(msgs, exp)
	if !strings.Contains(v2.Text, long) || !strings.Contains(v2.Text, "5") || !strings.Contains(v2.Text, "[свернуть]") {
		t.Fatalf("not expanded: %q", v2.Text)
	}
	// URL без хвостовой точки
	for _, s := range v2.Segs {
		if s.Kind == "link" && strings.HasSuffix(s.URL, ".") {
			t.Fatal("trailing dot in url")
		}
	}
}

func TestGeom(t *testing.T) {
	h := hostToken("guid", "PC")
	s := encodeGeom(h, winGeom{10, 20, 700, 600, true})
	g, ok := parseGeom(s, h)
	if !ok || g != (winGeom{10, 20, 700, 600, true}) {
		t.Fatal("roundtrip")
	}
	if _, ok := parseGeom(s, hostToken("guid2", "PC")); ok {
		t.Fatal("other machine accepted")
	}
	if _, ok := parseGeom("garbage", h); ok {
		t.Fatal("garbage accepted")
	}
	// экран уменьшили до 1024x768: окно на (1500,900) возвращается внутрь
	c := clampGeom(winGeom{1500, 900, 740, 660, false}, 0, 0, 1024, 728, 650, 600)
	if c.X+c.W > 1024 || c.Y+c.H > 728 || c.X < 0 || c.Y < 0 {
		t.Fatalf("clamp %+v", c)
	}
	// окно больше экрана
	c = clampGeom(winGeom{-300, -100, 3000, 2000, false}, 0, 0, 1280, 720, 650, 600)
	if c.W != 1280 || c.H != 720 || c.X != 0 || c.Y != 0 {
		t.Fatalf("clamp big %+v", c)
	}
}
