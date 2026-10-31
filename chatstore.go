package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

// Настройки чата хранятся отдельно от crocau.ini: папка crocau-chat рядом с программой (портабельно).

type chatRoomCfg struct {
	Label string `json:"label"`
	Pw    string `json:"pw"` // защищён так же, как остальные пароли
}

type chatKindCfg struct {
	Name     string        `json:"name,omitempty"`
	Common   bool          `json:"common,omitempty"`
	CommonPw string        `json:"commonPw,omitempty"`
	Rooms    []chatRoomCfg `json:"rooms,omitempty"`
}

type chatCfg struct {
	UID    string                 `json:"uid"`
	NetKey string                 `json:"netKey,omitempty"` // ключ подписи интернет-чата (hex, защищён)
	Kinds  map[string]chatKindCfg `json:"kinds"`
}

var chatCfgMu sync.Mutex

func chatDataDir() string { return filepath.Join(exeDir(), "crocau-chat") }

func chatCfgPath() string { return filepath.Join(chatDataDir(), "chat.json") }

func loadChatCfg() chatCfg {
	c, fresh := loadChatCfgRaw()
	if fresh {
		_ = saveChatCfg(c) // постоянный идентификатор сохраняем сразу, чтобы обе вкладки чата видели один и тот же
	}
	return c
}

func loadChatCfgRaw() (chatCfg, bool) {
	chatCfgMu.Lock()
	defer chatCfgMu.Unlock()
	var c chatCfg
	if b, err := os.ReadFile(chatCfgPath()); err == nil {
		_ = json.Unmarshal(b, &c)
	}
	if c.Kinds == nil {
		c.Kinds = map[string]chatKindCfg{}
	}
	fresh := false
	if c.UID == "" {
		c.UID = randHex(8)
		fresh = true
	}
	return c, fresh
}

func saveChatCfg(c chatCfg) error {
	chatCfgMu.Lock()
	defer chatCfgMu.Unlock()
	_ = os.MkdirAll(chatDataDir(), 0o700)
	b, _ := json.MarshalIndent(c, "", " ")
	return os.WriteFile(chatCfgPath(), b, 0o600)
}
