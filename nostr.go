package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// Событие Nostr (NIP-01): подпись BIP-340 (Schnorr, secp256k1).

type nostrEvent struct {
	ID        string     `json:"id"`
	PubKey    string     `json:"pubkey"`
	CreatedAt int64      `json:"created_at"`
	Kind      int        `json:"kind"`
	Tags      [][]string `json:"tags"`
	Content   string     `json:"content"`
	Sig       string     `json:"sig"`
}

// nostrPriv - закрытый ключ подписи.
type nostrPriv = btcec.PrivateKey

func nostrNewKey() (*nostrPriv, error) { return btcec.NewPrivateKey() }

func nostrKeyBytes(k *nostrPriv) []byte { return k.Serialize() }

func nostrPubHex(priv *nostrPriv) string {
	return hex.EncodeToString(schnorr.SerializePubKey(priv.PubKey()))
}

func nostrKeyFromBytes(b []byte) *nostrPriv {
	k, _ := btcec.PrivKeyFromBytes(b)
	return k
}

// nostrSign собирает и подписывает событие.
func nostrSign(priv *nostrPriv, kind int, tags [][]string, content string, ts int64) (nostrEvent, error) {
	if tags == nil {
		tags = [][]string{}
	}
	ev := nostrEvent{PubKey: nostrPubHex(priv), CreatedAt: ts, Kind: kind, Tags: tags, Content: content}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode([]interface{}{0, ev.PubKey, ev.CreatedAt, ev.Kind, ev.Tags, ev.Content}); err != nil {
		return ev, err
	}
	sum := sha256.Sum256(bytes.TrimRight(buf.Bytes(), "\n"))
	ev.ID = hex.EncodeToString(sum[:])
	sig, err := schnorr.Sign(priv, sum[:])
	if err != nil {
		return ev, err
	}
	ev.Sig = hex.EncodeToString(sig.Serialize())
	return ev, nil
}

// nostrEventID вычисляет идентификатор события по NIP-01.
func nostrEventID(ev nostrEvent) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	tags := ev.Tags
	if tags == nil {
		tags = [][]string{}
	}
	_ = enc.Encode([]interface{}{0, ev.PubKey, ev.CreatedAt, ev.Kind, tags, ev.Content})
	sum := sha256.Sum256(bytes.TrimRight(buf.Bytes(), "\n"))
	return hex.EncodeToString(sum[:])
}

// nostrVerify проверяет идентификатор и подпись события.
func nostrVerify(ev nostrEvent) bool {
	if len(ev.ID) != 64 || len(ev.PubKey) != 64 || len(ev.Sig) != 128 || nostrEventID(ev) != ev.ID {
		return false
	}
	pk, err := hex.DecodeString(ev.PubKey)
	if err != nil {
		return false
	}
	pub, err := schnorr.ParsePubKey(pk)
	if err != nil {
		return false
	}
	sb, err := hex.DecodeString(ev.Sig)
	if err != nil {
		return false
	}
	sig, err := schnorr.ParseSignature(sb)
	if err != nil {
		return false
	}
	id, _ := hex.DecodeString(ev.ID)
	return sig.Verify(id, pub)
}
