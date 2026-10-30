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

func nostrNewKey() (*btcec.PrivateKey, error) { return btcec.NewPrivateKey() }

func nostrPubHex(priv *btcec.PrivateKey) string {
	return hex.EncodeToString(schnorr.SerializePubKey(priv.PubKey()))
}

func nostrKeyFromBytes(b []byte) *btcec.PrivateKey {
	k, _ := btcec.PrivKeyFromBytes(b)
	return k
}

// nostrSign собирает и подписывает событие.
func nostrSign(priv *btcec.PrivateKey, kind int, tags [][]string, content string, ts int64) (nostrEvent, error) {
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
