package main

import (
	"archive/zip"
	"compress/flate"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"hash"
	"io"
	"os"
	"unicode"
)

// Шифрование zip по стандарту WinZip AES-256 (AE-2): открывается в 7-Zip, WinRAR, WinZip.
// Проводник Windows такие архивы не открывает (нужен 7-Zip).

const (
	aesMethod  = 99
	aesSaltLen = 16
	aesMacLen  = 10
	aesExtraID = 0x9901
)

var errZipPassword = errors.New("неверный пароль архива")

// pbkdf2SHA1 - PBKDF2-HMAC-SHA1 (RFC 2898), чтобы не тянуть лишние зависимости.
func pbkdf2SHA1(pw, salt []byte, iter, keyLen int) []byte {
	prf := hmac.New(sha1.New, pw)
	hl := prf.Size()
	n := (keyLen + hl - 1) / hl
	var out []byte
	buf := make([]byte, 4)
	for b := 1; b <= n; b++ {
		prf.Reset()
		prf.Write(salt)
		binary.BigEndian.PutUint32(buf, uint32(b))
		prf.Write(buf)
		u := prf.Sum(nil)
		t := append([]byte(nil), u...)
		for i := 1; i < iter; i++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(u[:0])
			for k := range t {
				t[k] ^= u[k]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen]
}

func aesKeys(pw string, salt []byte) (enc, auth, verifier []byte) {
	k := pbkdf2SHA1([]byte(pw), salt, 1000, 66)
	return k[:32], k[32:64], k[64:66]
}

// ctrLE - AES-CTR WinZip: счётчик 128 бит little-endian, начиная с 1.
type ctrLE struct {
	b   cipher.Block
	ctr [16]byte
	ks  [16]byte
	pos int
}

func newCtrLE(key []byte) *ctrLE {
	b, _ := aes.NewCipher(key)
	c := &ctrLE{b: b, pos: 16}
	c.ctr[0] = 1
	return c
}

func (c *ctrLE) xor(dst, src []byte) {
	for i := range src {
		if c.pos == 16 {
			c.b.Encrypt(c.ks[:], c.ctr[:])
			for j := 0; j < 16; j++ {
				c.ctr[j]++
				if c.ctr[j] != 0 {
					break
				}
			}
			c.pos = 0
		}
		dst[i] = src[i] ^ c.ks[c.pos]
		c.pos++
	}
}

func aesExtra(method uint16) []byte {
	e := make([]byte, 11)
	binary.LittleEndian.PutUint16(e[0:], aesExtraID)
	binary.LittleEndian.PutUint16(e[2:], 7)
	binary.LittleEndian.PutUint16(e[4:], 2) // AE-2
	e[6], e[7] = 'A', 'E'
	e[8] = 3 // AES-256
	binary.LittleEndian.PutUint16(e[9:], method)
	return e
}

// aesInfo достаёт из extra настоящий метод сжатия записи; ok=false, если это не AES-запись.
func aesInfo(extra []byte) (method uint16, ok bool) {
	for len(extra) >= 4 {
		id := binary.LittleEndian.Uint16(extra)
		sz := int(binary.LittleEndian.Uint16(extra[2:]))
		if 4+sz > len(extra) {
			return 0, false
		}
		if id == aesExtraID && sz >= 7 {
			d := extra[4 : 4+sz]
			if d[2] == 'A' && d[3] == 'E' && d[4] == 3 {
				return binary.LittleEndian.Uint16(d[5:]), true
			}
			return 0, false
		}
		extra = extra[4+sz:]
	}
	return 0, false
}

func isASCII(s string) bool {
	for _, r := range s {
		if r > unicode.MaxASCII {
			return false
		}
	}
	return true
}

// encryptZip перепаковывает обычный zip src в zip dst с шифрованием AES-256; сжатые данные берутся как есть.
func encryptZip(src, dst, pw, comment string) error {
	zr, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer zr.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	zw := zip.NewWriter(out)
	fail := func(e error) error {
		_ = zw.Close()
		_ = out.Close()
		_ = os.Remove(dst)
		return e
	}
	if comment != "" {
		_ = zw.SetComment(comment)
	}
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			h := &zip.FileHeader{Name: f.Name, Method: zip.Store, Modified: f.Modified}
			h.SetMode(f.Mode())
			if _, err := zw.CreateHeader(h); err != nil {
				return fail(err)
			}
			continue
		}
		raw, err := f.OpenRaw()
		if err != nil {
			return fail(err)
		}
		flags := uint16(1)
		if !isASCII(f.Name) {
			flags |= 0x800
		}
		h := &zip.FileHeader{
			Name: f.Name, Method: aesMethod, Modified: f.Modified, Flags: flags,
			CompressedSize64: uint64(aesSaltLen+2+aesMacLen) + f.CompressedSize64, UncompressedSize64: f.UncompressedSize64,
			Extra: aesExtra(f.Method),
		}
		h.SetMode(f.Mode())
		w, err := zw.CreateRaw(h)
		if err != nil {
			return fail(err)
		}
		salt := make([]byte, aesSaltLen)
		if _, err := rand.Read(salt); err != nil {
			return fail(err)
		}
		ek, ak, ver := aesKeys(pw, salt)
		if _, err := w.Write(salt); err != nil {
			return fail(err)
		}
		if _, err := w.Write(ver); err != nil {
			return fail(err)
		}
		mac := hmac.New(sha1.New, ak)
		ctr := newCtrLE(ek)
		buf := make([]byte, 64*1024)
		for {
			n, rerr := raw.Read(buf)
			if n > 0 {
				ctr.xor(buf[:n], buf[:n])
				mac.Write(buf[:n])
				if _, err := w.Write(buf[:n]); err != nil {
					return fail(err)
				}
			}
			if rerr == io.EOF {
				break
			}
			if rerr != nil {
				return fail(rerr)
			}
		}
		if _, err := w.Write(mac.Sum(nil)[:aesMacLen]); err != nil {
			return fail(err)
		}
	}
	if err := zw.Close(); err != nil {
		_ = out.Close()
		_ = os.Remove(dst)
		return err
	}
	return out.Close()
}

type aesReader struct {
	src     io.Reader // шифртекст ровно нужной длины
	rest    io.Reader // исходный поток (для чтения MAC)
	ctr     *ctrLE
	mac     hash.Hash
	checked bool
}

func (a *aesReader) Read(p []byte) (int, error) {
	n, err := a.src.Read(p)
	if n > 0 {
		a.mac.Write(p[:n])
		a.ctr.xor(p[:n], p[:n])
	}
	if err == io.EOF {
		return n, a.verify()
	}
	return n, err
}

func (a *aesReader) verify() error {
	if a.checked {
		return io.EOF
	}
	a.checked = true
	got := make([]byte, aesMacLen)
	if _, err := io.ReadFull(a.rest, got); err != nil {
		return errors.New("архив повреждён (нет кода проверки)")
	}
	if !hmac.Equal(got, a.mac.Sum(nil)[:aesMacLen]) {
		return errors.New("архив повреждён (код проверки не совпал)")
	}
	return io.EOF
}

// drain дочитывает шифртекст и проверяет MAC (если декомпрессор остановился раньше конца потока).
func (a *aesReader) drain() error {
	if a.checked {
		return nil
	}
	if _, err := io.Copy(io.Discard, a); err != nil && err != io.EOF {
		return err
	}
	return nil
}

type aesEntry struct {
	rc  io.Reader
	aes *aesReader
	cl  io.Closer
}

func (e *aesEntry) Read(p []byte) (int, error) {
	n, err := e.rc.Read(p)
	if err == io.EOF {
		if derr := e.aes.drain(); derr != nil {
			return n, derr
		}
	}
	return n, err
}

func (e *aesEntry) Close() error {
	if e.cl != nil {
		return e.cl.Close()
	}
	return nil
}

// zipEntryEncrypted говорит, зашифрована ли запись.
func zipEntryEncrypted(f *zip.File) bool { return f.Flags&1 != 0 }

// openZipEntry открывает запись zip; зашифрованные AES расшифровывает паролем pw.
func openZipEntry(f *zip.File, pw string) (io.ReadCloser, error) {
	if !zipEntryEncrypted(f) {
		return f.Open()
	}
	method, ok := aesInfo(f.Extra)
	if f.Method != aesMethod {
		return openZipClassic(f, pw) // традиционное шифрование (Проводник Windows)
	}
	if !ok {
		return nil, errors.New("неподдерживаемое шифрование архива")
	}
	if pw == "" {
		return nil, errZipPassword
	}
	raw, err := f.OpenRaw()
	if err != nil {
		return nil, err
	}
	hdr := make([]byte, aesSaltLen+2)
	if _, err := io.ReadFull(raw, hdr); err != nil {
		return nil, err
	}
	ek, ak, ver := aesKeys(pw, hdr[:aesSaltLen])
	if hdr[aesSaltLen] != ver[0] || hdr[aesSaltLen+1] != ver[1] {
		return nil, errZipPassword
	}
	total := int64(f.CompressedSize64) - int64(aesSaltLen+2+aesMacLen)
	if total < 0 {
		return nil, errors.New("архив повреждён")
	}
	ar := &aesReader{src: io.LimitReader(raw, total), rest: raw, ctr: newCtrLE(ek), mac: hmac.New(sha1.New, ak)}
	e := &aesEntry{aes: ar}
	switch method {
	case zip.Store:
		e.rc = ar
	case zip.Deflate:
		fr := flate.NewReader(ar)
		e.rc, e.cl = fr, fr
	default:
		return nil, errors.New("неподдерживаемый способ сжатия в архиве")
	}
	return e, nil
}
