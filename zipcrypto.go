package main

import (
	"archive/zip"
	"compress/flate"
	"crypto/rand"
	"errors"
	"hash/crc32"
	"io"
	"os"
)

// Традиционное шифрование zip (ZipCrypto). Слабое, зато такие архивы открывает Проводник Windows (7 и новее)
// без внешних архиваторов - используется, когда в архив вложена программа и важна универсальность.

type zcKeys struct{ k0, k1, k2 uint32 }

func crcUpd(crc uint32, b byte) uint32 { return crc32.IEEETable[byte(crc)^b] ^ (crc >> 8) }

func newZC(pw []byte) *zcKeys {
	k := &zcKeys{305419896, 591751049, 878082192}
	for _, c := range pw {
		k.update(c)
	}
	return k
}

func (k *zcKeys) update(c byte) {
	k.k0 = crcUpd(k.k0, c)
	k.k1 = (k.k1+(k.k0&0xff))*134775813 + 1
	k.k2 = crcUpd(k.k2, byte(k.k1>>24))
}

func (k *zcKeys) stream() byte {
	t := uint16(k.k2) | 2
	return byte((uint32(t) * uint32(t^1)) >> 8)
}

func (k *zcKeys) enc(b byte) byte {
	c := b ^ k.stream()
	k.update(b)
	return c
}

func (k *zcKeys) dec(c byte) byte {
	b := c ^ k.stream()
	k.update(b)
	return b
}

// encryptZipClassic перепаковывает zip src в dst с традиционным шифрованием паролем pw.
func encryptZipClassic(src, dst, pw, comment string) error {
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
			Name: f.Name, Method: f.Method, Modified: f.Modified, Flags: flags,
			CRC32: f.CRC32, CompressedSize64: f.CompressedSize64 + 12, UncompressedSize64: f.UncompressedSize64,
		}
		h.SetMode(f.Mode())
		w, err := zw.CreateRaw(h)
		if err != nil {
			return fail(err)
		}
		k := newZC([]byte(pw))
		hdr := make([]byte, 12)
		if _, err := rand.Read(hdr[:11]); err != nil {
			return fail(err)
		}
		hdr[11] = byte(f.CRC32 >> 24)
		for i := range hdr {
			hdr[i] = k.enc(hdr[i])
		}
		if _, err := w.Write(hdr); err != nil {
			return fail(err)
		}
		buf := make([]byte, 64*1024)
		for {
			n, rerr := raw.Read(buf)
			if n > 0 {
				for i := 0; i < n; i++ {
					buf[i] = k.enc(buf[i])
				}
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
	}
	if err := zw.Close(); err != nil {
		_ = out.Close()
		_ = os.Remove(dst)
		return err
	}
	return out.Close()
}

type zcReader struct {
	src io.Reader
	k   *zcKeys
}

func (z *zcReader) Read(p []byte) (int, error) {
	n, err := z.src.Read(p)
	for i := 0; i < n; i++ {
		p[i] = z.k.dec(p[i])
	}
	return n, err
}

// crcVerify проверяет CRC32 распакованных данных на конце потока (неверный пароль почти всегда даёт несовпадение).
type crcVerify struct {
	r    io.Reader
	cl   io.Closer
	want uint32
	sum  uint32
}

func (c *crcVerify) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.sum = crc32.Update(c.sum, crc32.IEEETable, p[:n])
	if err == io.EOF && c.sum != c.want {
		return n, errZipPassword
	}
	return n, err
}

func (c *crcVerify) Close() error {
	if c.cl != nil {
		return c.cl.Close()
	}
	return nil
}

// openZipClassic открывает запись, зашифрованную традиционным способом.
func openZipClassic(f *zip.File, pw string) (io.ReadCloser, error) {
	if pw == "" {
		return nil, errZipPassword
	}
	if f.Method != zip.Store && f.Method != zip.Deflate {
		return nil, errors.New("неподдерживаемый способ сжатия в архиве")
	}
	raw, err := f.OpenRaw()
	if err != nil {
		return nil, err
	}
	k := newZC([]byte(pw))
	hdr := make([]byte, 12)
	if _, err := io.ReadFull(raw, hdr); err != nil {
		return nil, err
	}
	for i := range hdr {
		hdr[i] = k.dec(hdr[i])
	}
	check := byte(f.CRC32 >> 24)
	alt := byte(f.ModifiedTime >> 8) // при записи с «дескриптором данных» проверочный байт - из времени файла
	if hdr[11] != check && !(f.Flags&8 != 0 && hdr[11] == alt) {
		return nil, errZipPassword
	}
	var r io.Reader = &zcReader{src: io.LimitReader(raw, int64(f.CompressedSize64)-12), k: k}
	var cl io.Closer
	if f.Method == zip.Deflate {
		fr := flate.NewReader(r)
		r, cl = fr, fr
	}
	return &crcVerify{r: r, cl: cl, want: f.CRC32}, nil
}
