package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"os"
)

// Шифрование файла для передачи через обменники в интернет-чате: AES-256-GCM по блокам по 64 КБ.
// Ключ у каждого файла свой и лежит только внутри зашифрованного сообщения чата. Последний блок помечен,
// поэтому обрезанный файл не расшифруется.

const (
	chatFileChunk = 64 * 1024
	chatFileMagic = "CRCF1"
)

func chatFileAEAD(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

func chatFileNonce(i uint64) []byte {
	n := make([]byte, 12)
	binary.BigEndian.PutUint64(n[4:], i)
	return n
}

func chatEncryptFile(src, dst string, key []byte) error {
	aead, err := chatFileAEAD(key)
	if err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	bw := bufio.NewWriterSize(out, 256*1024)
	_, _ = bw.WriteString(chatFileMagic)
	br := bufio.NewReaderSize(in, chatFileChunk*2)
	buf := make([]byte, chatFileChunk)
	var idx uint64
	for {
		n, err := io.ReadFull(br, buf)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			out.Close()
			return err
		}
		final := byte(0)
		if _, perr := br.Peek(1); perr != nil {
			final = 1
		}
		ct := aead.Seal(nil, chatFileNonce(idx), buf[:n], []byte{final})
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(ct)))
		_, _ = bw.Write(l[:])
		_, _ = bw.Write(ct)
		idx++
		if final == 1 {
			break
		}
	}
	if err := bw.Flush(); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func chatDecryptFile(src, dst string, key []byte) error {
	aead, err := chatFileAEAD(key)
	if err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	br := bufio.NewReaderSize(in, 256*1024)
	magic := make([]byte, len(chatFileMagic))
	if _, err := io.ReadFull(br, magic); err != nil || string(magic) != chatFileMagic {
		return errors.New("файл повреждён или это не файл чата")
	}
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	bw := bufio.NewWriterSize(out, 256*1024)
	fail := func(e error) error {
		out.Close()
		os.Remove(dst)
		return e
	}
	var idx uint64
	for {
		var l [4]byte
		if _, err := io.ReadFull(br, l[:]); err != nil {
			return fail(errors.New("файл обрезан"))
		}
		n := binary.BigEndian.Uint32(l[:])
		if n < 16 || n > chatFileChunk+16 {
			return fail(errors.New("файл повреждён"))
		}
		ct := make([]byte, n)
		if _, err := io.ReadFull(br, ct); err != nil {
			return fail(errors.New("файл обрезан"))
		}
		_, perr := br.Peek(1)
		final := byte(0)
		if perr != nil {
			final = 1
		}
		pt, err := aead.Open(nil, chatFileNonce(idx), ct, []byte{final})
		if err != nil {
			return fail(errors.New("не удалось расшифровать файл (неверный ключ или файл изменён)"))
		}
		_, _ = bw.Write(pt)
		idx++
		if final == 1 {
			break
		}
	}
	if err := bw.Flush(); err != nil {
		return fail(err)
	}
	return out.Close()
}

func mustRand(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}
