package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Анонимные файлообменники: загрузка и скачивание обычным HTTP, без сторонних библиотек.
// Файл на обменнике храним в виде zip (по желанию - с паролем AES), поэтому сам сервис содержимого не видит.

const uploaderUA = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36"

type xProvider struct {
	name   string
	max    int64 // предельный размер файла, байт
	keep   string
	upload func(ctx context.Context, c *http.Client, file, name string, size int64, prog func(done int64)) (string, error)
}

func uploadTextURL(body string) (string, error) {
	b := strings.TrimSpace(body)
	if !strings.HasPrefix(b, "http") {
		if len(b) > 60 {
			b = b[:60]
		}
		return "", fmt.Errorf("неожиданный ответ: %q", b)
	}
	if i := strings.IndexAny(b, " \r\n"); i > 0 {
		b = b[:i]
	}
	return b, nil
}

var xProviders = []xProvider{
	{name: "litterbox.catbox.moe", max: 1 << 30, keep: "72 часа", upload: func(ctx context.Context, c *http.Client, file, name string, size int64, prog func(int64)) (string, error) {
		body, err := postMultipart(ctx, c, "https://litterbox.catbox.moe/resources/internals/api.php",
			map[string]string{"reqtype": "fileupload", "time": "72h"}, "fileToUpload", file, name, size, prog)
		if err != nil {
			return "", err
		}
		return uploadTextURL(body)
	}},
	{name: "temp.sh", max: 4 << 30, keep: "3 суток", upload: func(ctx context.Context, c *http.Client, file, name string, size int64, prog func(int64)) (string, error) {
		body, err := postMultipart(ctx, c, "https://temp.sh/upload", nil, "file", file, name, size, prog)
		if err != nil {
			return "", err
		}
		return uploadTextURL(body)
	}},
	{name: "tmpfiles.org", max: 100 << 20, keep: "1 час", upload: func(ctx context.Context, c *http.Client, file, name string, size int64, prog func(int64)) (string, error) {
		body, err := postMultipart(ctx, c, "https://tmpfiles.org/api/v1/upload", nil, "file", file, name, size, prog)
		if err != nil {
			return "", err
		}
		var r struct {
			Data struct {
				URL string `json:"url"`
			} `json:"data"`
		}
		if err := json.Unmarshal([]byte(body), &r); err != nil || r.Data.URL == "" {
			return "", errors.New("неожиданный ответ")
		}
		return fixTmpfiles(r.Data.URL), nil
	}},
	{name: "uguu.se", max: 128 << 20, keep: "3 часа", upload: func(ctx context.Context, c *http.Client, file, name string, size int64, prog func(int64)) (string, error) {
		body, err := postMultipart(ctx, c, "https://uguu.se/upload?output=text", nil, "files[]", file, name, size, prog)
		if err != nil {
			return "", err
		}
		return uploadTextURL(body)
	}},
}

// fixTmpfiles: страница tmpfiles.org/123/name -> прямая ссылка tmpfiles.org/dl/123/name.
func fixTmpfiles(u string) string {
	u = strings.Replace(u, "http://", "https://", 1)
	if strings.Contains(u, "tmpfiles.org/") && !strings.Contains(u, "/dl/") {
		u = strings.Replace(u, "tmpfiles.org/", "tmpfiles.org/dl/", 1)
	}
	return u
}

type countReader struct {
	r    io.Reader
	n    int64
	prog func(int64)
	last time.Time
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	if c.prog != nil && time.Since(c.last) > 300*time.Millisecond {
		c.last = time.Now()
		c.prog(c.n)
	}
	return n, err
}

func randBoundary() string { return "----crocau" + randHex(12) }

func postMultipart(ctx context.Context, c *http.Client, urlStr string, fields map[string]string, fileField, file, name string, size int64, prog func(int64)) (string, error) {
	boundary := randBoundary()
	var head strings.Builder
	for k, v := range fields {
		head.WriteString("--" + boundary + "\r\nContent-Disposition: form-data; name=\"" + k + "\"\r\n\r\n" + v + "\r\n")
	}
	safe := strings.NewReplacer(`"`, "_", "\r", "_", "\n", "_").Replace(name)
	head.WriteString("--" + boundary + "\r\nContent-Disposition: form-data; name=\"" + fileField + "\"; filename=\"" + safe + "\"\r\nContent-Type: application/octet-stream\r\n\r\n")
	tail := "\r\n--" + boundary + "--\r\n"
	f, err := os.Open(file)
	if err != nil {
		return "", err
	}
	defer f.Close()
	body := io.MultiReader(strings.NewReader(head.String()), &countReader{r: f, prog: prog}, strings.NewReader(tail))
	req, err := http.NewRequestWithContext(ctx, "POST", urlStr, body)
	if err != nil {
		return "", err
	}
	req.ContentLength = int64(head.Len()) + size + int64(len(tail))
	req.Header.Set("Content-Type", "multipart/form-data; boundary="+boundary)
	req.Header.Set("User-Agent", uploaderUA)
	req.Header.Set("Accept", "*/*")
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		t := strings.TrimSpace(strings.ReplaceAll(string(b), "\n", " "))
		if len(t) > 70 {
			t = t[:70]
		}
		return "", fmt.Errorf("HTTP %d %s", resp.StatusCode, t)
	}
	return string(b), nil
}

// httpClientVia делает HTTP-клиент, выходящий в сеть напрямую или через выбранный прокси.
func httpClientVia(r Route, total time.Duration) *http.Client {
	tr := &http.Transport{
		Proxy:               nil,
		TLSHandshakeTimeout: 25 * time.Second,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if r.P == nil {
				d := net.Dialer{Timeout: 20 * time.Second}
				return d.DialContext(ctx, network, addr)
			}
			return dialVia(r, addr, 20*time.Second)
		},
		ResponseHeaderTimeout: 3 * time.Minute,
		DisableCompression:    true,
	}
	return &http.Client{Transport: tr, Timeout: total}
}

// uploadChain пробует обменники по очереди (с учётом размера); возвращает ссылку и имя сервиса.
func uploadChain(ctx context.Context, r Route, file, name string, prog func(done, total int64), note func(string)) (string, string, error) {
	fi, err := os.Stat(file)
	if err != nil {
		return "", "", err
	}
	size := fi.Size()
	var errs []string
	for _, p := range xProviders {
		if size > p.max {
			continue
		}
		if ctx.Err() != nil {
			return "", "", errCancelled
		}
		note("Загрузка на " + p.name + "...")
		c := httpClientVia(r, 2*time.Hour)
		u, err := p.upload(ctx, c, file, name, size, func(d int64) { prog(d, size) })
		if err == nil {
			return u, p.name + ", хранится ~" + p.keep, nil
		}
		if ctx.Err() != nil {
			return "", "", errCancelled
		}
		note(p.name + ": " + err.Error())
		errs = append(errs, p.name+": "+err.Error())
	}
	if len(errs) == 0 {
		return "", "", fmt.Errorf("файл (%s) больше предела всех обменников", humanSize(size))
	}
	return "", "", errors.New(strings.Join(errs, "; "))
}

func humanSize(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f ГБ", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f МБ", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f КБ", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d Б", n)
}

// normalizeLink приводит вставленную ссылку к прямой (убирает пробелы, чинит tmpfiles).
var linkRe = regexp.MustCompile(`https?://[^\s<>"]+`)

func normalizeLink(s string) (string, error) {
	s = strings.TrimSpace(s)
	if m := linkRe.FindString(s); m != "" {
		s = m
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", errors.New("вставьте ссылку вида https://...")
	}
	if strings.HasSuffix(u.Host, "tmpfiles.org") {
		return fixTmpfiles(s), nil
	}
	return s, nil
}

// downloadLink скачивает файл по ссылке в папку dir и возвращает путь к нему.
func downloadLink(ctx context.Context, r Route, link, dir string, prog func(done, total int64)) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", link, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", uploaderUA)
	c := httpClientVia(r, 2*time.Hour)
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d (ссылка устарела или недоступна)", resp.StatusCode)
	}
	name := ""
	if cd := resp.Header.Get("Content-Disposition"); cd != "" {
		if _, params, err := mime.ParseMediaType(cd); err == nil {
			name = params["filename"]
		}
	}
	if name == "" {
		name = path.Base(resp.Request.URL.Path)
		if n, err := url.PathUnescape(name); err == nil {
			name = n
		}
	}
	name = cleanFileName(name)
	if name == "" {
		name = "download-" + randHex(3)
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}
	dst := filepath.Join(dir, name)
	f, err := os.Create(dst)
	if err != nil {
		return "", err
	}
	cr := &countReader{r: resp.Body, prog: func(d int64) { prog(d, resp.ContentLength) }}
	_, err = io.Copy(f, cr)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(dst)
		return "", err
	}
	return dst, nil
}

func cleanFileName(n string) string {
	n = strings.Map(func(c rune) rune {
		if c < 32 || strings.ContainsRune(`\/:*?"<>|`, c) {
			return '_'
		}
		return c
	}, n)
	n = strings.Trim(n, " .")
	if n == "" || n == "_" {
		return ""
	}
	if r := []rune(n); len(r) > 120 {
		n = string(r[:120])
	}
	return n
}
