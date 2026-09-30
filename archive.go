package main

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	archiveSuffix = ".crocau.zip"
	// Уровень deflate 6 - золотая середина: почти как максимум по размеру, но в разы быстрее уровня 9.
	zipLevel = 6
)

var archiveNameRe = regexp.MustCompile(`^crocau-[0-9a-f]{8}\.crocau\.zip$`)

// Форматы, которые уже сжаты: кладём в архив без сжатия.
var storedExt = map[string]bool{
	".zip": true, ".rar": true, ".7z": true, ".gz": true, ".bz2": true, ".xz": true, ".zst": true,
	".lz4": true, ".lzma": true, ".cab": true, ".tgz": true, ".tbz": true, ".tbz2": true, ".txz": true,
	".jar": true, ".apk": true, ".docx": true, ".xlsx": true, ".pptx": true, ".odt": true, ".ods": true,
	".odp": true, ".epub": true, ".msi": true, ".deb": true, ".rpm": true, ".dmg": true,
	".mp3": true, ".aac": true, ".m4a": true, ".ogg": true, ".oga": true, ".opus": true, ".flac": true,
	".wma": true, ".mp4": true, ".m4v": true, ".mkv": true, ".avi": true, ".mov": true, ".wmv": true,
	".webm": true, ".flv": true, ".mpg": true, ".mpeg": true, ".3gp": true,
	".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".webp": true, ".heic": true, ".heif": true,
	".avif": true, ".jxl": true, ".pdf": true, ".woff": true, ".woff2": true,
}

// isIncompressible: по расширению, а для остальных - пробным сжатием начала файла.
func isIncompressible(path string, size int64) bool {
	if storedExt[strings.ToLower(filepath.Ext(path))] {
		return true
	}
	if size < 8*1024 {
		return false
	}
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	sample := make([]byte, 128*1024)
	n, _ := io.ReadFull(f, sample)
	if n == 0 {
		return false
	}
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, 1)
	_, _ = w.Write(sample[:n])
	_ = w.Close()
	return float64(buf.Len()) > 0.92*float64(n)
}

type arcEntry struct {
	src  string
	name string
	info fs.FileInfo
	dir  bool
}

func uniqueName(base string, used map[string]bool) string {
	name := base
	for i := 2; used[strings.ToLower(name)]; i++ {
		name = fmt.Sprintf("%s (%d)", base, i)
	}
	used[strings.ToLower(name)] = true
	return name
}

func collectEntries(items []string) ([]arcEntry, int64, int, error) {
	var entries []arcEntry
	var total int64
	skipped := 0
	used := map[string]bool{}
	for _, it := range items {
		st, err := os.Stat(it)
		if err != nil {
			return nil, 0, 0, err
		}
		base := strings.Trim(filepath.Base(it), `\/:.`)
		if base == "" {
			base = "disk"
		}
		base = uniqueName(base, used)
		if !st.IsDir() {
			entries = append(entries, arcEntry{src: it, name: base, info: st})
			total += st.Size()
			continue
		}
		_ = filepath.WalkDir(it, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				skipped++
				if d != nil && d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			rel, _ := filepath.Rel(it, p)
			name := base
			if rel != "." {
				name = base + "/" + filepath.ToSlash(rel)
			}
			if d.Type()&fs.ModeSymlink != 0 {
				skipped++
				return nil
			}
			info, err := d.Info()
			if err != nil {
				skipped++
				return nil
			}
			if d.IsDir() {
				entries = append(entries, arcEntry{name: name + "/", info: info, dir: true})
				return nil
			}
			if !info.Mode().IsRegular() {
				skipped++
				return nil
			}
			entries = append(entries, arcEntry{src: p, name: name, info: info})
			total += info.Size()
			return nil
		})
	}
	return entries, total, skipped, nil
}

func humanSize(n int64) string {
	const k = 1024.0
	f := float64(n)
	switch {
	case f >= k*k*k:
		return fmt.Sprintf("%.1f ГБ", f/(k*k*k))
	case f >= k*k:
		return fmt.Sprintf("%.1f МБ", f/(k*k))
	case f >= k:
		return fmt.Sprintf("%.1f КБ", f/k)
	}
	return fmt.Sprintf("%d Б", n)
}

var errCancelled = errors.New("отменено")

// buildArchive собирает zip (текст + файлы/папки) в work и возвращает путь к нему.
func buildArchive(j *Job, work, text string, items []string) (string, error) {
	entries, total, skipped, err := collectEntries(items)
	if err != nil {
		return "", err
	}
	out := filepath.Join(work, "crocau-"+randHex(4)+archiveSuffix)
	f, err := os.Create(out)
	if err != nil {
		return "", err
	}
	zw := zip.NewWriter(f)
	zw.RegisterCompressor(zip.Deflate, func(w io.Writer) (io.WriteCloser, error) { return flate.NewWriter(w, zipLevel) })
	fail := func(e error) (string, error) {
		_ = zw.Close()
		_ = f.Close()
		_ = os.Remove(out)
		return "", e
	}
	if text != "" {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: textFileName, Method: zip.Deflate, Modified: time.Now()})
		if err != nil {
			return fail(err)
		}
		if _, err := io.WriteString(w, text); err != nil {
			return fail(err)
		}
	}
	var done int64
	last := time.Now()
	buf := make([]byte, 256*1024)
	for _, e := range entries {
		if j.isKilled() {
			return fail(errCancelled)
		}
		hdr := &zip.FileHeader{Name: e.name, Modified: e.info.ModTime()}
		if e.dir {
			hdr.Method = zip.Store
			hdr.SetMode(fs.ModeDir | 0755)
			if _, err := zw.CreateHeader(hdr); err != nil {
				return fail(err)
			}
			continue
		}
		hdr.SetMode(e.info.Mode().Perm())
		if isIncompressible(e.src, e.info.Size()) {
			hdr.Method = zip.Store
		} else {
			hdr.Method = zip.Deflate
		}
		w, err := zw.CreateHeader(hdr)
		if err != nil {
			return fail(err)
		}
		src, err := os.Open(e.src)
		if err != nil {
			return fail(err)
		}
		for {
			n, rerr := src.Read(buf)
			if n > 0 {
				if _, werr := w.Write(buf[:n]); werr != nil {
					src.Close()
					return fail(werr)
				}
				done += int64(n)
				if time.Since(last) > 250*time.Millisecond {
					last = time.Now()
					pct := 100
					if total > 0 {
						pct = int(done * 100 / total)
					}
					j.setStatus(fmt.Sprintf("Архивирование: %d%% (%s)", pct, filepath.Base(e.src)))
					if j.isKilled() {
						src.Close()
						return fail(errCancelled)
					}
				}
			}
			if rerr != nil {
				if rerr != io.EOF {
					src.Close()
					return fail(rerr)
				}
				break
			}
		}
		src.Close()
	}
	if err := zw.Close(); err != nil {
		_ = f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	j.setStatus("")
	if st, err := os.Stat(out); err == nil {
		j.addNote(fmt.Sprintf("Архив: %s -> %s", humanSize(total), humanSize(st.Size())))
	}
	if skipped > 0 {
		j.addNote(fmt.Sprintf("Пропущено элементов (ссылки, недоступные): %d", skipped))
	}
	return out, nil
}

func safeArchiveName(name string) bool {
	if name == "" || strings.HasPrefix(name, "/") || strings.Contains(name, ":") {
		return false
	}
	for _, part := range strings.Split(name, "/") {
		if part == ".." {
			return false
		}
	}
	return true
}

// extractZip распаковывает архив в out, не выпуская записи за пределы out.
func extractZip(j *Job, zipPath, out string) error {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer zr.Close()
	var total uint64
	for _, f := range zr.File {
		total += f.UncompressedSize64
	}
	var done uint64
	last := time.Now()
	base := filepath.Clean(out)
	buf := make([]byte, 256*1024)
	for _, f := range zr.File {
		if j.isKilled() {
			return errCancelled
		}
		name := strings.ReplaceAll(f.Name, "\\", "/")
		if !safeArchiveName(name) {
			return fmt.Errorf("небезопасный путь в архиве: %q", f.Name)
		}
		target := filepath.Join(base, filepath.FromSlash(name))
		rel, err := filepath.Rel(base, target)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return fmt.Errorf("небезопасный путь в архиве: %q", f.Name)
		}
		if f.Mode()&fs.ModeSymlink != 0 {
			continue
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		dst, err := os.Create(target)
		if err != nil {
			rc.Close()
			return err
		}
		for {
			n, rerr := rc.Read(buf)
			if n > 0 {
				if _, werr := dst.Write(buf[:n]); werr != nil {
					rc.Close()
					dst.Close()
					return werr
				}
				done += uint64(n)
				if time.Since(last) > 250*time.Millisecond {
					last = time.Now()
					pct := 100
					if total > 0 {
						pct = int(done * 100 / total)
					}
					j.setStatus(fmt.Sprintf("Распаковка: %d%% (%s)", pct, filepath.Base(target)))
				}
			}
			if rerr != nil {
				if rerr != io.EOF {
					rc.Close()
					dst.Close()
					return rerr
				}
				break
			}
		}
		rc.Close()
		if err := dst.Close(); err != nil {
			return err
		}
		if !f.Modified.IsZero() {
			_ = os.Chtimes(target, f.Modified, f.Modified)
		}
	}
	j.setStatus("")
	return nil
}

func listNames(dir string) map[string]bool {
	m := map[string]bool{}
	if es, err := os.ReadDir(dir); err == nil {
		for _, e := range es {
			m[e.Name()] = true
		}
	}
	return m
}

// extractArchives распаковывает в out все новые архивы crocau (имя crocau-xxxxxxxx.crocau.zip).
func extractArchives(j *Job, out string, pre map[string]bool) error {
	es, err := os.ReadDir(out)
	if err != nil {
		return err
	}
	var first error
	for _, e := range es {
		if e.IsDir() || !archiveNameRe.MatchString(e.Name()) || pre[e.Name()] {
			continue
		}
		zp := filepath.Join(out, e.Name())
		j.addNote("Получен архив, распаковка...")
		if err := extractZip(j, zp, out); err != nil {
			if first == nil {
				first = fmt.Errorf("распаковка не удалась: %v (архив оставлен: %s)", err, zp)
			}
			continue
		}
		_ = os.Remove(zp)
	}
	return first
}
