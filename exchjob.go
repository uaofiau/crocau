package main

import (
	"archive/zip"
	"compress/flate"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// Режим «Через обменники»: отправитель выкладывает zip (по желанию с паролем AES) на анонимный файлообменник
// и получает ссылку; получатель (с Crocau или без) скачивает по ссылке.

type upItem struct {
	path, name, label string
}

// zipOne кладёт один файл в zip (deflate) - для отправки самой программы.
func zipOne(src, nameInZip, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	fi, _ := in.Stat()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	zw := zip.NewWriter(out)
	zw.RegisterCompressor(zip.Deflate, func(w io.Writer) (io.WriteCloser, error) { return flate.NewWriter(w, zipLevel) })
	h := &zip.FileHeader{Name: nameInZip, Method: zip.Deflate}
	if fi != nil {
		h.Modified = fi.ModTime()
	}
	w, err := zw.CreateHeader(h)
	if err == nil {
		_, err = io.Copy(w, in)
	}
	if cerr := zw.Close(); err == nil {
		err = cerr
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(dst)
	}
	return err
}

func isRegularFile(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular()
}

// startExchSend загружает текст/файлы (и, по желанию, саму программу) на файлообменник.
// pw пустой - архив без пароля; иначе (от 3 символов) файлы в архиве шифруются AES-256.
func startExchSend(s Settings, pw, text string, items []string, withExe bool) (*Job, error) {
	if strings.TrimSpace(text) == "" {
		text = ""
	}
	if text == "" && len(items) == 0 && !withExe {
		return nil, errors.New("нечего отправлять")
	}
	if pw != "" && utf8.RuneCountInString(pw) < 3 {
		return nil, errors.New("пароль архива должен быть не короче 3 символов (или оставьте поле пустым - без пароля)")
	}
	routes, err := routesFor(s)
	if err != nil {
		return nil, err
	}
	work, err := newWork()
	if err != nil {
		return nil, err
	}
	from := cleanDeviceName(s.ExchName)
	var files []upItem
	spec := JobSpec{Work: work, Routes: routes}
	spec.Prep = func(j *Job) error {
		if text != "" || len(items) > 0 {
			if text == "" && len(items) == 1 && pw == "" && !s.Compress && isRegularFile(items[0]) {
				files = append(files, upItem{items[0], filepath.Base(items[0]), "Файл"})
			} else {
				j.setStatus("Архивирование...")
				p, err := buildArchive(j, work, text, from, items)
				if err != nil {
					return err
				}
				if pw != "" {
					j.setStatus("Шифрование архива...")
					enc := p + ".enc"
					if err := encryptZip(p, enc, pw, "crocau"); err != nil {
						return err
					}
					_ = os.Remove(p)
					p = enc
				}
				files = append(files, upItem{p, "crocau-" + randHex(4) + ".zip", "Файлы"})
			}
		}
		if withExe {
			exe, err := os.Executable()
			if err != nil {
				return err
			}
			if s.Compress {
				zp := filepath.Join(work, "crocau-program.zip")
				j.setStatus("Архивирование программы...")
				if err := zipOne(exe, "crocau.exe", zp); err != nil {
					return err
				}
				files = append(files, upItem{zp, "crocau.zip", "Программа Crocau"})
			} else {
				files = append(files, upItem{exe, "crocau.exe", "Программа Crocau"})
			}
		}
		j.setStatus("")
		return nil
	}
	spec.Do = func(j *Job, routes []Route) int {
		var lines []string
		for _, it := range files {
			link, info, err := uploadWithRoutes(j, routes, it)
			if err != nil && it.name == "crocau.exe" {
				// многие обменники отклоняют .exe: пробуем в zip
				zp := filepath.Join(work, "crocau-program.zip")
				j.addNote("Обменники не приняли .exe, пробую в zip...")
				if zerr := zipOne(it.path, "crocau.exe", zp); zerr == nil {
					link, info, err = uploadWithRoutes(j, routes, upItem{zp, "crocau.zip", it.label})
				}
			}
			if err != nil {
				if j.isKilled() {
					return -1
				}
				j.addNote("Ошибка: " + err.Error())
				return 1
			}
			j.addNote(fmt.Sprintf("%s: %s  (%s)", it.label, link, info))
			lines = append(lines, it.label+": "+link)
		}
		if pw != "" {
			j.addNote("Файлы в архиве зашифрованы паролем. Сообщите его получателю отдельно. Открыть архив можно в 7-Zip или WinRAR (Проводник Windows с такими архивами не работает).")
		}
		if len(lines) == 1 {
			lines[0] = lines[0][strings.Index(lines[0], ": ")+2:]
		}
		j.setResult(strings.Join(lines, "\r\n"))
		return 0
	}
	return startJob(spec), nil
}

func uploadWithRoutes(j *Job, routes []Route, it upItem) (string, string, error) {
	var last error
	for _, r := range routes {
		if j.isKilled() {
			return "", "", errCancelled
		}
		if r.P != nil {
			j.addNote("Маршрут: " + r.Name())
		}
		link, info, err := uploadChain(j.ctx, r, it.path, it.name, func(done, total int64) {
			pct := 0
			if total > 0 {
				pct = int(done * 100 / total)
			}
			j.setStatus(fmt.Sprintf("Загрузка «%s»: %d%% (%s из %s)", it.label, pct, humanSize(done), humanSize(total)))
		}, j.addNote)
		j.setStatus("")
		if err == nil {
			return link, info, nil
		}
		last = err
	}
	if last == nil {
		last = errors.New("нет маршрута")
	}
	return "", "", last
}

// startExchRecv скачивает по ссылке и распаковывает архивы Crocau (с паролем, если он есть) в папку out.
func startExchRecv(s Settings, pw, link, out string) (*Job, bool, error) {
	l, err := normalizeLink(link)
	if err != nil {
		return nil, false, err
	}
	routes, err := routesFor(s)
	if err != nil {
		return nil, false, err
	}
	created := false
	if _, err := os.Stat(out); os.IsNotExist(err) {
		created = true
	}
	if err := os.MkdirAll(out, 0755); err != nil {
		return nil, false, err
	}
	pre := listNames(out)
	work, err := newWork()
	if err != nil {
		return nil, false, err
	}
	spec := JobSpec{Work: work, Routes: routes}
	spec.Do = func(j *Job, routes []Route) int {
		dl := filepath.Join(work, "dl")
		var path string
		var last error
		for _, r := range routes {
			if j.isKilled() {
				return -1
			}
			if r.P != nil {
				j.addNote("Маршрут: " + r.Name())
			}
			p, err := downloadLink(j.ctx, r, l, dl, func(done, total int64) {
				if total > 0 {
					j.setStatus(fmt.Sprintf("Скачивание: %d%% (%s из %s)", int(done*100/total), humanSize(done), humanSize(total)))
				} else {
					j.setStatus("Скачивание: " + humanSize(done))
				}
			})
			j.setStatus("")
			if err == nil {
				path = p
				break
			}
			last = err
		}
		if path == "" {
			if j.isKilled() {
				return -1
			}
			j.addNote("Ошибка: " + fmt.Sprint(last))
			return 1
		}
		if err := placeDownloaded(j, path, out, pw, pre); err != nil {
			j.addNote("Ошибка: " + err.Error())
			return 2
		}
		return 0
	}
	j := startJob(spec)
	j.preCount = len(pre)
	j.pre = pre
	return j, created, nil
}

// placeDownloaded: архив Crocau (по метке в комментарии) распаковывает, любой другой файл просто кладёт в папку.
func placeDownloaded(j *Job, path, out, pw string, pre map[string]bool) error {
	if zr, err := zip.OpenReader(path); err == nil {
		isOurs := strings.HasPrefix(zr.Comment, "crocau")
		enc := false
		for _, f := range zr.File {
			if zipEntryEncrypted(f) {
				enc = true
				break
			}
		}
		zr.Close()
		if isOurs {
			if enc && pw == "" {
				return errors.New("архив защищён паролем: введите пароль в поле «Пароль» и повторите")
			}
			j.addNote("Распаковка...")
			if err := extractZipPw(j, path, out, pw); err != nil {
				if errors.Is(err, errZipPassword) {
					return errZipPassword
				}
				return fmt.Errorf("распаковка не удалась: %v", err)
			}
			j.addNote("Готово: файлы в папке " + out)
			return nil
		}
	}
	name := filepath.Base(path)
	dst := filepath.Join(out, name)
	for i := 2; fileExists(dst); i++ {
		ext := filepath.Ext(name)
		dst = filepath.Join(out, fmt.Sprintf("%s (%d)%s", strings.TrimSuffix(name, ext), i, ext))
	}
	if err := moveAny(path, dst); err != nil {
		return err
	}
	j.addNote("Сохранено: " + dst)
	return nil
}
