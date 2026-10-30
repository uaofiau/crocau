// crocau - один exe: оболочка (GUI) + встроенный croc.
// Режимы:
//
//	crocau.exe               - окно программы
//	crocau.exe --croc ...    - внутренний режим: работает как croc (запускается самой программой на каждую передачу)
//	crocau.exe --selftest    - самотест передачи (для CI)
//	crocau.exe --guitest     - тест окна (для CI)
//	crocau.exe --send путь.. - окно с добавленными файлами (меню Проводника «Отправить через Crocau»)
package main

import (
	"log"
	"os"

	"github.com/schollz/croc/v10/src/cli"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--croc":
			os.Args = append([]string{"croc"}, os.Args[2:]...)
			if err := cli.Run(); err != nil {
				log.Fatalln(err)
			}
			return
		case "--selftest":
			os.Exit(selfTest())
		case "--fw-install":
			os.Exit(fwInstallMain())
		case "--fw-remove":
			os.Exit(fwRemoveMain())
		case "--fwtest":
			os.Exit(fwSelfTest())
		case "--chattest":
			os.Exit(chatSpike())
		case "--nettest":
			os.Exit(netTest())
		case "--send":
			// из меню Проводника: окно с выбранными файлами (или пересылка в уже открытое окно)
			if code := shellSendMain(os.Args[2:]); code >= 0 {
				os.Exit(code)
			}
		case "--guitest":
			os.Exit(guiMain(true))
		}
	}
	os.Exit(guiMain(false))
}
