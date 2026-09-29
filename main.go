// crocau - один exe: оболочка (GUI) + встроенный croc.
// Режимы:
//   crocau.exe               - окно программы
//   crocau.exe --croc ...    - внутренний режим: работает как croc (запускается самой программой на каждую передачу)
//   crocau.exe --selftest    - самотест передачи (для CI)
//   crocau.exe --guitest     - тест окна (для CI)
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
		case "--nettest":
			os.Exit(netTest())
		case "--guitest":
			os.Exit(guiMain(true))
		}
	}
	os.Exit(guiMain(false))
}
