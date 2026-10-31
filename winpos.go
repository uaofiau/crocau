package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// Положение и размер окна запоминаются только для этого компьютера (в файле хранится "отпечаток" компьютера).

type winGeom struct {
	X, Y, W, H int
	Max        bool
}

func hostToken(machineGUID, hostname string) string {
	h := sha256.Sum256([]byte("crocau-win:" + machineGUID + "|" + strings.ToLower(hostname)))
	return hex.EncodeToString(h[:6])
}

func encodeGeom(host string, g winGeom) string {
	m := 0
	if g.Max {
		m = 1
	}
	return fmt.Sprintf("%s|%d|%d|%d|%d|%d", host, g.X, g.Y, g.W, g.H, m)
}

// parseGeom разбирает запись; ok=false, если запись повреждена или сделана на другом компьютере.
func parseGeom(text, host string) (winGeom, bool) {
	f := strings.Split(strings.TrimSpace(text), "|")
	if len(f) != 6 || f[0] != host {
		return winGeom{}, false
	}
	var v [5]int
	for i := 0; i < 5; i++ {
		n, err := strconv.Atoi(f[i+1])
		if err != nil {
			return winGeom{}, false
		}
		v[i] = n
	}
	return winGeom{v[0], v[1], v[2], v[3], v[4] == 1}, true
}

// clampGeom вписывает окно в рабочую область монитора wa (левый, верхний, правый, нижний края),
// не меньше минимального размера. Если область меньше минимума, минимум имеет приоритет.
func clampGeom(g winGeom, waL, waT, waR, waB, minW, minH int) winGeom {
	aw, ah := waR-waL, waB-waT
	if g.W > aw {
		g.W = aw
	}
	if g.H > ah {
		g.H = ah
	}
	if g.W < minW {
		g.W = minW
	}
	if g.H < minH {
		g.H = minH
	}
	if g.X+g.W > waR {
		g.X = waR - g.W
	}
	if g.Y+g.H > waB {
		g.Y = waB - g.H
	}
	if g.X < waL {
		g.X = waL
	}
	if g.Y < waT {
		g.Y = waT
	}
	return g
}
