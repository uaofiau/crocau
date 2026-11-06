//go:build windows

package main

import "github.com/lxn/walk"

// fileListModel - список файлов на вкладке «Отправить». Свой тип модели позволяет удалять строки по одной
// (без полной перезагрузки списка), что надёжнее при выделении нескольких файлов с Ctrl.
type fileListModel struct {
	walk.ListModelBase
	items *[]string
}

func (m *fileListModel) ItemCount() int { return len(*m.items) }

func (m *fileListModel) Value(i int) interface{} {
	if i < 0 || i >= len(*m.items) {
		return ""
	}
	return (*m.items)[i]
}
