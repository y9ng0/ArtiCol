package main

import (
	"encoding/json"
	"fmt"
	"time"

	"golang.org/x/sys/unix"
)

// Запись в логи с добавлением времени по UTC и префиксом вывода.
func loggingFile(c *Collector, text_input, type_input string, err error) {
	time_now := time.Now().UTC().Format(time.DateTime)
	var line string
	if err == nil {
		line = fmt.Sprintf("%s [%s] %s\n", time_now,
			type_input, text_input)
	} else {
		line = fmt.Sprintf("%s [%s] %s %v\n", time_now,
			type_input, text_input, err)
	}
	unix.Write(c.LogFile, []byte(line))
}

// Запись в логи и стандартный вывод в консоль с добавлением времени по UTC и префиксом вывода.
func loggingFilePlusConsole(c *Collector, text_input, type_input string, err error) {
	time_now := time.Now().UTC().Format(time.DateTime)
	var line string
	if err == nil {
		line = fmt.Sprintf("%s [%s] %s\n", time_now,
			type_input, text_input)
	} else {
		line = fmt.Sprintf("%s [%s] %s %v\n", time_now,
			type_input, text_input, err)
	}
	unix.Write(1, []byte(line))
	unix.Write(c.LogFile, []byte(line))
}

// Запись данных в json файл
// strct - слайс структур
func loggingJson(c *Collector, strct any, title string, flag bool, file int) {
	data, err := json.Marshal(strct)
	data = append(data, '\n')
	if err != nil {
		text_input := fmt.Sprintf("Problem adding to JSON. %s", title)
		loggingFilePlusConsole(c, text_input, "WARNING", err)
	}
	_, err = unix.Write(file, data)
	if flag {
		if err == nil {
			text_input := fmt.Sprintf("%s added to JSON.", title)
			loggingFilePlusConsole(c, text_input, "INFO", err)
		} else {
			text_input := fmt.Sprintf("%s not added to JSON.", title)
			loggingFilePlusConsole(c, text_input, "WARNING", err)
		}
	} else {
		if err == nil {
			text_input := fmt.Sprintf("%s added to JSON.", title)
			loggingFile(c, text_input, "INFO", err)
		} else {
			text_input := fmt.Sprintf("%s not added to JSON.", title)
			loggingFile(c, text_input, "WARNING", err)
		}
	}
}
