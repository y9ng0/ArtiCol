package main

import (
	"encoding/json"
	"fmt"
	"time"

	"golang.org/x/sys/unix"
)

// loggingFile - запись в лог файл с добавлением времени по UTC и префиксом вывода.
// c - коллектор
// text_input - текст для логирования
// type_input - тип логирования (INFO, WARNING, ERROR)
// err - ошибка (если есть, иначе nil)
func loggingFile(c *Collector, text_input, type_input string, err error) {
	time_now := time.Now().UTC().Format(time.DateTime)
	var line string
	if err == nil {
		line = fmt.Sprintf("%s [%s] %s\n", time_now,
			type_input, text_input)
	} else {
		line = fmt.Sprintf("%s [%s] %s Error: %v.\n", time_now,
			type_input, text_input, err)
	}
	c.LogMutex.Lock()
	unix.Write(c.LogFile, []byte(line))
	c.LogMutex.Unlock()
}

// loggingConsole - запись в стандартный вывод в консоль с добавлением времени по UTC и префиксом вывода.
// text_input - текст для логирования
// type_input - тип логирования (INFO, WARNING, ERROR)
// err - ошибка (если есть, иначе nil)
func loggingConsole(text_input, type_input string, err error) {
	time_now := time.Now().UTC().Format(time.DateTime)
	var line string
	if err == nil {
		line = fmt.Sprintf("%s [%s] %s\n", time_now, type_input, text_input)
	} else {
		line = fmt.Sprintf("%s [%s] %s Error: %v.\n", time_now, type_input, text_input, err)
	}
	unix.Write(1, []byte(line))
}

// loggingFilePlusConsole - запись в логи и стандартный вывод в консоль с добавлением времени по UTC и префиксом вывода.
// c - коллектор
// text_input - текст для логирования
// type_input - тип логирования (INFO, WARNING, ERROR)
// err - ошибка (если есть, иначе nil)
func loggingFilePlusConsole(c *Collector, text_input, type_input string, err error) {
	time_now := time.Now().UTC().Format(time.DateTime)
	var line string
	if err == nil {
		line = fmt.Sprintf("%s [%s] %s\n", time_now,
			type_input, text_input)
	} else {
		line = fmt.Sprintf("%s [%s] %s Error:%v.\n", time_now,
			type_input, text_input, err)
	}
	c.LogMutex.Lock()
	unix.Write(1, []byte(line))
	unix.Write(c.LogFile, []byte(line))
	c.LogMutex.Unlock()
}

// loggingJson - запись данных в json файл
// c - коллектор
// strct - структура для записи
// title - название записи
// flag - флаг для вывода в консоль, если true - выводит в консоль и лог
// file - файл для записи
func loggingJson(c *Collector, strct any, title string, flag bool, file int) {
	loggingFile(c, fmt.Sprintf("Starting to write information about \"%s\"...", title), "INFO", nil)

	// Маршалим структуру в JSON
	data, err := json.Marshal(strct)
	data = append(data, '\n')
	if err != nil {
		text_input := fmt.Sprintf("Problem converting information about \"%v\" to JSON.", title)
		loggingFilePlusConsole(c, text_input, "WARNING", err)
		return
	}

	// Записываем в файл
	_, err = unix.Write(file, data)

	// Выводим в консоль и лог
	text_input := fmt.Sprintf("JSON structure for \"%v\" written to file.", title)
	text_input_err := fmt.Sprintf("JSON structure for \"%v\" not written to file.", title)
	if flag {
		if err == nil {
			loggingFilePlusConsole(c, text_input, "INFO", err)
		} else {
			loggingFilePlusConsole(c, text_input_err, "WARNING", err)
		}
		// Выводим только в лог
	} else {
		if err == nil {
			loggingFile(c, text_input, "INFO", err)
		} else {
			loggingFile(c, text_input_err, "WARNING", err)
		}
	}
}
