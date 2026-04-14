package main

import (
	"encoding/json"
	"fmt"
	"time"

	"golang.org/x/sys/unix"
)

// Стандартный вывод в консоль с добавлением времени по UTC и префиксом вывода
func loggingConsole(text_input, type_input string, err error) {
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
}

// Запись в логи с добавлением времени по UTC и префиксом вывода
func loggingFile(text_input, type_input string, err error) {
	time_now := time.Now().UTC().Format(time.DateTime)
	var line string
	if err == nil {
		line = fmt.Sprintf("%s [%s] %s\n", time_now,
			type_input, text_input)
	} else {
		line = fmt.Sprintf("%s [%s] %s %v\n", time_now,
			type_input, text_input, err)
	}
	unix.Write(Log_file, []byte(line))
}

// Запись в логи и стандартный вывод в консоль с добавлением времени по UTC и префиксом вывода
func loggingFilePlusConsole(text_input, type_input string, err error) {
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
	unix.Write(Log_file, []byte(line))
}

func loggingJson(str *sysInfo) {
	data, err := json.Marshal(str)
	data = append(data, '\n')
	if err != nil {
		text_input := fmt.Sprintf("Problem with %s", str.Title)
		loggingFilePlusConsole(text_input, "WARNING", err)
	}
	_, err = unix.Write(Json_file, data)
	if err == nil {
		text_input := fmt.Sprintf("%s added to json", str.Title)
		loggingFilePlusConsole(text_input, "OK", err)
	} else {
		text_input := fmt.Sprintf("%s not added to json", str.Title)
		loggingFilePlusConsole(text_input, "WARNING", err)
	}
}
