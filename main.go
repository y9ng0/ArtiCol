package main

import (
	"fmt"
	"time"

	"github.com/shirou/gopsutil/v4/host"
	"golang.org/x/sys/unix"
)

var Log_file int
var Json_file int

// Инициализация работы (создание рабочего пространства и запуск горутин)
func initialization(flag bool) error {
	loggingConsole("Program started.", "INFO", nil)

	// Создание рабочей директории с названием хоста и указанием времени начала сбора
	info, err := host.Info()
	time_now := time.Now().UTC().Format(time.DateTime)
	var path_directory string
	if err == nil {
		path_directory = fmt.Sprintf("./%v_%v", time_now, info.Hostname)
		err = unix.Mkdir(path_directory, 0700)
	} else {
		path_directory = fmt.Sprintf("./%v_Unnamed", time_now)
		err = unix.Mkdir(path_directory, 0700)
	}
	if err == nil {
		loggingConsole("Directory created.", "OK", nil)
	} else {
		loggingConsole("Directory not created.", "ERROR", err)
		return err
	}

	// Создание лог файла
	filename := fmt.Sprintf("%v/program.log", path_directory)
	Log_file, err = unix.Open(filename, unix.O_CREAT|unix.O_WRONLY|unix.O_APPEND, 0700)
	if err == nil {
		loggingFilePlusConsole("Log file created.", "OK", nil)
		defer unix.Close(Log_file)
	} else {
		loggingConsole("Log file not created.", "ERROR", err)
		return err
	}

	// Создание файла json с собранной информацией
	filename = fmt.Sprintf("%v/program.json", path_directory)
	Json_file, err = unix.Open(filename, unix.O_CREAT|unix.O_WRONLY|unix.O_APPEND, 0700)
	if err == nil {
		loggingFilePlusConsole("Json file created.", "OK", nil)
		defer unix.Close(Json_file)
	} else {
		loggingFilePlusConsole("Json file not created.", "ERROR", err)
		return err
	}

	// Начало обхода системы на сбор артефактов
	// TODO: Добавить горутины
	var arrive = []string{"kernel", "hostname", "uptime"}
	for _, value := range arrive {
		copySysInfo := sysInfo{}
		systemInfo(&copySysInfo, value)
	}

	// Начало обхода системы при наличии root-прав
	if flag {
		loggingConsole("TODO: add root_artifacts", "INFO", nil)
	}
	return nil
}

// Проверка наличия root-прав процесса
func getProcessId() bool {
	user_id := unix.Getuid()
	if user_id == 0 {
		return true
	} else {
		return false
	}
}

// Вход в программу
func main() {
	start := time.Now()
	if getProcessId() {
		initialization(true)
	} else {
		initialization(false)

	}
	time_result := time.Since(start)
	result := fmt.Sprintf("You can remove the flash drive. The program runs in %v", time_result)
	loggingConsole(result, "DONE", nil)
}
