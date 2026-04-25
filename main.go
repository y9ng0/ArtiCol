package main

import (
	"bytes"
	"fmt"
	"time"

	"github.com/shirou/gopsutil/v4/host"
	"golang.org/x/sys/unix"
)

func jsonCreate(c *Collector, filename string) (int, error) {
	filename = fmt.Sprintf("%v/%v.json", c.MainDirectory, filename)
	file, err := unix.Open(filename, unix.O_CREAT|unix.O_WRONLY|unix.O_APPEND, 0777)
	if err == nil {
		loggingFilePlusConsole(c, fmt.Sprintf("File to path \"%v\" created.", filename), "INFO", nil)
		return file, nil
	} else {
		loggingFilePlusConsole(c, fmt.Sprintf("File to path \"%v\" not created.", filename), "ERROR", err)
		return 100000, err
	}
}

func getTimeUtc() string {
	return string(time.Now().UTC().Format(time.DateTime))
}

func makeDirectory(path string) error {
	return unix.Mkdir(path, 0777)
}

func loggingConsole(text_input, type_input string, err error) {
	time_now := time.Now().UTC().Format(time.DateTime)
	var line string
	if err == nil {
		line = fmt.Sprintf("%s [%s] %s\n", time_now, type_input, text_input)
	} else {
		line = fmt.Sprintf("%s [%s] %s %v\n", time_now, type_input, text_input, err)
	}
	unix.Write(1, []byte(line))
}

// Инициализация работы (создание рабочего пространства и запуск горутин)
func initialization(c *Collector, flag bool, start time.Time) error {
	loggingConsole("Program started.", "INFO", nil)
	c.UserName = getUserProcessName()

	// Создание рабочей директории с названием хоста и указанием времени начала сбора
	info, err := host.Info()
	time_now := time.Now().UTC().Format(time.DateTime)
	if err == nil {
		c.MainDirectory = fmt.Sprintf("./%v_%v", time_now, info.Hostname)
		err = makeDirectory(c.MainDirectory)
	} else {
		c.MainDirectory = fmt.Sprintf("./%v_Unnamed", time_now)
		err = makeDirectory(c.MainDirectory)
	}
	if err == nil {
		loggingConsole("Directory created.", "INFO", nil)
	} else {
		loggingConsole("Directory not created.", "FATAL", err)
		return err
	}

	// Создание лог файла
	filename := fmt.Sprintf("%v/program.log", c.MainDirectory)
	c.LogFile, err = unix.Open(filename, unix.O_CREAT|unix.O_WRONLY|unix.O_APPEND, 0777)
	if err == nil {
		loggingFilePlusConsole(c, "Log file created.", "INFO", nil)
		defer unix.Close(c.LogFile)
	} else {
		loggingConsole("Log file not created.", "FATAL", err)
		return err
	}

	// Создание файла json с собранной информацией
	c.JsonFile, err = jsonCreate(c, "INFO")
	if err != nil {
		return err
	}
	defer unix.Close(c.JsonFile)
	json_info := []Info{}

	// Начало обхода системы на сбор артефактов
	json_info = mainArtifacts(c, json_info, flag)

	// Завершение процесса сбора информации и запись данных в json
	loggingJson(c, &json_info, "INFO", true, c.JsonFile)

	time_result := time.Since(start)
	result := fmt.Sprintf("You can remove the flash drive or the report. The program runs in %v", time_result)
	loggingFilePlusConsole(c, result, "DONE", nil)
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

func getUserProcessName() string {
	user_id := fmt.Sprintf("%v", unix.Geteuid())
	var name string
	pathUsers := "/etc/passwd"
	fd, err := unix.Open(pathUsers, unix.O_RDONLY, 0)
	defer unix.Close(fd)
	if err == nil {
		buf := make([]byte, 1024)
		var finalData []byte
		for {
			n, err := unix.Read(fd, buf)
			if n == 0 || err != nil {
				break
			}

			finalData = append(finalData, buf[:n]...)
		}
		// Собираю данные о пользователе
		temp_data := bytes.Split(finalData, []byte("\n"))
		var data [][]byte
		for _, d := range temp_data {
			if len(d) >= 1 {
				data = append(data, d)
			}
		}
		for _, d := range data {
			line := bytes.Split(d, []byte(":"))
			uid := line[2]
			if string(uid) == user_id {
				name = string(line[0])
			}
		}
	}
	return name
}

// Вход в программу
func main() {
	start := time.Now()
	c := &Collector{}
	if getProcessId() {
		initialization(c, true, start)
	} else {
		initialization(c, false, start)
	}
}
