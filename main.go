package main

import (
	"bytes"
	"fmt"
	"time"

	"github.com/shirou/gopsutil/v4/host"
	"golang.org/x/sys/unix"
)

// getTimeUtc - получение текущего времени в формате UTC
// Возвращает строку со временем
func getTimeUtc() string {
	return string(time.Now().UTC().Format(time.DateTime))
}

// initialization - инициализация работы (создание рабочего пространства и запуск горутин)
// c - коллектор
// start - время начала сбора
// Возвращает ошибку или nil
func initialization(c *Collector, start time.Time) error {
	loggingConsole("Starting to retrieve artifacts.", "INFO", nil)
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
		loggingConsole("Finished creating directory \"workspace\".", "INFO", nil)
	} else {
		loggingConsole("Failed to create directory \"workspace\".", "FATAL", err)
		return err
	}

	// Создание лог файла
	filename := fmt.Sprintf("%v/program.log", c.MainDirectory)
	c.LogFile, err = unix.Open(filename, unix.O_CREAT|unix.O_WRONLY|unix.O_APPEND, 0700)
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
	json_info = mainArtifacts(c, json_info)

	// Завершение процесса сбора информации и запись данных в json
	loggingJson(c, &json_info, "INFO", true, c.JsonFile)

	// Генерация пароля для архива и очистка
	finalizeArchive(c)

	elapsed := time.Since(start)
	result := fmt.Sprintf("Finished retrieving artifacts. The program ran in %v.", elapsed)
	loggingFilePlusConsole(c, result, "DONE", nil)
	return nil
}

// getUserProcessName - получение имени пользователя процесса
// Возвращает строку с именем пользователя
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

// main - вход в программу
func main() {
	start := time.Now()
	c := &Collector{}
	initialization(c, start)
}
