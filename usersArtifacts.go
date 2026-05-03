package main

import (
	"bytes"
	"fmt"
	"sync"

	"golang.org/x/sys/unix"
)

// getPasswd - извлекает файл /etc/passwd
// c - коллектор
// infoSys - информация об объекте
func getPasswd(c *Collector, infoSys *Info) {
	loggingFilePlusConsole(c, "Starting to read the \"passwd\" file...", "INFO", nil)

	// Заполняем информацию о файле и дате извлечения
	infoSys.Title = "/etc/passwd"
	infoSys.Time = getTimeUtc()

	// Создаем директорию для хранения файла
	path_directory := fmt.Sprintf("%v/users/", c.MainDirectory)
	loggingFile(c, fmt.Sprintf("Creating directory at path \"%v\".", path_directory), "INFO", nil)
	err := makeDirectory(path_directory)
	if err != nil {
		loggingFilePlusConsole(c, fmt.Sprintf("Error creating directory at path \"%v\".", path_directory), "WARNING", err)
		infoSys.Value = fmt.Sprintf("Error: %v", err)
		return
	}
	loggingFile(c, fmt.Sprintf("Directory at path \"%v\" created.", path_directory), "INFO", nil)

	// Начало процесса копирования файла passwd
	sourcePath := "/etc/passwd"
	destination := path_directory + "passwd"
	loggingFile(c, fmt.Sprintf("Starting to copy the file at path \"%v\" to \"%v\"", sourcePath, destination), "INFO", nil)

	// Хэшируем оригинальный файл passwd
	sysHash, sysErr := computeFileHash(sourcePath)
	if sysErr != nil {
		loggingFile(c, "Failed to hash original passwd.", "WARNING", sysErr)
	} else {
		loggingFile(c, fmt.Sprintf("Original passwd SHA-256 \"%s\".", sysHash), "INFO", nil)
	}

	// Копируем файл passwd
	err = CopyFile(c, sourcePath, destination)
	if err == nil {
		copyHash, copyErr := computeFileHash(destination)
		if copyErr != nil {
			loggingFile(c, "Failed to hash copied passwd.", "WARNING", copyErr)
		} else if sysErr == nil {
			loggingFile(c, fmt.Sprintf("Original passwd SHA-256 \"%s\".", sysHash), "INFO", nil)
			if sysHash == copyHash {
				loggingFile(c, "A match for the passwd file hash was found.", "INFO", nil)
			} else {
				loggingFile(c, fmt.Sprintf("Error matching passwd file hashes. Original: \"%s\", Copy: \"%s\".", sysHash, copyHash), "ERROR", nil)
			}
		}
		loggingFilePlusConsole(c, fmt.Sprintf("Passwd extracted to \"%s\"", destination), "INFO", err)
		infoSys.Value = destination
	} else {
		loggingFilePlusConsole(c, fmt.Sprintf("Passwd not extracted from %s", sourcePath), "ERROR", err)
		infoSys.Value = fmt.Sprintf("Error: %v", err)
	}
	loggingFilePlusConsole(c, "Finished reading the \"passwd\" file.", "INFO", nil)
}

// getShadow - извлекает файл /etc/shadow
// c - коллектор
// infoSys - информация об объекте
// flag - флаг запуска (true - root, false - user)
func getShadow(c *Collector, infoSys *Info, flag bool) {
	loggingFilePlusConsole(c, "Starting to read the \"shadow\" file...", "INFO", nil)

	// Заполняем информацию о файле и дате извлечения
	infoSys.Title = "/etc/shadow"
	infoSys.Time = getTimeUtc()

	// Создаем директорию для хранения файлов
	path_directory := fmt.Sprintf("%v/users/", c.MainDirectory)
	makeDirectory(path_directory)

	// Копируем файл shadow
	if flag {
		sourcePath := "/etc/shadow"
		destination := path_directory + "shadow"
		loggingFile(c, fmt.Sprintf("Copying \"%s\" to \"%s\".", sourcePath, destination), "INFO", nil)

		// Получаем хеш оригинального файла
		sysHash, sysErr := computeFileHash(sourcePath)
		if sysErr != nil {
			loggingFile(c, "Failed to hash original shadow.", "WARNING", sysErr)
		} else {
			loggingFile(c, fmt.Sprintf("Original shadow SHA-256 \"%s\".", sysHash), "INFO", nil)
		}

		// Копируем файл shadow
		err := CopyFile(c, sourcePath, destination)
		if err == nil {
			copyHash, copyErr := computeFileHash(destination)
			if copyErr != nil {
				loggingFile(c, "Failed to hash copied shadow", "WARNING", copyErr)
			} else if sysErr == nil {
				loggingFile(c, fmt.Sprintf("Copied shadow SHA-256 \"%s\".", copyHash), "INFO", nil)
				if sysHash == copyHash {
					loggingFile(c, "Shadow file verified (hash match)", "INFO", nil)
				} else {
					loggingFile(c, fmt.Sprintf("Error matching shadow file hashes. Original: %s, Copy: %s", sysHash, copyHash), "ERROR", nil)
				}
			}

			loggingFilePlusConsole(c, fmt.Sprintf("Shadow extracted to \"%s\"", destination), "INFO", err)
			infoSys.Value = destination
		} else {
			loggingFilePlusConsole(c, fmt.Sprintf("Shadow not extracted from %s", sourcePath), "ERROR", err)
			infoSys.Value = fmt.Sprintf("Error: %v", err)
		}
	} else {
		loggingFilePlusConsole(c, "Shadow not extracted. Error: permission denied.", "ERROR", nil)
	}
}

// getHomeDir - извлекает файлы из домашних директорий пользователей
// c - коллектор
// infoSys - информация об объекте
// flag - флаг запуска (true - root, false - user)
func getHomeDir(c *Collector, infoSys *Info, flag bool) {
	loggingFilePlusConsole(c, "Starting to read bash history...", "INFO", nil)

	// Заполняем информацию об объекте
	infoSys.Title = "bash_history"
	infoSys.Time = getTimeUtc()

	// Открываем файл /etc/passwd и читаем его, разбивая на строки
	pathUsers := "/etc/passwd"
	fd, err := unix.Open(pathUsers, unix.O_RDONLY, 0)
	defer unix.Close(fd)
	if err == nil {
		loggingFile(c, fmt.Sprintf("Reading \"%v\".", pathUsers), "INFO", nil)
		buf := make([]byte, 1024)
		var finalData []byte
		for {
			n, err := unix.Read(fd, buf)
			if n == 0 || err != nil {
				break
			}
			finalData = append(finalData, buf[:n]...)
		}

		// Собираю данные о пользователе (имя пользователя, домашняя директория и шелл)
		loggingFile(c, "Parsing \"/etc/passwd\" data.", "INFO", nil)
		temp_data := bytes.Split(finalData, []byte("\n"))
		var data [][]byte
		for _, d := range temp_data {
			if len(d) >= 1 {
				data = append(data, d)
			}
		}
		path_directory := fmt.Sprintf("%v/users/", c.MainDirectory)
		var wg sync.WaitGroup

		// Если флаг true, то извлекаем bash history для всех пользователей
		if flag {
			loggingFile(c, "Retrieving bash history for all users.", "INFO", nil)
			for _, d := range data {
				line := bytes.Split(d, []byte(":"))
				name := line[0]
				home_dir := line[5]
				shell := line[6]
				if string(shell) == "/usr/sbin/nologin" || string(shell) == "/bin/false" {
					loggingFile(c, fmt.Sprintf("Skipping user \"%s\" (nologin shell).", name), "INFO", nil)
					continue
				} else {
					wg.Add(1)
					go func(name, home_dir []byte) {
						defer wg.Done()
						loggingFile(c, fmt.Sprintf("[Goroutine] Processing user \"%s\" with home directory \"%v\".", name, string(home_dir)), "INFO", nil)
						getHistory(c, name, home_dir)
					}(name, home_dir)
				}
			}
		} else {
			loggingFile(c, fmt.Sprintf("Retrieving bash history for user \"%s\".", c.UserName), "INFO", nil)
			for _, d := range data {
				line := bytes.Split(d, []byte(":"))
				name := line[0]
				home_dir := line[5]
				if string(name) == c.UserName {
					wg.Add(1)
					go func(name, home_dir []byte) {
						defer wg.Done()
						loggingFile(c, fmt.Sprintf("[Goroutine] Processing user \"%s\" with home directory \"%v\".", name, string(home_dir)), "INFO", nil)
						getHistory(c, name, home_dir)
					}(name, home_dir)
				}
			}
		}

		// Ожидаем завершения всех горутин
		wg.Wait()
		loggingFile(c, "All goroutines for bash history collection completed.", "INFO", nil)
		infoSys.Value = path_directory
		loggingFilePlusConsole(c, fmt.Sprintf("Bash history added to \"%v\"", path_directory), "INFO", nil)

	} else {
		loggingFilePlusConsole(c, fmt.Sprintf("File to path \"%v\" could not be opened.", pathUsers), "ERROR", err)
		infoSys.Value = fmt.Sprintf("Error: %v", err)
	}
}

// getHistory - извлекает файлы из домашних директорий пользователей
// c - коллектор
// name - имя пользователя
// home_dir - домашняя директория пользователя
func getHistory(c *Collector, name, home_dir []byte) {
	user_dir := fmt.Sprintf("%v/users/%s", c.MainDirectory, name)
	loggingFile(c, fmt.Sprintf("Creating directory \"%v\" for user \"%s\".", user_dir, name), "INFO", nil)
	err := makeDirectory(user_dir)
	if err != nil {
		text := fmt.Sprintf("Directory \"%v\" not created for user \"%s\".", user_dir, name)
		loggingFile(c, text, "ERROR", err)
		return
	}
	loggingFile(c, fmt.Sprintf("Directory \"%v\" created for user \"%s\".", user_dir, name), "INFO", nil)

	sourcePath := string(home_dir) + "/.bash_history"
	destination := fmt.Sprintf("%v/users/%s/bash_history", c.MainDirectory, name)
	loggingFile(c, fmt.Sprintf("Copying \"%v\" to \"%v\".", sourcePath, destination), "INFO", nil)

	sysHash, sysErr := computeFileHash(sourcePath)
	if sysErr != nil {
		loggingFile(c, fmt.Sprintf("Failed to hash original bash_history for user %s: %v", name, sysErr), "WARNING", sysErr)
	} else {
		loggingFile(c, fmt.Sprintf("Original bash_history (user %s) SHA-256: %s", name, sysHash), "INFO", nil)
	}

	err = CopyFile(c, sourcePath, destination)

	if err == nil {
		copyHash, copyErr := computeFileHash(destination)
		if copyErr != nil {
			loggingFile(c, fmt.Sprintf("Failed to hash copied bash_history for user %s: %v", name, copyErr), "WARNING", copyErr)
		} else if sysErr == nil {
			if sysHash == copyHash {
				loggingFile(c, fmt.Sprintf("✓ Bash_history verified for user %s (hash match)", name), "INFO", nil)
			} else {
				loggingFile(c, fmt.Sprintf("✗ BASH_HISTORY VERIFICATION FAILED for user %s! Original: %s, Copy: %s", name, sysHash, copyHash), "ERROR", nil)
			}
		}

		text := fmt.Sprintf("User \"%s\" bash_history was retrieved.", name)
		loggingFile(c, text, "INFO", err)
	} else {
		unix.Rmdir(user_dir)
		text := fmt.Sprintf("User \"%s\" bash_history was not retrieved.", name)
		loggingFile(c, text, "ERROR", err)
	}
}

// getSessions - извлекает информацию об активных сессиях пользователей
// c - коллектор
// infoSys - информация об объекте
func getSessions(c *Collector, infoSys *Info) {
	loggingFilePlusConsole(c, "Starting to retrieve systemd sessions...", "INFO", nil)
	loggingFile(c, "Starting to retrieve \"systemd sessions\".", "INFO", nil)
	infoSys.Title = "systemd sessions"
	infoSys.Time = getTimeUtc()

	sessions_directory := fmt.Sprintf("%v/users/sessions/", c.MainDirectory)
	loggingFile(c, fmt.Sprintf("Creating directory \"%v\".", sessions_directory), "INFO", nil)
	err := makeDirectory(sessions_directory)
	if err != nil {
		loggingFilePlusConsole(c, fmt.Sprintf("Directory \"%v\" not created.", sessions_directory), "ERROR", err)
		infoSys.Value = fmt.Sprintf("Error: %v", err)
		return
	}
	loggingFile(c, fmt.Sprintf("Directory \"%v\" created.", sessions_directory), "INFO", nil)

	loggingFile(c, "Starting to copy \"/var/run/systemd/sessions\" directory.", "INFO", nil)
	err = copyDirectory(c, "/var/run/systemd/sessions", sessions_directory)
	if err != nil {
		loggingFilePlusConsole(c, fmt.Sprintf("Failed to copy \"/var/run/systemd/sessions\": %v", err), "ERROR", err)
		infoSys.Value = fmt.Sprintf("Error: %v", err)
		return
	}
	loggingFile(c, "Successfully copied \"/var/run/systemd/sessions\" directory.", "INFO", nil)

	loggingFilePlusConsole(c, "\"Systemd sessions\" added to JSON.", "INFO", nil)
	infoSys.Value = fmt.Sprintf("%v/users/sessions/", c.MainDirectory)
}
