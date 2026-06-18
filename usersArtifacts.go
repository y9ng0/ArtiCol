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
	loggingFilePlusConsole(c, "Starting to retrieve \"passwd\".", "INFO", nil)

	// Заполняем информацию о файле и дате извлечения
	infoSys.Title = "/etc/passwd"
	infoSys.Time = getTimeUtc()

	// Создаем директорию для хранения файла
	path_directory := fmt.Sprintf("%v/users/", c.MainDirectory)
	loggingFile(c, fmt.Sprintf("Starting to create directory \"%v\".", path_directory), "INFO", nil)
	err := makeDirectory(path_directory)
	if err != nil {
		loggingFilePlusConsole(c, fmt.Sprintf("Failed to create directory \"%v\".", path_directory), "ERROR", err)
		infoSys.Value = fmt.Sprintf("Error: %v", err)
		return
	}
	loggingFile(c, fmt.Sprintf("Finished creating directory \"%v\".", path_directory), "INFO", nil)

	// Начало процесса копирования файла passwd
	sourcePath := "/etc/passwd"
	destination := path_directory + "passwd"
	loggingFile(c, fmt.Sprintf("Starting to copy file \"%v\" to \"%v\".", sourcePath, destination), "INFO", nil)

	// Хэшируем оригинальный файл passwd
	sysHash, sysErr := computeFileHash(sourcePath)
	if sysErr != nil {
		loggingFile(c, fmt.Sprintf("Failed to hash original file \"%s\".", sourcePath), "WARNING", sysErr)
	} else {
		loggingFile(c, fmt.Sprintf("Finished hashing original file \"%s\" (SHA-256: %s).", sourcePath, sysHash), "INFO", nil)
	}

	// Копируем файл passwd
	err = CopyFile(c, sourcePath, destination)
	if err == nil {
		copyHash, copyErr := computeFileHash(destination)
		if copyErr != nil {
			loggingFile(c, fmt.Sprintf("Failed to hash copied file \"%s\".", destination), "WARNING", copyErr)
		} else if sysErr == nil {
			if sysHash == copyHash {
				loggingFile(c, fmt.Sprintf("Hash match found for file \"%s\".", destination), "INFO", nil)
			} else {
				loggingFile(c, fmt.Sprintf("Hash mismatch for file \"%s\" (Original: %s, Copy: %s).", destination, sysHash, copyHash), "ERROR", nil)
			}
		}
		loggingFilePlusConsole(c, fmt.Sprintf("Finished copying file \"passwd\" to \"%s\".", destination), "INFO", err)
		infoSys.Value = destination
	} else {
		loggingFilePlusConsole(c, "Failed to copy file \"passwd\".", "ERROR", err)
		infoSys.Value = fmt.Sprintf("Error: %v", err)
	}
	loggingFilePlusConsole(c, fmt.Sprintf("Finished retrieving \"passwd\" to \"%v\".", infoSys.Value), "INFO", nil)
}

// getShadow - извлекает файл /etc/shadow
// c - коллектор
// infoSys - информация об объекте
func getShadow(c *Collector, infoSys *Info) {
	loggingFilePlusConsole(c, "Starting to retrieve \"shadow\".", "INFO", nil)

	// Заполняем информацию о файле и дате извлечения
	infoSys.Title = "/etc/shadow"
	infoSys.Time = getTimeUtc()

	// Создаем директорию для хранения файлов
	path_directory := fmt.Sprintf("%v/users/", c.MainDirectory)
	makeDirectory(path_directory)

	// Копируем файл shadow
	sourcePath := "/etc/shadow"
	destination := path_directory + "shadow"
	loggingFile(c, fmt.Sprintf("Starting to copy file \"%s\" to \"%s\".", sourcePath, destination), "INFO", nil)

	// Получаем хеш оригинального файла
	sysHash, sysErr := computeFileHash(sourcePath)
	if sysErr != nil {
		loggingFile(c, fmt.Sprintf("Failed to hash original file \"%s\".", sourcePath), "WARNING", sysErr)
	} else {
		loggingFile(c, fmt.Sprintf("Finished hashing original file \"%s\" (SHA-256: %s).", sourcePath, sysHash), "INFO", nil)
	}

	// Копируем файл shadow
	err := CopyFile(c, sourcePath, destination)
	if err == nil {
		copyHash, copyErr := computeFileHash(destination)
		if copyErr != nil {
			loggingFile(c, fmt.Sprintf("Failed to hash copied file \"%s\".", destination), "WARNING", copyErr)
		} else if sysErr == nil {
			if sysHash == copyHash {
				loggingFile(c, fmt.Sprintf("Hash match found for file \"%s\".", destination), "INFO", nil)
			} else {
				loggingFile(c, fmt.Sprintf("Hash mismatch for file \"%s\" (Original: %s, Copy: %s).", destination, sysHash, copyHash), "ERROR", nil)
			}
		}

		loggingFilePlusConsole(c, fmt.Sprintf("Finished copying file \"shadow\" to \"%s\".", destination), "INFO", err)
		infoSys.Value = destination
	} else {
		loggingFilePlusConsole(c, "Failed to copy file \"shadow\".", "ERROR", err)
		infoSys.Value = fmt.Sprintf("Error: %v", err)
	}
	loggingFilePlusConsole(c, fmt.Sprintf("Finished retrieving \"shadow\" to \"%v\".", infoSys.Value), "INFO", nil)
}

// getHomeDir - извлекает файлы из домашних директорий пользователей
// c - коллектор
// infoSys - информация об объекте
func getHomeDir(c *Collector, infoSys *Info) {
	loggingFilePlusConsole(c, "Starting to retrieve \"history files\".", "INFO", nil)

	// Заполняем информацию об объекте
	infoSys.Title = "bash_history"
	infoSys.Time = getTimeUtc()

	// Открываем файл /etc/passwd и читаем его, разбивая на строки
	pathUsers := "/etc/passwd"
	fd, err := unix.Open(pathUsers, unix.O_RDONLY, 0)
	defer unix.Close(fd)
	if err == nil {
		loggingFile(c, fmt.Sprintf("Starting to open file \"%v\".", pathUsers), "INFO", nil)
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
		// Remove this duplicate log
		temp_data := bytes.Split(finalData, []byte("\n"))
		var data [][]byte
		for _, d := range temp_data {
			if len(d) >= 1 {
				data = append(data, d)
			}
		}
		path_directory := fmt.Sprintf("%v/users/", c.MainDirectory)
		err = makeDirectory(path_directory)
		if err != nil {
			loggingFilePlusConsole(c, fmt.Sprintf("Failed to create directory \"%v\".", path_directory), "ERROR", err)
			infoSys.Value = fmt.Sprintf("Error: %v", err)
			return
		}
		var wg sync.WaitGroup

		loggingFile(c, "Starting to retrieve \"history files\" for all users.", "INFO", nil)
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

		wg.Wait()
		infoSys.Value = path_directory
		loggingFilePlusConsole(c, fmt.Sprintf("Finished retrieving \"history files\" to \"%v\".", infoSys.Value), "INFO", nil)
	} else {
		loggingFilePlusConsole(c, fmt.Sprintf("Failed to open file \"%v\".", pathUsers), "ERROR", err)
		infoSys.Value = fmt.Sprintf("Error: %v", err)
	}
}

// getHistory - извлекает файлы из домашних директорий пользователей
// c - коллектор
// name - имя пользователя
// home_dir - домашняя директория пользователя
func getHistory(c *Collector, name, home_dir []byte) {
	user_dir := fmt.Sprintf("%v/users/%s", c.MainDirectory, name)
	loggingFile(c, fmt.Sprintf("Starting to create directory \"%v\".", user_dir), "INFO", nil)
	err := makeDirectory(user_dir)
	if err != nil {
		text := fmt.Sprintf("Failed to create directory \"%v\".", user_dir)
		loggingFile(c, text, "ERROR", err)
		return
	}
	loggingFile(c, fmt.Sprintf("Finished creating directory \"%v\".", user_dir), "INFO", nil)

	bashSource := string(home_dir) + "/.bash_history"
	bashDest := fmt.Sprintf("%v/users/%s/bash_history", c.MainDirectory, name)
	bashErr := copyHistoryFile(c, bashSource, bashDest, "bash_history", name)

	zshSource := string(home_dir) + "/.zsh_history"
	zshDest := fmt.Sprintf("%v/users/%s/zsh_history", c.MainDirectory, name)
	zshErr := copyHistoryFile(c, zshSource, zshDest, "zsh_history", name)

	if bashErr != nil && zshErr != nil {
		unix.Rmdir(user_dir)
	}
}

func copyHistoryFile(c *Collector, sourcePath, destination, fileType string, name []byte) error {
	loggingFile(c, fmt.Sprintf("Starting to copy file \"%v\" to \"%v\".", sourcePath, destination), "INFO", nil)

	sysHash, sysErr := computeFileHash(sourcePath)
	if sysErr != nil {
		loggingFile(c, fmt.Sprintf("Failed to hash original file \"%s\".", sourcePath), "WARNING", sysErr)
	} else {
		loggingFile(c, fmt.Sprintf("Finished hashing original file \"%s\" (SHA-256: %s).", sourcePath, sysHash), "INFO", nil)
	}

	err := CopyFile(c, sourcePath, destination)
	if err == nil {
		copyHash, copyErr := computeFileHash(destination)
		if copyErr != nil {
			loggingFile(c, fmt.Sprintf("Failed to hash copied file \"%s\".", destination), "WARNING", copyErr)
		} else if sysErr == nil {
			if sysHash == copyHash {
				loggingFile(c, fmt.Sprintf("Hash match found for file \"%s\".", destination), "INFO", nil)
			} else {
				loggingFile(c, fmt.Sprintf("Hash mismatch for file \"%s\" (Original: %s, Copy: %s).", destination, sysHash, copyHash), "ERROR", nil)
			}
		}

		text := fmt.Sprintf("Finished copying file \"%s\" for user \"%s\".", fileType, name)
		loggingFile(c, text, "INFO", err)
	} else {
		text := fmt.Sprintf("Failed to copy file \"%s\" for user \"%s\".", fileType, name)
		loggingFile(c, text, "ERROR", err)
	}
	return err
}

// getSessions - извлекает информацию об активных сессиях пользователей
// c - коллектор
// infoSys - информация об объекте
func getSessions(c *Collector, infoSys *Info) {
	loggingFilePlusConsole(c, "Starting to retrieve \"systemd sessions\".", "INFO", nil)

	infoSys.Title = "systemd sessions"
	infoSys.Time = getTimeUtc()

	parent_directory := fmt.Sprintf("%v/users/", c.MainDirectory)
	err := makeDirectory(parent_directory)
	if err != nil && err != unix.EEXIST {
		loggingFilePlusConsole(c, fmt.Sprintf("Failed to create directory \"%v\".", parent_directory), "ERROR", err)
		infoSys.Value = fmt.Sprintf("Error: %v", err)
		return
	}

	sessions_directory := fmt.Sprintf("%v/users/sessions/", c.MainDirectory)
	loggingFile(c, fmt.Sprintf("Starting to create directory \"%v\".", sessions_directory), "INFO", nil)
	err = makeDirectory(sessions_directory)
	if err != nil {
		loggingFilePlusConsole(c, fmt.Sprintf("Failed to create directory \"%v\".", sessions_directory), "ERROR", err)
		infoSys.Value = fmt.Sprintf("Error: %v", err)
		return
	}
	loggingFile(c, fmt.Sprintf("Finished creating directory \"%v\".", sessions_directory), "INFO", nil)

	loggingFile(c, "Starting to copy directory \"/var/run/systemd/sessions\".", "INFO", nil)
	err = copyDirectory(c, "/var/run/systemd/sessions", sessions_directory)
	if err != nil {
		loggingFilePlusConsole(c, "Failed to copy directory \"/var/run/systemd/sessions\".", "ERROR", err)
		infoSys.Value = fmt.Sprintf("Error: %v", err)
		return
	}
	loggingFile(c, "Finished copying directory \"/var/run/systemd/sessions\".", "INFO", nil)

	infoSys.Value = fmt.Sprintf("%v/users/sessions/", c.MainDirectory)
	loggingFilePlusConsole(c, fmt.Sprintf("Finished retrieving \"systemd sessions\" to \"%v\".", infoSys.Value), "INFO", nil)
}

// getGroup - извлекает файл /etc/group
func getGroup(c *Collector, infoSys *Info) {
	loggingFilePlusConsole(c, "Starting to retrieve \"group\".", "INFO", nil)

	infoSys.Title = "/etc/group"
	infoSys.Time = getTimeUtc()

	path_directory := fmt.Sprintf("%v/users/", c.MainDirectory)
	err := makeDirectory(path_directory)
	if err != nil {
		loggingFilePlusConsole(c, fmt.Sprintf("Failed to create directory \"%v\".", path_directory), "ERROR", err)
		infoSys.Value = fmt.Sprintf("Error: %v", err)
		return
	}

	sourcePath := "/etc/group"
	destination := path_directory + "group"
	loggingFile(c, fmt.Sprintf("Starting to copy file \"%v\" to \"%v\".", sourcePath, destination), "INFO", nil)

	sysHash, sysErr := computeFileHash(sourcePath)
	if sysErr != nil {
		loggingFile(c, fmt.Sprintf("Failed to hash original file \"%s\".", sourcePath), "WARNING", sysErr)
	} else {
		loggingFile(c, fmt.Sprintf("Finished hashing original file \"%s\" (SHA-256: %s).", sourcePath, sysHash), "INFO", nil)
	}

	err = CopyFile(c, sourcePath, destination)
	if err == nil {
		copyHash, copyErr := computeFileHash(destination)
		if copyErr != nil {
			loggingFile(c, fmt.Sprintf("Failed to hash copied file \"%s\".", destination), "WARNING", copyErr)
		} else if sysErr == nil {
			if sysHash == copyHash {
				loggingFile(c, fmt.Sprintf("Hash match found for file \"%s\".", destination), "INFO", nil)
			} else {
				loggingFile(c, fmt.Sprintf("Hash mismatch for file \"%s\" (Original: %s, Copy: %s).", destination, sysHash, copyHash), "ERROR", nil)
			}
		}
		loggingFilePlusConsole(c, fmt.Sprintf("Finished copying file \"group\" to \"%s\".", destination), "INFO", err)
		infoSys.Value = destination
	} else {
		loggingFilePlusConsole(c, "Failed to copy file \"group\".", "ERROR", err)
		infoSys.Value = fmt.Sprintf("Error: %v", err)
	}
	loggingFilePlusConsole(c, fmt.Sprintf("Finished retrieving \"group\" to \"%v\".", infoSys.Value), "INFO", nil)
}

// getSudoers - извлекает файл /etc/sudoers
func getSudoers(c *Collector, infoSys *Info) {
	loggingFilePlusConsole(c, "Starting to retrieve \"sudoers\".", "INFO", nil)

	infoSys.Title = "/etc/sudoers"
	infoSys.Time = getTimeUtc()

	path_directory := fmt.Sprintf("%v/users/", c.MainDirectory)
	err := makeDirectory(path_directory)
	if err != nil {
		loggingFilePlusConsole(c, fmt.Sprintf("Failed to create directory \"%v\".", path_directory), "ERROR", err)
		infoSys.Value = fmt.Sprintf("Error: %v", err)
		return
	}

	sourcePath := "/etc/sudoers"
	destination := path_directory + "sudoers"
	loggingFile(c, fmt.Sprintf("Starting to copy file \"%s\" to \"%s\".", sourcePath, destination), "INFO", nil)

	sysHash, sysErr := computeFileHash(sourcePath)
	if sysErr != nil {
		loggingFile(c, fmt.Sprintf("Failed to hash original file \"%s\".", sourcePath), "WARNING", sysErr)
	} else {
		loggingFile(c, fmt.Sprintf("Finished hashing original file \"%s\" (SHA-256: %s).", sourcePath, sysHash), "INFO", nil)
	}

	err = CopyFile(c, sourcePath, destination)
	if err == nil {
		copyHash, copyErr := computeFileHash(destination)
		if copyErr != nil {
			loggingFile(c, fmt.Sprintf("Failed to hash copied file \"%s\".", destination), "WARNING", copyErr)
		} else if sysErr == nil {
			if sysHash == copyHash {
				loggingFile(c, fmt.Sprintf("Hash match found for file \"%s\".", destination), "INFO", nil)
			} else {
				loggingFile(c, fmt.Sprintf("Hash mismatch for file \"%s\" (Original: %s, Copy: %s).", destination, sysHash, copyHash), "ERROR", nil)
			}
		}
		loggingFilePlusConsole(c, fmt.Sprintf("Finished copying file \"sudoers\" to \"%s\".", destination), "INFO", err)
		infoSys.Value = destination
	} else {
		loggingFilePlusConsole(c, "Failed to copy file \"sudoers\".", "ERROR", err)
		infoSys.Value = fmt.Sprintf("Error: %v", err)
	}
	loggingFilePlusConsole(c, fmt.Sprintf("Finished retrieving \"sudoers\" to \"%v\".", infoSys.Value), "INFO", nil)
}

// getSudoersD - рекурсивно копирует содержимое /etc/sudoers.d/
func getSudoersD(c *Collector, infoSys *Info) {
	loggingFilePlusConsole(c, "Starting to retrieve \"sudoers.d\".", "INFO", nil)

	infoSys.Title = "/etc/sudoers.d"
	infoSys.Time = getTimeUtc()

	parent_directory := fmt.Sprintf("%v/users/", c.MainDirectory)
	err := makeDirectory(parent_directory)
	if err != nil && err != unix.EEXIST {
		loggingFilePlusConsole(c, fmt.Sprintf("Failed to create directory \"%v\".", parent_directory), "ERROR", err)
		infoSys.Value = fmt.Sprintf("Error: %v", err)
		return
	}

	dest_directory := fmt.Sprintf("%v/users/sudoers.d/", c.MainDirectory)
	err = makeDirectory(dest_directory)
	if err != nil && err != unix.EEXIST {
		loggingFilePlusConsole(c, fmt.Sprintf("Failed to create directory \"%v\".", dest_directory), "ERROR", err)
		infoSys.Value = fmt.Sprintf("Error: %v", err)
		return
	}

	loggingFile(c, "Starting to copy directory \"/etc/sudoers.d\".", "INFO", nil)
	err = copyDirectory(c, "/etc/sudoers.d", dest_directory)
	if err != nil {
		loggingFilePlusConsole(c, "Failed to copy directory \"/etc/sudoers.d\".", "ERROR", err)
		infoSys.Value = fmt.Sprintf("Error: %v", err)
		return
	}
	loggingFile(c, "Finished copying directory \"/etc/sudoers.d\".", "INFO", nil)

	infoSys.Value = dest_directory
	loggingFilePlusConsole(c, fmt.Sprintf("Finished retrieving \"sudoers.d\" to \"%v\".", infoSys.Value), "INFO", nil)
}
