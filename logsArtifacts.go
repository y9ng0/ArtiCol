package main

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// Рекурсивное копирование директории
func copyDirectory(c *Collector, src, dst string) error {
	loggingFile(c, fmt.Sprintf("Opening directory \"%v\".", src), "INFO", nil)
	// Открытие исходной директории
	fd, err := unix.Open(src, unix.O_RDONLY, 0)
	if err != nil {
		loggingFile(c, fmt.Sprintf("Unable to open directory \"%v\".", src), "ERROR", err)
		return err
	}
	defer unix.Close(fd)

	loggingFile(c, fmt.Sprintf("Creating directory \"%v\".", dst), "INFO", nil)
	// Создание целевой директории
	err = makeDirectory(dst)
	if err != nil && err != unix.EEXIST {
		loggingFile(c, fmt.Sprintf("Unable to create directory \"%v\".", dst), "ERROR", err)
		return err
	}

	loggingFile(c, fmt.Sprintf("Reading directory \"%v\".", src), "INFO", nil)
	// Чтение содержимого директории
	buf := make([]byte, 8192)
	for {
		n, err := unix.ReadDirent(fd, buf)
		if n == 0 || err != nil {
			break
		}

		for bpos := 0; bpos < n; {
			if bpos+19 > n {
				break
			}

			reclen := uint16(buf[bpos+16]) | uint16(buf[bpos+17])<<8
			if reclen == 0 || int(reclen) > n-bpos {
				break
			}

			nameStart := bpos + 19
			nameEnd := nameStart
			for nameEnd < bpos+int(reclen) && nameEnd < n && buf[nameEnd] != 0 {
				nameEnd++
			}
			name := string(buf[nameStart:nameEnd])

			if name == "." || name == ".." || name == "" {
				bpos += int(reclen)
				continue
			}

			src_path := src + "/" + name
			dst_path := dst + "/" + name

			loggingFile(c, fmt.Sprintf("Checking file type for \"%v\".", src_path), "INFO", nil)
			var st unix.Stat_t
			err = unix.Stat(src_path, &st)
			if err != nil {
				loggingFile(c, fmt.Sprintf("Unable to stat \"%v\".", src_path), "ERROR", err)
				bpos += int(reclen)
				continue
			}

			if st.Mode&unix.S_IFDIR != 0 {
				loggingFile(c, fmt.Sprintf("Copying directory \"%v\" to \"%v\".", src_path, dst_path), "INFO", nil)
				err = copyDirectory(c, src_path, dst_path)
				if err != nil {
					loggingFile(c, fmt.Sprintf("Unable to copy directory \"%v\".", src_path), "ERROR", err)
				}
			} else {
				loggingFile(c, fmt.Sprintf("Copying file \"%v\" to \"%v\".", src_path, dst_path), "INFO", nil)
				err = CopyFile(c, src_path, dst_path)
				if err != nil {
					loggingFile(c, fmt.Sprintf("Unable to copy file \"%v\".", src_path), "ERROR", err)
				}
			}

			bpos += int(reclen)
		}
	}

	return nil
}

// Сбор системных логов из /var/log
func getSystemLogs(c *Collector, infoSys *Info) {
	loggingFilePlusConsole(c, "Starting to retrieve system logs...", "INFO", nil)
	loggingFile(c, "Starting to retrieve system logs from \"/var/log\".", "INFO", nil)
	infoSys.Title = "system logs"
	infoSys.Time = getTimeUtc()

	logs_directory := fmt.Sprintf("%v/log/", c.MainDirectory)
	loggingFile(c, fmt.Sprintf("Creating directory \"%v\".", logs_directory), "INFO", nil)
	err := makeDirectory(logs_directory)
	if err != nil {
		loggingFilePlusConsole(c, fmt.Sprintf("Directory \"%v\" not created.", logs_directory), "ERROR", err)
		infoSys.Value = fmt.Sprintf("Error: %v", err)
		return
	}
	loggingFile(c, fmt.Sprintf("Directory \"%v\" created.", logs_directory), "INFO", nil)

	loggingFile(c, "Starting to copy \"/var/log\" directory.", "INFO", nil)
	err = copyDirectory(c, "/var/log", logs_directory)
	if err != nil {
		loggingFilePlusConsole(c, fmt.Sprintf("Failed to copy \"/var/log\": %v", err), "ERROR", err)
		infoSys.Value = fmt.Sprintf("Error: %v", err)
		return
	}
	loggingFile(c, "Successfully copied \"/var/log\" directory.", "INFO", nil)

	loggingFilePlusConsole(c, fmt.Sprintf("System logs added to \"%v\".", logs_directory), "INFO", nil)
	loggingFilePlusConsole(c, "\"System logs\" added to JSON.", "INFO", nil)
	infoSys.Value = "./log/"
}
