package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"

	"golang.org/x/sys/unix"
)

// computeFileHash - вычисление хэша файла из пути
// filePath - путь к файлу
// Возвращает хэш файла и ошибку (или nil)
func computeFileHash(filePath string) (string, error) {

	// Открытие файла
	fd, err := unix.Open(filePath, unix.O_RDONLY, 0)
	if err != nil {
		return "", err
	}
	defer unix.Close(fd)

	// Создание хэша
	hash := sha256.New()

	// Буфер для чтения
	buf := make([]byte, 1048565)

	// Чтение файла
	for {
		n, err := unix.Read(fd, buf)
		if n == 0 {
			break
		}
		if err != nil {
			return "", err
		}
		hash.Write(buf[:n])
	}

	// Возвращение хэша
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// CopyDirectory - рекурсивное копирование директории с параллельным копированием файлов
// c - коллекция данных
// src - путь к исходной директории
// dst - путь к целевой директории
// Возвращает ошибку или nil
func copyDirectory(c *Collector, src, dst string) error {

	// Открытие исходной директории
	loggingFile(c, fmt.Sprintf("Opening directory \"%v\".", src), "INFO", nil)
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

	// Собираем задачи для копирования файлов
	var fileTasks []fileCopyTask
	var subDirs []struct{ src, dst string }

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

			if len(name) >= 4 && name[len(name)-4:] == ".ref" {
				loggingFile(c, fmt.Sprintf("Skipping .ref file (no forensic value): \"%v\"", src_path), "INFO", nil)
				bpos += int(reclen)
				continue
			}

			loggingFile(c, fmt.Sprintf("Checking file type for \"%v\".", src_path), "INFO", nil)
			var st unix.Stat_t
			err = unix.Stat(src_path, &st)
			if err != nil {
				loggingFile(c, fmt.Sprintf("Unable to stat \"%v\".", src_path), "ERROR", err)
				bpos += int(reclen)
				continue
			}

			if st.Mode&unix.S_IFDIR != 0 {
				// Сохраняем поддиректории для рекурсивной обработки
				subDirs = append(subDirs, struct{ src, dst string }{src_path, dst_path})
			} else {
				// Сохраняем файлы для параллельного копирования
				fileTasks = append(fileTasks, fileCopyTask{src_path, dst_path, name})
			}
			bpos += int(reclen)
		}
	}

	// Копируем файлы параллельно с помощью горутин
	if len(fileTasks) > 0 {
		loggingFile(c, fmt.Sprintf("Starting concurrent copy of %d files from \"%s\"...", len(fileTasks), src), "INFO", nil)
		var wg sync.WaitGroup

		for _, task := range fileTasks {
			wg.Add(1)
			go func(t fileCopyTask) {
				defer wg.Done()
				copyFileConcurrent(c, t.srcPath, t.dstPath)
			}(task)
		}

		wg.Wait()
		loggingFile(c, fmt.Sprintf("All %d files copied concurrently from \"%s\".", len(fileTasks), src), "INFO", nil)
	}

	// Обрабатываем поддиректории рекурсивно (последовательно)
	for _, dir := range subDirs {
		loggingFile(c, fmt.Sprintf("Copying directory \"%v\" to \"%v\".", dir.src, dir.dst), "INFO", nil)
		err = copyDirectory(c, dir.src, dir.dst)
		if err != nil {
			loggingFile(c, fmt.Sprintf("Unable to copy directory \"%v\".", dir.src), "ERROR", err)
		}
	}

	return nil
}

// copyFileConcurrent - копирование файла в горутине
func copyFileConcurrent(c *Collector, srcPath, dstPath string) {
	loggingFile(c, fmt.Sprintf("[Goroutine] Copying file \"%v\" to \"%v\".", srcPath, dstPath), "INFO", nil)

	sysHash, sysErr := computeFileHash(srcPath)
	if sysErr != nil {
		loggingFile(c, fmt.Sprintf("[Goroutine] Failed to hash original file: %v", srcPath), "WARNING", sysErr)
		sysHash = "error"
	} else {
		loggingFile(c, fmt.Sprintf("[Goroutine] Original file SHA-256: %s", sysHash), "INFO", nil)
	}

	err := CopyFile(c, srcPath, dstPath)
	if err != nil {
		loggingFile(c, fmt.Sprintf("[Goroutine] Unable to copy file \"%v\".", srcPath), "ERROR", err)
		return
	}

	copyHash, copyErr := computeFileHash(dstPath)
	if copyErr != nil {
		loggingFile(c, fmt.Sprintf("[Goroutine] Failed to hash copied file: %v", dstPath), "WARNING", copyErr)
		copyHash = "error"
	}

	relativePath := dstPath[len(c.MainDirectory)+1:]
	if sysErr == nil && copyErr == nil {
		match := (sysHash == copyHash)
		if match {
			loggingFile(c, fmt.Sprintf("[Goroutine] ✓ File verified: %s (hash match)", relativePath), "INFO", nil)
		} else {
			loggingFile(c, fmt.Sprintf("[Goroutine] ✗ FILE VERIFICATION FAILED: %s (hash mismatch - original: %s, copy: %s)", relativePath, sysHash, copyHash), "ERROR", nil)
		}
	} else {
		loggingFile(c, fmt.Sprintf("[Goroutine] ⚠ File copied but verification incomplete: %s", relativePath), "WARNING", nil)
	}
}

// makeDirectory - создание директории
// path - путь к директории
func makeDirectory(path string) error {
	return unix.Mkdir(path, 0777)
}

// Создание JSON файла
// Возвращает дескриптор файла и ошибку
// Путь к файлу формируется как ./<имя_файла>.json
// c - коллекция данных
// filename - имя файла
func jsonCreate(c *Collector, filename string) (int, error) {
	filename = fmt.Sprintf("%v/%v.json", c.MainDirectory, filename)
	loggingFile(c, fmt.Sprintf("Creating a JSON file at the path \"%v\"...", filename), "INFO", nil)
	file, err := unix.Open(filename, unix.O_CREAT|unix.O_WRONLY|unix.O_APPEND, 0777)
	if err == nil {
		loggingFilePlusConsole(c, fmt.Sprintf("The JSON file at the path \"%v\" was created.", filename), "INFO", nil)
		return file, nil
	} else {
		loggingFilePlusConsole(c, fmt.Sprintf("The JSON file at the path \"%v\" was not created.", filename), "WARNING", err)
		return file, err
	}
}

// CopyFile - копирование файла
// c - ссылка на экземпляр Collector
// source - путь к исходному файлу
// destination - путь к целевому файлу
// возвращает ошибку или nil
func CopyFile(c *Collector, source, destination string) error {
	loggingFile(c, fmt.Sprintf("Opening source file \"%v\".", source), "INFO", nil)
	sfd, err := unix.Open(source, unix.O_RDONLY, 0)
	defer unix.Close(sfd)
	if err == nil {
		var st unix.Stat_t
		unix.Stat(source, &st)

		loggingFile(c, fmt.Sprintf("Creating destination file \"%v\".", destination), "INFO", nil)
		dfd, err := unix.Open(destination, unix.O_WRONLY|unix.O_CREAT|unix.O_TRUNC, uint32(st.Mode))
		if err != nil {
			loggingFile(c, fmt.Sprintf("Unable to create destination file \"%v\".", destination), "ERROR", err)
			return err
		}
		defer unix.Close(dfd)

		loggingFile(c, fmt.Sprintf("Copying data from \"%v\" to \"%v\".", source, destination), "INFO", nil)
		_, err = unix.Sendfile(dfd, sfd, nil, int(st.Size))
		if err != nil {
			loggingFile(c, fmt.Sprintf("Unable to copy data from \"%v\" to \"%v\".", source, destination), "ERROR", err)
		} else {
			loggingFile(c, fmt.Sprintf("Successfully copied \"%v\" to \"%v\".", source, destination), "INFO", nil)
		}
		return err
	} else {
		loggingFile(c, fmt.Sprintf("Unable to open source file \"%v\".", source), "ERROR", err)
	}
	return err
}
