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

// copyDirectory - рекурсивное копирование директории с параллельным копированием файлов
// c - коллектор
// src - путь к исходной директории
// dst - путь к целевой директории
// Возвращает ошибку или nil
func copyDirectory(c *Collector, src, dst string) error {

	// Открытие исходной директории
	fd, err := unix.Open(src, unix.O_RDONLY, 0)
	if err != nil {
		loggingFile(c, fmt.Sprintf("Failed to open directory \"%v\".", src), "ERROR", err)
		return err
	}
	defer unix.Close(fd)

	// Создание целевой директории
	err = makeDirectory(dst)
	if err != nil && err != unix.EEXIST {
		loggingFile(c, fmt.Sprintf("Failed to create directory \"%v\".", dst), "ERROR", err)
		return err
	}

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
				bpos += int(reclen)
				continue
			}

			var st unix.Stat_t
			err = unix.Stat(src_path, &st)
			if err != nil {
				loggingFile(c, fmt.Sprintf("Failed to stat \"%v\".", src_path), "ERROR", err)
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
		loggingFile(c, fmt.Sprintf("Starting to copy %d files from \"%s\".", len(fileTasks), src), "INFO", nil)
		var wg sync.WaitGroup

		for _, task := range fileTasks {
			wg.Add(1)
			go func(t fileCopyTask) {
				defer wg.Done()
				copyFileConcurrent(c, t.srcPath, t.dstPath)
			}(task)
		}

		wg.Wait()
		loggingFile(c, fmt.Sprintf("Finished copying %d files from \"%s\".", len(fileTasks), src), "INFO", nil)
	}

	// Обрабатываем поддиректории рекурсивно (последовательно)
	for _, dir := range subDirs {
		err = copyDirectory(c, dir.src, dir.dst)
		if err != nil {
			loggingFile(c, fmt.Sprintf("Failed to copy directory \"%v\".", dir.src), "ERROR", err)
		}
	}

	return nil
}

// copyFileConcurrent - копирование файла в горутине
// c - коллектор
// srcPath - путь к исходному файлу
// dstPath - путь к целевому файлу
func copyFileConcurrent(c *Collector, srcPath, dstPath string) {
	sysHash, sysErr := computeFileHash(srcPath)
	if sysErr != nil {
		sysHash = "error"
	}

	err := CopyFile(c, srcPath, dstPath)
	if err != nil {
		loggingFile(c, fmt.Sprintf("[Goroutine] Failed to copy file \"%v\".", srcPath), "ERROR", err)
		return
	}

	copyHash, copyErr := computeFileHash(dstPath)
	if copyErr != nil {
		copyHash = "error"
	}

	relativePath := dstPath[len(c.MainDirectory)+1:]
	if sysErr == nil && copyErr == nil {
		match := (sysHash == copyHash)
		if !match {
			loggingFile(c, fmt.Sprintf("[Goroutine] Hash mismatch for file \"%s\" (Original: %s, Copy: %s).", relativePath, sysHash, copyHash), "ERROR", nil)
		}
	} else {
		loggingFile(c, fmt.Sprintf("[Goroutine] Verification incomplete for file \"%s\".", relativePath), "WARNING", nil)
	}
}

// makeDirectory - создание директории
// path - путь к директории
// Возвращает ошибку или nil
func makeDirectory(path string) error {
	err := unix.Mkdir(path, 0700)
	if err == unix.EEXIST {
		return nil
	}
	return err
}

// jsonCreate - создание JSON файла
// c - коллектор
// filename - имя файла
// Возвращает дескриптор файла и ошибку (путь к файлу формируется как ./<имя_файла>.json)
func jsonCreate(c *Collector, filename string) (int, error) {
	filename = fmt.Sprintf("%v/%v.json", c.MainDirectory, filename)
	loggingFile(c, fmt.Sprintf("Starting to create JSON file \"%v\".", filename), "INFO", nil)
	file, err := unix.Open(filename, unix.O_CREAT|unix.O_WRONLY|unix.O_APPEND, 0700)
	if err == nil {
		loggingFile(c, fmt.Sprintf("Finished creating JSON file \"%v\".", filename), "INFO", nil)
		return file, nil
	} else {
		loggingFilePlusConsole(c, fmt.Sprintf("Failed to create JSON file \"%v\".", filename), "ERROR", err)
		return file, err
	}
}

// CopyFile - копирование файла
// c - коллектор
// source - путь к исходному файлу
// destination - путь к целевому файлу
// Возвращает ошибку или nil
func CopyFile(c *Collector, source, destination string) error {
	sysHash, sysErr := computeFileHash(source)
	if sysErr != nil {
		if sysErr == unix.ENOENT {
			return sysErr
		}
	}

	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		err := copyOnce(source, destination)
		if err != nil {
			lastErr = err
			loggingFile(c, fmt.Sprintf("Failed to copy file from \"%s\" to \"%s\" (attempt %d/3).", source, destination, attempt), "ERROR", err)
			continue
		}

		if sysErr == nil {
			copyHash, copyErr := computeFileHash(destination)
			if copyErr != nil {
				lastErr = copyErr
				unix.Unlink(destination)
				loggingFile(c, fmt.Sprintf("Failed to hash copied file \"%s\" (attempt %d/3).", destination, attempt), "WARNING", copyErr)
				continue
			}

			if sysHash == copyHash {
				return nil
			} else {
				lastErr = fmt.Errorf("hash mismatch")
				unix.Unlink(destination)
				loggingFile(c, fmt.Sprintf("Hash mismatch for file \"%s\" (Original: %s, Copy: %s) on attempt %d/3. Deleting copy.", destination, sysHash, copyHash, attempt), "ERROR", nil)
				continue
			}
		} else {
			return nil
		}
	}

	return lastErr
}

func copyOnce(source, destination string) error {
	sfd, err := unix.Open(source, unix.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer unix.Close(sfd)

	var st unix.Stat_t
	err = unix.Stat(source, &st)
	if err != nil {
		return err
	}

	dfd, err := unix.Open(destination, unix.O_WRONLY|unix.O_CREAT|unix.O_TRUNC, uint32(st.Mode))
	if err != nil {
		return err
	}
	defer unix.Close(dfd)

	buf := make([]byte, 32768)
	for {
		n, err := unix.Read(sfd, buf)
		if n == 0 {
			break
		}
		if err != nil {
			return err
		}
		_, err = unix.Write(dfd, buf[:n])
		if err != nil {
			return err
		}
	}
	return nil
}
