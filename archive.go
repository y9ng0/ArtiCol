package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// generateRandomPassword создаёт случайный 32-символьный пароль
func generateRandomPassword() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		loggingFile(nil, "Failed to generate random password, using fallback", "WARNING", err)
		return "fallback_insecure_password"
	}
	return hex.EncodeToString(bytes)
}

// createEncryptedArchive создаёт зашифрованный архив напрямую на флешку
func createEncryptedArchive(c *Collector, sourceDir, password string) error {
	timestamp := time.Now().UTC().Format("2006-01-02_15-04-05")
	archiveName := fmt.Sprintf("artifacts_%s.tar.gz.enc", timestamp)
	parentDir := filepath.Dir(sourceDir)
	encryptedPath := filepath.Join(parentDir, archiveName)

	loggingFile(c, fmt.Sprintf("Creating encrypted archive directly on USB: %s", encryptedPath), "INFO", nil)

	// Создаём зашифрованный архив напрямую (без временных файлов)
	if err := createEncryptedTarGzDirect(encryptedPath, sourceDir, password); err != nil {
		loggingFile(c, fmt.Sprintf("Archive creation failed: %v", err), "ERROR", nil)
		return err
	}

	loggingFile(c, fmt.Sprintf("Encrypted archive created: %s", encryptedPath), "INFO", nil)
	return nil
}

// createEncryptedTarGzDirect создаёт зашифрованный tar.gz архив напрямую
func createEncryptedTarGzDirect(outputPath, sourceDir, password string) error {
	// Создаём выходной файл на флешке
	outFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer outFile.Close()

	// Создаём ключ из пароля с помощью SHA-256
	key := sha256.Sum256([]byte(password))

	// Создаём AES cipher block
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	// Для AES-CTR нужен IV (nonce) размером 16 байт (размер блока AES)
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return fmt.Errorf("failed to generate IV: %w", err)
	}

	// Записываем IV в начало файла (для возможности расшифровки)
	if _, err := outFile.Write(iv); err != nil {
		return fmt.Errorf("failed to write IV: %w", err)
	}

	// Создаём шифрованный writer с использованием CTR режима
	encryptedWriter := &cipher.StreamWriter{
		S: cipher.NewCTR(block, iv),
		W: outFile,
	}

	// Создаём gzip writer, который пишет в зашифрованный поток
	gzipWriter := gzip.NewWriter(encryptedWriter)
	defer gzipWriter.Close()

	// Создаём tar writer
	tarWriter := tar.NewWriter(gzipWriter)
	defer tarWriter.Close()

	// Обходим директорию и добавляем файлы
	err = filepath.Walk(sourceDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Получаем относительный путь
		relPath, err := filepath.Rel(sourceDir, path)
		if err != nil {
			return fmt.Errorf("failed to get relative path: %w", err)
		}

		// Пропускаем корневую директорию
		if relPath == "." {
			return nil
		}

		// Создаём заголовок tar
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return fmt.Errorf("failed to create tar header: %w", err)
		}
		header.Name = relPath

		// Записываем заголовок
		if err := tarWriter.WriteHeader(header); err != nil {
			return fmt.Errorf("failed to write tar header: %w", err)
		}

		// Если это файл, копируем содержимое
		if !info.IsDir() {
			file, err := os.Open(path)
			if err != nil {
				return fmt.Errorf("failed to open file: %w", err)
			}
			defer file.Close()

			if _, err := io.Copy(tarWriter, file); err != nil {
				return fmt.Errorf("failed to copy file content: %w", err)
			}
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to walk directory: %w", err)
	}

	return nil
}

// removeAll удаляет рабочую директорию на флешке (не на системном диске!)
func removeAll(c *Collector, path string) {
	// Проверяем, что директория находится на флешке (не в /tmp или системных путях)
	if isSystemPath(path) {
		loggingFile(c, fmt.Sprintf("WARNING: Skipping removal of system path: %s", path), "WARNING", nil)
		return
	}

	if err := os.RemoveAll(path); err != nil {
		loggingFile(c, fmt.Sprintf("Failed to remove directory %s: %v", path, err), "ERROR", nil)
	} else {
		loggingFile(c, fmt.Sprintf("Removed working directory from USB: %s", path), "INFO", nil)
	}
}

// isSystemPath проверяет, является ли путь системным
func isSystemPath(path string) bool {
	systemPaths := []string{
		"/tmp", "/var/tmp", "/dev", "/proc", "/sys", "/etc", "/bin", "/usr", "/root", "/home",
	}

	for _, sysPath := range systemPaths {
		if strings.HasPrefix(path, sysPath) {
			return true
		}
	}
	return false
}

// finalizeArchive генерирует пароль, создаёт зашифрованный архив и удаляет временные файлы
func finalizeArchive(c *Collector) {
	// Генерация пароля для архива
	password := generateRandomPassword()
	loggingFilePlusConsole(c, fmt.Sprintf("\033[38;5;88mARCHIVE PASSWORD (SAVE IT): %s\033[0m", password), "INFO", nil)
	
	if err := createEncryptedArchive(c, c.MainDirectory, password); err != nil {
		loggingFile(c, fmt.Sprintf("Archive creation failed: %v", err), "ERROR", nil)
	} else {
		removeAll(c, c.MainDirectory)
		loggingFilePlusConsole(c, "Temporary files on USB cleaned up", "INFO", nil)
	}
}
