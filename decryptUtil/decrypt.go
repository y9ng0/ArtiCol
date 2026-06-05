package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Println("Usage: ./decrypt <input.enc> <password>")
		fmt.Println("Example: ./decrypt \"2026-06-01 13-31-28_satellite.tar.gz.enc\" d5d11b1ad53ec139970363655448333d")
		os.Exit(1)
	}

	inputFile := os.Args[1]
	password := os.Args[2]

	// Получаем имя выходного архива путем удаления расширения .enc
	outputFile := inputFile
	if strings.HasSuffix(inputFile, ".enc") {
		outputFile = strings.TrimSuffix(inputFile, ".enc")
	} else {
		outputFile = inputFile + ".tar.gz"
	}

	// Открыть зашифрованный файл
	in, err := os.Open(inputFile)
	if err != nil {
		fmt.Printf("Error: Cannot open input file: %v\n", err)
		os.Exit(1)
	}
	defer in.Close()

	// Прочитать IV (первые 16 байт)
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(in, iv); err != nil {
		fmt.Printf("Error: Cannot read IV: %v\n", err)
		os.Exit(1)
	}

	// Создать ключ из пароля с использованием SHA-256
	key := sha256.Sum256([]byte(password))

	// Создать AES шифр
	block, err := aes.NewCipher(key[:])
	if err != nil {
		fmt.Printf("Error: Cannot create cipher: %v\n", err)
		os.Exit(1)
	}

	// Дешифрующий ридер CTR режима
	stream := cipher.NewCTR(block, iv)
	decryptReader := &cipher.StreamReader{
		S: stream,
		R: in,
	}

	// Создать выходной файл .tar.gz
	out, err := os.Create(outputFile)
	if err != nil {
		fmt.Printf("Error: Cannot create output file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Decrypting archive to %s...\n", outputFile)
	if _, err := io.Copy(out, decryptReader); err != nil {
		out.Close()
		fmt.Printf("Error: Decryption failed: %v\n", err)
		os.Exit(1)
	}
	out.Close()
	fmt.Printf("Success! Decrypted archive saved to: %s\n", outputFile)

	// Начинаем распаковку
	fmt.Println("Extracting files...")
	archiveFile, err := os.Open(outputFile)
	if err != nil {
		fmt.Printf("Error: Cannot open decrypted archive for extraction: %v\n", err)
		os.Exit(1)
	}
	defer archiveFile.Close()

	gzipReader, err := gzip.NewReader(archiveFile)
	if err != nil {
		fmt.Printf("Error: Cannot initialize gzip reader: %v\n", err)
		os.Exit(1)
	}
	defer gzipReader.Close()

	tarReader := tar.NewReader(gzipReader)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Printf("Error: Failed to read tar: %v\n", err)
			os.Exit(1)
		}

		// Безопасный путь во избежание Zip Slip
		target := filepath.Clean(header.Name)
		if filepath.IsAbs(target) || strings.HasPrefix(target, "..") {
			fmt.Printf("Warning: Skipping potentially unsafe file path: %s\n", header.Name)
			continue
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0755); err != nil {
				fmt.Printf("Error: Failed to create directory: %v\n", err)
				os.Exit(1)
			}
		case tar.TypeReg:
			// Убедимся, что родительская директория существует
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				fmt.Printf("Error: Failed to create parent directory: %v\n", err)
				os.Exit(1)
			}

			outFile, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR|os.O_TRUNC, header.FileInfo().Mode())
			if err != nil {
				fmt.Printf("Error: Failed to create file: %v\n", err)
				os.Exit(1)
			}

			if _, err := io.Copy(outFile, tarReader); err != nil {
				outFile.Close()
				fmt.Printf("Error: Failed to write file content: %v\n", err)
				os.Exit(1)
			}
			outFile.Close()
		}
	}

	fmt.Println("Extraction completed successfully!")
}
