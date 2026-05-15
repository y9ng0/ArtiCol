package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Println("Usage: ./decrypt <input.enc> <password>")
		fmt.Println("Example: ./decrypt artifacts_2026-05-15_13-33-54.tar.gz.enc d5d11b1ad53ec139970363655448333d")
		os.Exit(1)
	}

	inputFile := os.Args[1]
	password := os.Args[2]
	outputFile := "decrypted_archive.tar.gz"

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

	// Создать выходной файл
	out, err := os.Create(outputFile)
	if err != nil {
		fmt.Printf("Error: Cannot create output file: %v\n", err)
		os.Exit(1)
	}
	defer out.Close()

	// Расшифровать с использованием режима CTR
	stream := cipher.NewCTR(block, iv)
	buf := make([]byte, 32*1024)

	for {
		n, err := in.Read(buf)
		if n > 0 {
			stream.XORKeyStream(buf[:n], buf[:n])
			if _, err := out.Write(buf[:n]); err != nil {
				fmt.Printf("Error: Cannot write to output: %v\n", err)
				os.Exit(1)
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Printf("Error: Cannot read input: %v\n", err)
			os.Exit(1)
		}
	}

	fmt.Printf("Success! Decrypted: %s\n", outputFile)
}
