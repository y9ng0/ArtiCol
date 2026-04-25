package main

import (
	"bytes"
	"fmt"

	"golang.org/x/sys/unix"
)

// Сбор информации о загруженных модулях ядра
func getKernelModules(c *Collector, infoSys *Info) {
	loggingFilePlusConsole(c, "Starting to retrieve kernel modules...", "INFO", nil)
	infoSys.Title = "kernel modules"
	infoSys.Time = getTimeUtc()
	filename := "kernel_modules"
	loggingFile(c, fmt.Sprintf("Creating JSON file \"%v\".", filename), "INFO", nil)
	kernel_json, err := jsonCreate(c, filename)
	if err != nil {
		loggingFilePlusConsole(c, "Kernel modules JSON not created.", "ERROR", err)
		infoSys.Value = fmt.Sprintf("Error: %v", err)
		return
	}
	defer unix.Close(kernel_json)
	loggingFile(c, fmt.Sprintf("JSON file \"%v\" created.", filename), "INFO", nil)

	// Чтение файла /proc/modules
	loggingFile(c, "Opening \"/proc/modules\".", "INFO", nil)
	fd, err := unix.Open("/proc/modules", unix.O_RDONLY, 0)
	defer unix.Close(fd)
	if err != nil {
		loggingFilePlusConsole(c, "Unable to open \"/proc/modules\".", "ERROR", err)
		infoSys.Value = fmt.Sprintf("Error: %v", err)
		return
	}
	loggingFile(c, "Reading \"/proc/modules\".", "INFO", nil)

	buf := make([]byte, 4096)
	var finalData []byte
	for {
		n, err := unix.Read(fd, buf)
		if n == 0 || err != nil {
			break
		}
		finalData = append(finalData, buf[:n]...)
	}
	loggingFile(c, "Parsing \"/proc/modules\" data.", "INFO", nil)

	// Парсинг данных
	lines := bytes.Split(finalData, []byte("\n"))
	modules := []kernelModule{}

	// Пропускаем заголовок (если есть) и пустые строки
	for _, line := range lines {
		if len(line) < 1 {
			continue
		}
		// Пропускаем заголовок если он начинается с "Module"
		if bytes.HasPrefix(line, []byte("Module")) {
			continue
		}

		parts := bytes.Fields(line)
		if len(parts) >= 3 {
			module := kernelModule{}
			module.Name = string(parts[0])
			module.Size = string(parts[1])
			module.UsedBy = string(parts[2])
			if len(parts) >= 4 {
				module.RefCnt = string(parts[3])
			} else {
				module.RefCnt = "0"
			}
			modules = append(modules, module)
		}
	}

	loggingFile(c, "Writing \"kernel_modules\" to JSON.", "INFO", nil)
	loggingJson(c, modules, "Kernel modules", true, kernel_json)
	infoSys.Value = fmt.Sprintf("./%v.json", filename)
}
