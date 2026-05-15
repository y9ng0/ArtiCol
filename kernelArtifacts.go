package main

import (
	"bytes"
	"fmt"

	"golang.org/x/sys/unix"
)

// getKernelModules - сбор информации о загруженных модулях ядра
// c - коллектор
// infoSys - информация об объекте
func getKernelModules(c *Collector, infoSys *Info) {
	loggingFilePlusConsole(c, "Starting to retrieve \"kernel modules\".", "INFO", nil)
	infoSys.Title = "kernel modules"
	infoSys.Time = getTimeUtc()
	filename := "kernel_modules"
	kernel_json, _ := jsonCreate(c, filename)
	defer unix.Close(kernel_json)

	// Чтение файла /proc/modules
	fd, err := unix.Open("/proc/modules", unix.O_RDONLY, 0)
	if err != nil {
		loggingFilePlusConsole(c, "Failed to open file \"/proc/modules\".", "ERROR", err)
		infoSys.Value = fmt.Sprintf("Error: %v", err)
		return
	}
	defer unix.Close(fd)

	buf := make([]byte, 4096)
	var finalData []byte
	for {
		n, err := unix.Read(fd, buf)
		if n == 0 || err != nil {
			break
		}
		finalData = append(finalData, buf[:n]...)
	}

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
			module.RefCnt = string(parts[2])
			if len(parts) >= 4 {
				module.UsedBy = string(parts[3])
			} else {
				module.UsedBy = "-"
			}
			modules = append(modules, module)
		}
	}

	loggingJson(c, modules, "Kernel modules", true, kernel_json)
	infoSys.Value = fmt.Sprintf("%v/%v.json", c.MainDirectory, filename)
	loggingFilePlusConsole(c, fmt.Sprintf("Finished retrieving \"kernel modules\" to \"%v\".", infoSys.Value), "INFO", nil)
}
