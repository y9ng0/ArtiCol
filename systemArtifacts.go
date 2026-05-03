package main

import (
	"fmt"

	"github.com/shirou/gopsutil/v4/host"
)

// systemInfo - сбор информации о системе
// c - коллектор
// infoSys - информация об объекте
func systemInfo(c *Collector, infoSys *Info) {
	loggingFilePlusConsole(c, "Starting to retrieve \"system information\".", "INFO", nil)

	// Типы информации для сбора
	var arrive = []string{"Kernel", "Hostname", "Uptime", "OS"}

	// Создание JSON файла
	filename := "system_info"
	system_json, _ := jsonCreate(c, filename)

	// Наполнитель для JSON файла
	sys_json := []sysInfo{}

	// Заполнение JSON файла
	for _, value := range arrive {
		typeInfo := sysInfo{}
		getInfo(c, &typeInfo, value)
		sys_json = append(sys_json, typeInfo)
	}

	// Запись в JSON файл
	loggingJson(c, sys_json, "system", true, system_json)
	infoSys.Title = "system information"
	infoSys.Value = fmt.Sprintf("%v/%v.json", c.MainDirectory, filename)
	infoSys.Time = getTimeUtc()
	loggingFilePlusConsole(c, fmt.Sprintf("Finished retrieving \"system information\" to \"%v\".", infoSys.Value), "INFO", nil)
}

// getInfo - получение информации о системе
// c - коллектор
// strct - структура для заполнения
// typeInfo - тип информации
func getInfo(c *Collector, strct *sysInfo, typeInfo string) {
	loggingFile(c, fmt.Sprintf("Starting to retrieve \"%v\".", typeInfo), "INFO", nil)
	info, err := host.Info()
	strct.NameInfo = typeInfo
	if err != nil {
		loggingFile(c, fmt.Sprintf("Failed to retrieve \"%v\".", typeInfo), "WARNING", err)
		strct.Value = fmt.Sprintf("Error: %v", err)
	} else {
		switch typeInfo {
		case "Uptime":
			strct.Value = fmt.Sprintf("%ds", info.Uptime)
		case "Hostname":
			strct.Value = info.Hostname
		case "Kernel":
			strct.Value = info.KernelVersion + " " + info.KernelArch
		case "OS":
			strct.Value = fmt.Sprintf("%v (%v)", info.PlatformFamily, info.PlatformVersion)
		}
		loggingFile(c, fmt.Sprintf("Finished retrieving \"%v\".", typeInfo), "INFO", nil)
	}
}
