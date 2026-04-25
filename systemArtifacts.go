package main

import (
	"fmt"

	"github.com/shirou/gopsutil/v4/host"
)

// Сбор информации о системе
// strct - Ссылка на экземпляр sysInfo структуры
// typeInfo - какую информацию необходимо добавить в структуру
func systemInfo(c *Collector, infoSys *Info) {
	loggingFilePlusConsole(c, "Starting to retrieve system info...", "INFO", nil)
	var arrive = []string{"Kernel", "Hostname", "Uptime", "OS"}
	filename := "system_info"
	loggingFile(c, fmt.Sprintf("Creating JSON file \"%v\".", filename), "INFO", nil)
	system_json, err := jsonCreate(c, filename)
	if err != nil {
		loggingFilePlusConsole(c, "System info JSON not created.", "ERROR", err)
		return
	}
	loggingFile(c, fmt.Sprintf("JSON file \"%v\" created.", filename), "INFO", nil)
	sys_json := []sysInfo{} // наполнитель system_json
	for _, value := range arrive {
		loggingFile(c, fmt.Sprintf("Retrieving \"%s\" info.", value), "INFO", nil)
		typeInfo := sysInfo{}
		// Добавить горутины
		getInfo(&typeInfo, value)
		sys_json = append(sys_json, typeInfo)
	}
	loggingFile(c, "Writing \"system_info\" to JSON.", "INFO", nil)
	loggingJson(c, sys_json, "System info", true, system_json)
	infoSys.Title = "system info"
	infoSys.Value = fmt.Sprintf("./%v.json", filename)
	infoSys.Time = getTimeUtc()
}

func getInfo(strct *sysInfo, typeInfo string) {
	info, err := host.Info()
	strct.NameInfo = typeInfo
	if err != nil {
		strct.Value = err
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
	}
}
