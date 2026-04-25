package main

import (
	"fmt"

	"github.com/shirou/gopsutil/v4/net"
)

func getAllConnections(c *Collector, json_info []Info) []Info {
	loggingFilePlusConsole(c, "Starting to retrieve TCP/UDP connections...", "INFO", nil)
	loggingFile(c, "Starting to retrieve \"TCP/UDP\" connections.", "INFO", nil)
	filename := "active_networks"
	loggingFile(c, fmt.Sprintf("Creating JSON file \"%v\".", filename), "INFO", nil)
	networks_json, err := jsonCreate(c, filename)
	if err != nil {
		loggingFilePlusConsole(c, "Networks JSON not created.", "ERROR", err)
		return json_info
	}
	loggingFile(c, fmt.Sprintf("JSON file \"%v\" created.", filename), "INFO", nil)
	network := []networks{} // наполнитель для json файла
	loggingFile(c, "Retrieving \"network\" connections.", "INFO", nil)
	connections, err := net.Connections("inet")

	if err != nil {
		loggingFilePlusConsole(c, "Unable to retrieve TCP/UDP connections.", "ERROR", err)
	} else {
		loggingFile(c, fmt.Sprintf("Found %d connections.", len(connections)), "INFO", nil)
		for _, conn := range connections {
			info := networks{}
			// Pid соединения
			info.Pid = conn.Pid

			// Тип соединения и версия протокола ip
			typeCon := conn.Type
			switch typeCon {
			case 1:
				info.Type = "TCP"
			case 2:
				info.Type = "UDP"
			default:
				info.Type = fmt.Sprintf("type connection id: %v", typeCon)
			}
			versionCon := conn.Family
			switch versionCon {
			case 2:
				info.Type = fmt.Sprintf("%v(v4)", info.Type)
			case 10:
				info.Type = fmt.Sprintf("%v(v6)", info.Type)
			default:
				info.Type = fmt.Sprintf("%v (version id = %v)", info.Type, versionCon)
			}

			// IP удаленного хоста
			info.RemoteAddr = fmt.Sprintf("%v:%v", conn.Raddr.IP, conn.Raddr.Port)

			// Статус соединения
			info.Status = conn.Status

			// Локальный адрес
			info.LocalAddress = fmt.Sprintf("%v:%v", conn.Laddr.IP, conn.Laddr.Port)

			network = append(network, info)
		}
	}
	loggingFile(c, "Writing \"network\" connections to JSON.", "INFO", nil)
	loggingJson(c, network, "Networks", true, networks_json)
	infoSys := Info{}
	infoSys.Title = "networks"
	infoSys.Value = fmt.Sprintf("./%v.json", filename)
	infoSys.Time = getTimeUtc()
	json_info = append(json_info, infoSys)
	return json_info
}
