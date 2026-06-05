package main

import (
	"fmt"

	"github.com/shirou/gopsutil/v4/net"
	"golang.org/x/sys/unix"
)

// getAllConnections - сбор информации о сетевых соединениях
// c - коллектор
// json_info - срез для сохранения информации об артефакте
// Возвращает обновленный срез json_info
func getAllConnections(c *Collector, json_info []Info) []Info {
	loggingFilePlusConsole(c, "Starting to retrieve TCP/UDP connections...", "INFO", nil)
	filename := "active_networks"
	networks_json, _ := jsonCreate(c, filename)
	network := []networks{} // наполнитель для json файла
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
	loggingJson(c, network, "Networks", true, networks_json)
	infoSys := Info{}
	infoSys.Title = "networks"
	infoSys.Value = fmt.Sprintf("%v/%v.json", c.MainDirectory, filename)
	infoSys.Time = getTimeUtc()
	json_info = append(json_info, infoSys)
	loggingFilePlusConsole(c, "Finished retrieving TCP/UDP connections.", "INFO", nil)
	return json_info
}

// getRoute - копирует /proc/net/route
func getRoute(c *Collector, infoSys *Info) {
	loggingFilePlusConsole(c, "Starting to retrieve \"routing table\".", "INFO", nil)

	infoSys.Title = "routing table"
	infoSys.Time = getTimeUtc()

	path_directory := fmt.Sprintf("%v/networks/", c.MainDirectory)
	err := makeDirectory(path_directory)
	if err != nil {
		loggingFilePlusConsole(c, fmt.Sprintf("Failed to create directory \"%v\".", path_directory), "ERROR", err)
		infoSys.Value = fmt.Sprintf("Error: %v", err)
		return
	}

	sourcePath := "/proc/net/route"
	destination := path_directory + "route"
	loggingFile(c, fmt.Sprintf("Starting to copy file \"%v\" to \"%v\".", sourcePath, destination), "INFO", nil)

	err = CopyFile(c, sourcePath, destination)
	if err == nil {
		loggingFilePlusConsole(c, fmt.Sprintf("Finished copying file \"route\" to \"%s\".", destination), "INFO", err)
		infoSys.Value = destination
	} else {
		loggingFilePlusConsole(c, "Failed to copy file \"route\".", "ERROR", err)
		infoSys.Value = fmt.Sprintf("Error: %v", err)
	}
	loggingFilePlusConsole(c, fmt.Sprintf("Finished retrieving \"routing table\" to \"%v\".", infoSys.Value), "INFO", nil)
}

// getArp - копирует /proc/net/arp
func getArp(c *Collector, infoSys *Info) {
	loggingFilePlusConsole(c, "Starting to retrieve \"arp table\".", "INFO", nil)

	infoSys.Title = "arp table"
	infoSys.Time = getTimeUtc()

	path_directory := fmt.Sprintf("%v/networks/", c.MainDirectory)
	err := makeDirectory(path_directory)
	if err != nil && err != unix.EEXIST {
		loggingFilePlusConsole(c, fmt.Sprintf("Failed to create directory \"%v\".", path_directory), "ERROR", err)
		infoSys.Value = fmt.Sprintf("Error: %v", err)
		return
	}

	sourcePath := "/proc/net/arp"
	destination := path_directory + "arp"
	loggingFile(c, fmt.Sprintf("Starting to copy file \"%v\" to \"%v\".", sourcePath, destination), "INFO", nil)

	err = CopyFile(c, sourcePath, destination)
	if err == nil {
		loggingFilePlusConsole(c, fmt.Sprintf("Finished copying file \"arp\" to \"%s\".", destination), "INFO", err)
		infoSys.Value = destination
	} else {
		loggingFilePlusConsole(c, "Failed to copy file \"arp\".", "ERROR", err)
		infoSys.Value = fmt.Sprintf("Error: %v", err)
	}
	loggingFilePlusConsole(c, fmt.Sprintf("Finished retrieving \"arp table\" to \"%v\".", infoSys.Value), "INFO", nil)
}

// getDnsConfigs - копирует /etc/resolv.conf и /etc/hosts
func getDnsConfigs(c *Collector, json_info []Info) []Info {
	loggingFilePlusConsole(c, "Starting to retrieve DNS configs...", "INFO", nil)

	path_directory := fmt.Sprintf("%v/networks/", c.MainDirectory)
	err := makeDirectory(path_directory)
	if err != nil && err != unix.EEXIST {
		loggingFilePlusConsole(c, fmt.Sprintf("Failed to create directory \"%v\".", path_directory), "ERROR", err)
		return json_info
	}

	dnsFiles := []struct {
		src  string
		dest string
	}{
		{"/etc/resolv.conf", "resolv.conf"},
		{"/etc/hosts", "hosts"},
	}

	for _, f := range dnsFiles {
		infoSys := Info{}
		infoSys.Title = f.src
		infoSys.Time = getTimeUtc()

		loggingFile(c, fmt.Sprintf("Starting to copy file \"%s\" to \"%s\".", f.src, path_directory+f.dest), "INFO", nil)
		err = CopyFile(c, f.src, path_directory+f.dest)
		if err == nil {
			loggingFilePlusConsole(c, fmt.Sprintf("Finished copying file \"%s\" to \"%s\".", f.dest, path_directory+f.dest), "INFO", err)
			infoSys.Value = path_directory + f.dest
		} else {
			loggingFilePlusConsole(c, fmt.Sprintf("Failed to copy file \"%s\".", f.dest), "ERROR", err)
			infoSys.Value = fmt.Sprintf("Error: %v", err)
		}
		json_info = append(json_info, infoSys)
	}

	loggingFilePlusConsole(c, "Finished retrieving DNS configs.", "INFO", nil)
	return json_info
}

// getNetworkConfigs - рекурсивно копирует содержимое /etc/ufw/, /etc/iptables/, /etc/ssh/
func getNetworkConfigs(c *Collector, json_info []Info) []Info {
	loggingFilePlusConsole(c, "Starting to retrieve network configs...", "INFO", nil)

	networkDirs := []struct {
		src  string
		dest string
	}{
		{"/etc/ufw", "ufw"},
		{"/etc/iptables", "iptables"},
		{"/etc/ssh", "ssh"},
	}

	for _, d := range networkDirs {
		infoSys := Info{}
		infoSys.Title = d.src
		infoSys.Time = getTimeUtc()

		dest_directory := fmt.Sprintf("%v/networks/%s/", c.MainDirectory, d.dest)
		err := makeDirectory(dest_directory)
		if err != nil {
			loggingFilePlusConsole(c, fmt.Sprintf("Failed to create directory \"%v\".", dest_directory), "ERROR", err)
			infoSys.Value = fmt.Sprintf("Error: %v", err)
			json_info = append(json_info, infoSys)
			continue
		}

		loggingFile(c, fmt.Sprintf("Starting to copy directory \"%s\".", d.src), "INFO", nil)
		err = copyDirectory(c, d.src, dest_directory)
		if err != nil {
			loggingFilePlusConsole(c, fmt.Sprintf("Failed to copy directory \"%s\".", d.src), "ERROR", err)
			infoSys.Value = fmt.Sprintf("Error: %v", err)
		} else {
			loggingFile(c, fmt.Sprintf("Finished copying directory \"%s\".", d.src), "INFO", nil)
			infoSys.Value = dest_directory
		}
		json_info = append(json_info, infoSys)
	}

	loggingFilePlusConsole(c, "Finished retrieving network configs.", "INFO", nil)
	return json_info
}

