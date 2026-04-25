package main

import (
	"fmt"
	"time"

	"github.com/shirou/gopsutil/v4/process"
	"golang.org/x/sys/unix"
)

// flag - если true, то имеется допуск к привелегиям root
// info - ссылка на экземляр информационной структуры
func getPids(c *Collector, info *Info, flag bool) error {
	loggingFilePlusConsole(c, "Starting to retrieve processes...", "INFO", nil)
	loggingFile(c, "Starting to retrieve processes from /proc.", "INFO", nil)
	filename := "processes"
	var allProcesses []processesId
	loggingFile(c, fmt.Sprintf("Creating JSON file \"%v\".", filename), "INFO", nil)
	processes_json, err := jsonCreate(c, filename)
	defer unix.Close(processes_json)
	if err != nil {
		loggingFilePlusConsole(c, "JSON for processes not created.", "ERROR", nil)
		return err
	}
	loggingFile(c, fmt.Sprintf("JSON file \"%v\" created.", filename), "INFO", nil)

	loggingFile(c, "Retrieving process IDs.", "INFO", nil)
	pids, err := process.Pids()
	if err == nil {
		length := len(pids)
		loggingFile(c, fmt.Sprintf("Found %d processes in /proc.", length), "INFO", nil)
		if length >= 4 {
			p1 := length / 4
			p2 := p1 + length/4
			p3 := p2 + length/4
			parts := [][]int32{pids[:p1], pids[p1:p2], pids[p2:p3], pids[p3:]}
			for _, part := range parts {
				// Многопоточность сюда добавить
				partAllProcesses := getInfoPid(c, part, flag)
				for _, strct := range partAllProcesses {
					allProcesses = append(allProcesses, strct)
				}
			}
		} else {
			allProcesses = getInfoPid(c, pids, flag)
		}
	} else {
		loggingFilePlusConsole(c, "Unable to retrieve processes.", "ERROR", err)
		return err
	}
	info.Title = filename
	info.Value = fmt.Sprintf("./%v.json", filename)
	info.Time = getTimeUtc()
	loggingFile(c, "Writing \"processes\" to JSON.", "INFO", nil)
	loggingJson(c, allProcesses, "Processes", true, processes_json)
	return nil
}

// flag - если true, то имеется допуск к привелегиям root
// pids - 1/4 всех pids, для увеличения скорости сбора
func getInfoPid(c *Collector, pids []int32, flag bool) []processesId {
	var partAllProcesses []processesId
	for _, pid := range pids {
		strct := processesId{}
		p, err := process.NewProcess(pid)
		if err == nil {
			// Pid
			strct.Pid = fmt.Sprintf("%v", pid)

			// Имя процесса
			name, err := p.Name()
			if err == nil {
				strct.Name = name
			} else {
				strct.Name = fmt.Sprintf("Unknown. Error: %v", err)
			}

			// Статус процесса
			status, err := p.Status()
			if err == nil {
				strct.Status = status
			} else {
				strct.Status = []string{fmt.Sprintf("Unknown. Error: %v", err)}
			}

			// Оперативная память. Округление до 2 знаков после запятой
			infoMem, err := p.MemoryInfo()
			if err == nil {
				strct.Memory = fmt.Sprintf("%.2f", float32(infoMem.RSS/1024.0/1024))
			} else {
				strct.Memory = fmt.Sprintf("Unknown. Error: %v", err)
			}

			// Uptime
			uptime, err := p.CreateTime()
			if err == nil {
				strct.Uptime = fmt.Sprintf("%.3f", time.Since(time.Unix(0, uptime*int64(time.Millisecond))).Seconds())
			} else {
				strct.Uptime = fmt.Sprintf("Unknown. Error: %v", err)
			}

			// Владелец процесса
			user, err := p.Username()
			if err == nil {
				strct.User = user
			} else {
				strct.User = fmt.Sprintf("Unknown. Error: %v", err)
			}

			// UIDS [RUID, EUID, SUID, FSUID]
			uids, err := p.Uids()
			if err == nil {
				strct.Uids = uids
			} else {
				strct.Uids = fmt.Sprintf("Unknown. Error: %v", err)
			}

			// Только при наличии root или процесс запущен от твоего имени
			uids, _ = p.Uids()
			if flag || unix.Getuid() == int(uids[1]) {
				// Путь к исполняемому файлу
				path, err := p.Exe()
				if err == nil {
					strct.Location = path
				} else {
					strct.Location = fmt.Sprintf("Unknown. Error: %v", err)
				}

				// Открытые файловые дескрипторы
				files, err := p.OpenFiles()
				if err == nil {
					strct.FileDescriptor = files
				} else {
					strct.FileDescriptor = fmt.Sprintf("Unknown. Error: %v", err)
				}

			}
		} else {
			loggingFile(c, fmt.Sprintf("Unable to retrieve process [pid=\"%v\"].", pid), "ERROR", err)
		}
		partAllProcesses = append(partAllProcesses, strct)
	}
	return partAllProcesses

}
