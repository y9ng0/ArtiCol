package main

import (
	"fmt"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/process"
	"golang.org/x/sys/unix"
)

// processWorker - воркер для параллельного сбора информации о процессах
// c - коллектор
// pids - срез идентификаторов процессов
// wg - группа ожидания
// resultsChan - канал для результатов
func processWorker(c *Collector, pids []int32, wg *sync.WaitGroup, resultsChan chan<- []processesId) {
	defer wg.Done()
	result := getInfoPid(c, pids)
	resultsChan <- result
}

// getPids - сбор информации о процессах
// c - коллектор
// info - информация об объекте
func getPids(c *Collector, info *Info) error {
	loggingFilePlusConsole(c, "Starting to retrieve \"processes\".", "INFO", nil)

	filename := "processes"
	processes_json, err := jsonCreate(c, filename)
	if err != nil {
		loggingFilePlusConsole(c, "Failed to create JSON file \"processes\".", "ERROR", nil)
		return err
	}
	defer unix.Close(processes_json)

	loggingFile(c, "Starting to retrieve process IDs.", "INFO", nil)
	pids, err := process.Pids()
	if err != nil {
		loggingFilePlusConsole(c, "Failed to retrieve \"processes\".", "ERROR", err)
		return err
	}

	length := len(pids)
	loggingFile(c, fmt.Sprintf("Found %d processes.", length), "INFO", nil)

	if length == 0 {
		loggingFile(c, "No processes found.", "WARNING", nil)
		info.Title = filename
		info.Value = fmt.Sprintf("%v/%v.json", c.MainDirectory, filename)
		info.Time = getTimeUtc()
		return nil
	}

	numWorkers := 4
	partSize := length / numWorkers
	if partSize == 0 {
		partSize = length
		numWorkers = 1
	}

	var wg sync.WaitGroup
	resultsChan := make(chan []processesId, numWorkers)

	for i := 0; i < numWorkers; i++ {
		start := i * partSize
		end := start + partSize
		if i == numWorkers-1 {
			end = length
		}
		if start >= length {
			break
		}
		wg.Add(1)
		go processWorker(c, pids[start:end], &wg, resultsChan)
	}

	wg.Wait()
	close(resultsChan)

	allProcesses := []processesId{}
	for part := range resultsChan {
		allProcesses = append(allProcesses, part...)
	}

	loggingFile(c, fmt.Sprintf("Found %d processes.", len(allProcesses)), "INFO", nil)

	info.Title = filename
	info.Value = fmt.Sprintf("%v/%v.json", c.MainDirectory, filename)
	info.Time = getTimeUtc()

	loggingJson(c, allProcesses, "Processes", true, processes_json)
	loggingFilePlusConsole(c, fmt.Sprintf("Finished retrieving \"processes\" to \"%v\".", info.Value), "INFO", nil)

	return nil
}

// getInfoPid - сбор детальной информации о конкретных процессах
// c - коллектор
// pids - срез идентификаторов процессов
func getInfoPid(c *Collector, pids []int32) []processesId {
	var partAllProcesses []processesId
	for _, pid := range pids {
		strct := processesId{}
		p, err := process.NewProcess(pid)
		if err == nil {
			strct.Pid = fmt.Sprintf("%v", pid)

			name, err := p.Name()
			if err == nil {
				strct.Name = name
			} else {
				strct.Name = fmt.Sprintf("Unknown. Error: %v", err)
			}

			status, err := p.Status()
			if err == nil {
				strct.Status = status
			} else {
				strct.Status = []string{fmt.Sprintf("Unknown. Error: %v", err)}
			}

			infoMem, err := p.MemoryInfo()
			if err == nil {
				strct.Memory = fmt.Sprintf("%.2f", float32(infoMem.RSS/1024.0/1024))
			} else {
				strct.Memory = fmt.Sprintf("Unknown. Error: %v", err)
			}

			uptime, err := p.CreateTime()
			if err == nil {
				strct.Uptime = fmt.Sprintf("%.3f", time.Since(time.Unix(0, uptime*int64(time.Millisecond))).Seconds())
			} else {
				strct.Uptime = fmt.Sprintf("Unknown. Error: %v", err)
			}

			user, err := p.Username()
			if err == nil {
				strct.User = user
			} else {
				strct.User = fmt.Sprintf("Unknown. Error: %v", err)
			}

			uids, err := p.Uids()
			if err == nil {
				strct.Uids = uids
			} else {
				strct.Uids = fmt.Sprintf("Unknown. Error: %v", err)
			}

			path, err := p.Exe()
			if err == nil {
				strct.Location = path
			} else {
				strct.Location = fmt.Sprintf("Unknown. Error: %v", err)
			}

			files, err := p.OpenFiles()
			if err == nil {
				strct.FileDescriptor = files
			} else {
				strct.FileDescriptor = fmt.Sprintf("Unknown. Error: %v", err)
			}
		} else {
			loggingFile(c, fmt.Sprintf("Failed to retrieve process \"%v\".", pid), "WARNING", err)
		}
		partAllProcesses = append(partAllProcesses, strct)
	}
	return partAllProcesses
}
