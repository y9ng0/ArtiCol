package main

import (
	"fmt"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/process"
	"golang.org/x/sys/unix"
)

func processWorker(c *Collector, pids []int32, flag bool, wg *sync.WaitGroup, resultsChan chan<- []processesId) {
	defer wg.Done()
	result := getInfoPid(c, pids, flag)
	resultsChan <- result
}

func getPids(c *Collector, info *Info, flag bool) error {
	loggingFilePlusConsole(c, "Starting to retrieve processes (parallel)...", "INFO", nil)
	loggingFile(c, "Starting to retrieve processes from /proc.", "INFO", nil)

	filename := "processes"
	processes_json, err := jsonCreate(c, filename)
	if err != nil {
		loggingFilePlusConsole(c, "JSON for processes not created.", "ERROR", nil)
		return err
	}
	defer unix.Close(processes_json)

	loggingFile(c, "Retrieving process IDs.", "INFO", nil)
	pids, err := process.Pids()
	if err != nil {
		loggingFilePlusConsole(c, "Unable to retrieve processes.", "ERROR", err)
		return err
	}

	length := len(pids)
	loggingFile(c, fmt.Sprintf("Found %d processes in /proc.", length), "INFO", nil)

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
		go processWorker(c, pids[start:end], flag, &wg, resultsChan)
	}

	wg.Wait()
	close(resultsChan)

	allProcesses := []processesId{}
	for part := range resultsChan {
		allProcesses = append(allProcesses, part...)
	}

	loggingFile(c, fmt.Sprintf("Total processes collected: %d", len(allProcesses)), "INFO", nil)

	info.Title = filename
	info.Value = fmt.Sprintf("%v/%v.json", c.MainDirectory, filename)
	info.Time = getTimeUtc()

	loggingFile(c, "Writing \"processes\" to JSON.", "INFO", nil)
	loggingJson(c, allProcesses, "Processes", true, processes_json)

	return nil
}

func getInfoPid(c *Collector, pids []int32, flag bool) []processesId {
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

			if flag || unix.Getuid() == int(uids[1]) {
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
			}
		} else {
			loggingFile(c, fmt.Sprintf("Unable to retrieve process [pid=\"%v\"]: %v", pid, err), "ERROR", err)
		}
		partAllProcesses = append(partAllProcesses, strct)
	}
	return partAllProcesses
}
