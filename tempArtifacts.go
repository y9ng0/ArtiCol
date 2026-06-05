package main

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// getTempDirs - рекурсивно копирует содержимое /tmp/, /dev/shm/, /var/tmp/
func getTempDirs(c *Collector, json_info []Info) []Info {
	loggingFilePlusConsole(c, "Starting to retrieve temp directories...", "INFO", nil)

	path_directory := fmt.Sprintf("%v/temp/", c.MainDirectory)
	err := makeDirectory(path_directory)
	if err != nil {
		loggingFilePlusConsole(c, fmt.Sprintf("Failed to create directory \"%v\".", path_directory), "ERROR", err)
		return json_info
	}

	tempDirs := []struct {
		src  string
		dest string
	}{
		{"/tmp", "tmp"},
		{"/dev/shm", "shm"},
		{"/var/tmp", "var_tmp"},
	}

	for _, d := range tempDirs {
		infoSys := Info{}
		infoSys.Title = d.src
		infoSys.Time = getTimeUtc()

		dest_directory := fmt.Sprintf("%v/temp/%s/", c.MainDirectory, d.dest)
		err := makeDirectory(dest_directory)
		if err != nil && err != unix.EEXIST {
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

	loggingFilePlusConsole(c, "Finished retrieving temp directories.", "INFO", nil)
	return json_info
}
