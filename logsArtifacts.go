package main

import (
	"fmt"
)

// getSystemLogs - сбор системных логов из /var/log
// c - коллектор
// infoSys - информация об объекте
func getSystemLogs(c *Collector, infoSys *Info) {
	loggingFilePlusConsole(c, "Starting to retrieve \"system logs\".", "INFO", nil)
	infoSys.Title = "system logs"
	infoSys.Time = getTimeUtc()

	logs_directory := fmt.Sprintf("%v/log/", c.MainDirectory)
	loggingFile(c, fmt.Sprintf("Starting to create directory \"%v\".", logs_directory), "INFO", nil)
	err := makeDirectory(logs_directory)
	if err != nil {
		loggingFilePlusConsole(c, fmt.Sprintf("Failed to create directory \"%v\".", logs_directory), "ERROR", err)
		infoSys.Value = fmt.Sprintf("Error: %v", err)
		return
	}
	loggingFile(c, fmt.Sprintf("Finished creating directory \"%v\".", logs_directory), "INFO", nil)

	loggingFile(c, "Starting to copy directory \"/var/log\".", "INFO", nil)
	err = copyDirectory(c, "/var/log", logs_directory)
	if err != nil {
		loggingFilePlusConsole(c, "Failed to copy directory \"/var/log\".", "ERROR", err)
		infoSys.Value = fmt.Sprintf("Error: %v", err)
		return
	}
	loggingFile(c, "Finished copying directory \"/var/log\".", "INFO", nil)

	infoSys.Value = fmt.Sprintf("%v/log/", c.MainDirectory)
	loggingFilePlusConsole(c, fmt.Sprintf("Finished retrieving \"system logs\" to \"%v\".", infoSys.Value), "INFO", nil)
}
