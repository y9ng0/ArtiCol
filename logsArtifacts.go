package main

import (
	"fmt"
)

// Сбор системных логов из /var/log
func getSystemLogs(c *Collector, infoSys *Info) {
	loggingFilePlusConsole(c, "Starting to retrieve system logs...", "INFO", nil)
	loggingFile(c, "Starting to retrieve system logs from \"/var/log\".", "INFO", nil)
	infoSys.Title = "system logs"
	infoSys.Time = getTimeUtc()

	logs_directory := fmt.Sprintf("%v/log/", c.MainDirectory)
	loggingFile(c, fmt.Sprintf("Creating directory \"%v\".", logs_directory), "INFO", nil)
	err := makeDirectory(logs_directory)
	if err != nil {
		loggingFilePlusConsole(c, fmt.Sprintf("Directory \"%v\" not created.", logs_directory), "ERROR", err)
		infoSys.Value = fmt.Sprintf("Error: %v", err)
		return
	}
	loggingFile(c, fmt.Sprintf("Directory \"%v\" created.", logs_directory), "INFO", nil)

	loggingFile(c, "Starting to copy \"/var/log\" directory.", "INFO", nil)
	err = copyDirectory(c, "/var/log", logs_directory)
	if err != nil {
		loggingFilePlusConsole(c, fmt.Sprintf("Failed to copy \"/var/log\": %v", err), "ERROR", err)
		infoSys.Value = fmt.Sprintf("Error: %v", err)
		return
	}
	loggingFile(c, "Successfully copied \"/var/log\" directory.", "INFO", nil)

	loggingFilePlusConsole(c, fmt.Sprintf("System logs added to \"%v\".", logs_directory), "INFO", nil)
	loggingFilePlusConsole(c, "\"System logs\" added to JSON.", "INFO", nil)
	infoSys.Value = fmt.Sprintf("%v/log/", c.MainDirectory)
}
