package main

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// getAutorunConfigs - копирует конфигурационные файлы автозапуска (/etc/rc.local и /etc/crontab)
func getAutorunConfigs(c *Collector, json_info []Info) []Info {
	loggingFilePlusConsole(c, "Starting to retrieve autorun configs...", "INFO", nil)

	path_directory := fmt.Sprintf("%v/autorun/", c.MainDirectory)
	err := makeDirectory(path_directory)
	if err != nil && err != unix.EEXIST {
		loggingFilePlusConsole(c, fmt.Sprintf("Failed to create directory \"%v\".", path_directory), "ERROR", err)
		return json_info
	}

	autorunFiles := []struct {
		src  string
		dest string
	}{
		{"/etc/rc.local", "rc.local"},
		{"/etc/crontab", "crontab"},
	}

	for _, f := range autorunFiles {
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

	loggingFilePlusConsole(c, "Finished retrieving autorun configs.", "INFO", nil)
	return json_info
}

// getAutorunDirs - рекурсивно копирует cron-директории и systemd-юниты
func getAutorunDirs(c *Collector, json_info []Info) []Info {
	loggingFilePlusConsole(c, "Starting to retrieve autorun directories...", "INFO", nil)

	autorunDirs := []struct {
		src  string
		dest string
	}{
		{"/var/spool/cron/crontabs", "crontabs"},
		{"/etc/cron.monthly", "cron.monthly"},
		{"/etc/cron.weekly", "cron.weekly"},
		{"/etc/cron.daily", "cron.daily"},
		{"/etc/cron.hourly", "cron.hourly"},
		{"/etc/cron.yearly", "cron.yearly"},
		{"/etc/cron.d", "cron.d"},
		{"/run/systemd/system", "systemd_run"},
		{"/etc/systemd/system", "systemd_etc"},
	}

	for _, d := range autorunDirs {
		infoSys := Info{}
		infoSys.Title = d.src
		infoSys.Time = getTimeUtc()

		dest_directory := fmt.Sprintf("%v/autorun/%s/", c.MainDirectory, d.dest)
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

	loggingFilePlusConsole(c, "Finished retrieving autorun directories.", "INFO", nil)
	return json_info
}
