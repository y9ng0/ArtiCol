package main

import (
	"bytes"
	"fmt"

	"golang.org/x/sys/unix"
)

func CopyFile(c *Collector, source, destination string) error {
	loggingFile(c, fmt.Sprintf("Opening source file \"%v\".", source), "INFO", nil)
	sfd, err := unix.Open(source, unix.O_RDONLY, 0)
	defer unix.Close(sfd)
	if err == nil {
		var st unix.Stat_t
		unix.Stat(source, &st)

		loggingFile(c, fmt.Sprintf("Creating destination file \"%v\".", destination), "INFO", nil)
		dfd, err := unix.Open(destination, unix.O_WRONLY|unix.O_CREAT|unix.O_TRUNC, uint32(st.Mode))
		if err != nil {
			loggingFile(c, fmt.Sprintf("Unable to create destination file \"%v\".", destination), "ERROR", err)
			return err
		}
		defer unix.Close(dfd)

		loggingFile(c, fmt.Sprintf("Copying data from \"%v\" to \"%v\".", source, destination), "INFO", nil)
		_, err = unix.Sendfile(dfd, sfd, nil, int(st.Size))
		if err != nil {
			loggingFile(c, fmt.Sprintf("Unable to copy data from \"%v\" to \"%v\".", source, destination), "ERROR", err)
		} else {
			loggingFile(c, fmt.Sprintf("Successfully copied \"%v\" to \"%v\".", source, destination), "INFO", nil)
		}
		return err
	} else {
		loggingFile(c, fmt.Sprintf("Unable to open source file \"%v\".", source), "ERROR", err)
	}
	return err
}

func getPasswd(c *Collector, infoSys *Info) {
	loggingFilePlusConsole(c, "Starting to retrieve passwd...", "INFO", nil)
	loggingFile(c, "Starting to retrieve \"/etc/passwd\".", "INFO", nil)
	infoSys.Title = "/etc/passwd"
	infoSys.Time = getTimeUtc()
	path_directory := fmt.Sprintf("%v/users/", c.MainDirectory)
	loggingFile(c, fmt.Sprintf("Creating directory \"%v\".", path_directory), "INFO", nil)
	err := makeDirectory(path_directory)
	if err != nil {
		loggingFilePlusConsole(c, fmt.Sprintf("Directory \"%v\" not created.", path_directory), "ERROR", err)
		infoSys.Value = fmt.Sprintf("Error: %v", err)
		return
	}
	loggingFile(c, fmt.Sprintf("Directory \"%v\" created.", path_directory), "INFO", nil)
	destination := path_directory + "passwd"
	loggingFile(c, fmt.Sprintf("Copying \"/etc/passwd\" to \"%v\".", destination), "INFO", nil)
	err = CopyFile(c, "/etc/passwd", destination)
	if err == nil {
		fillText := fmt.Sprintf("Passwd added to \"%v\"", destination)
		loggingFilePlusConsole(c, fillText, "INFO", err)
		infoSys.Value = destination
	} else {
		fillText := fmt.Sprintf("Passwd not added to \"%v\"", destination)
		loggingFilePlusConsole(c, fillText, "ERROR", err)
		infoSys.Value = fmt.Sprintf("Error: %v", err)
	}
}

func getShadow(c *Collector, infoSys *Info, flag bool) {
	loggingFilePlusConsole(c, "Starting to retrieve shadow...", "INFO", nil)
	loggingFile(c, "Starting to retrieve \"/etc/shadow\".", "INFO", nil)
	infoSys.Title = "/etc/shadow"
	infoSys.Time = getTimeUtc()
	path_directory := fmt.Sprintf("%v/users/", c.MainDirectory)
	makeDirectory(path_directory)

	if flag {
		destination := path_directory + "shadow"
		loggingFile(c, fmt.Sprintf("Copying \"/etc/shadow\" to \"%v\".", destination), "INFO", nil)
		err := CopyFile(c, "/etc/shadow", destination)
		if err == nil {
			fillText := fmt.Sprintf("Shadow added to \"%v\"", destination)
			loggingFilePlusConsole(c, fillText, "INFO", err)
			infoSys.Value = destination
		} else {
			fillText := fmt.Sprintf("Shadow not added to \"%v\"", destination)
			loggingFilePlusConsole(c, fillText, "ERROR", err)
			infoSys.Value = fmt.Sprintf("Error: %v", err)
		}
	} else {
		loggingFilePlusConsole(c, "Shadow was not retrieved. Permission denied.", "ERROR", nil)
	}
}

func getHomeDir(c *Collector, infoSys *Info, flag bool) {
	loggingFilePlusConsole(c, "Starting to retrieve bash history...", "INFO", nil)
	loggingFile(c, "Starting to retrieve \"bash_history\".", "INFO", nil)
	infoSys.Title = "bash_history"
	infoSys.Time = getTimeUtc()
	pathUsers := "/etc/passwd"
	loggingFile(c, fmt.Sprintf("Opening \"%v\".", pathUsers), "INFO", nil)
	fd, err := unix.Open(pathUsers, unix.O_RDONLY, 0)
	defer unix.Close(fd)
	if err == nil {
		loggingFile(c, fmt.Sprintf("Reading \"%v\".", pathUsers), "INFO", nil)
		buf := make([]byte, 1024)
		var finalData []byte
		for {
			n, err := unix.Read(fd, buf)
			if n == 0 || err != nil {
				break
			}

			finalData = append(finalData, buf[:n]...)
		}
		// Собираю данные о пользователе (имя пользователя, домашняя директория и шелл)
		loggingFile(c, "Parsing \"/etc/passwd\" data.", "INFO", nil)
		temp_data := bytes.Split(finalData, []byte("\n"))
		var data [][]byte
		for _, d := range temp_data {
			if len(d) >= 1 {
				data = append(data, d)
			}
		}
		path_directory := fmt.Sprintf("%v/users/", c.MainDirectory)
		if flag {
			loggingFile(c, "Retrieving bash history for all users.", "INFO", nil)
			for _, d := range data {
				line := bytes.Split(d, []byte(":"))
				name := line[0]
				home_dir := line[5]
				shell := line[6]
				if string(shell) == "/usr/sbin/nologin" || string(shell) == "/bin/false" {
					loggingFile(c, fmt.Sprintf("Skipping user \"%s\" (nologin shell).", name), "INFO", nil)
					continue
				} else {
					loggingFile(c, fmt.Sprintf("Processing user \"%s\" with home directory \"%v\".", name, string(home_dir)), "INFO", nil)
					getHistory(c, name, home_dir)
				}
			}
		} else {
			loggingFile(c, fmt.Sprintf("Retrieving bash history for user \"%s\".", c.UserName), "INFO", nil)
			for _, d := range data {
				line := bytes.Split(d, []byte(":"))
				name := line[0]
				home_dir := line[5]
				if string(name) == c.UserName {
					loggingFile(c, fmt.Sprintf("Processing user \"%s\" with home directory \"%v\".", name, string(home_dir)), "INFO", nil)
					getHistory(c, name, home_dir)
				}
			}
		}
		infoSys.Value = path_directory
		loggingFilePlusConsole(c, fmt.Sprintf("Bash history added to \"%v\"", path_directory), "INFO", nil)

	} else {
		loggingFilePlusConsole(c, fmt.Sprintf("File to path \"%v\" could not be opened.", pathUsers), "ERROR", err)
		infoSys.Value = fmt.Sprintf("Error: %v", err)
	}
}

func getHistory(c *Collector, name, home_dir []byte) {
	user_dir := fmt.Sprintf("%v/users/%s", c.MainDirectory, name)
	loggingFile(c, fmt.Sprintf("Creating directory \"%v\" for user \"%s\".", user_dir, name), "INFO", nil)
	err := makeDirectory(user_dir)
	if err != nil {
		text := fmt.Sprintf("Directory \"%v\" not created for user \"%s\".", user_dir, name)
		loggingFile(c, text, "ERROR", err)
		return
	}
	loggingFile(c, fmt.Sprintf("Directory \"%v\" created for user \"%s\".", user_dir, name), "INFO", nil)
	destination := fmt.Sprintf("\"%v/users/%s/bash_history\"", c.MainDirectory, name)
	source := string(home_dir) + "/.bash_history"
	loggingFile(c, fmt.Sprintf("Copying \"%v\" to \"%v\".", source, destination), "INFO", nil)
	err = CopyFile(c, source, destination)
	if err != nil {
		unix.Rmdir(user_dir)
		text := fmt.Sprintf("User \"%s\" bash_history was not retrieved.", name)
		loggingFile(c, text, "ERROR", err)
	} else {
		text := fmt.Sprintf("User \"%s\" bash_history was retrieved.", name)
		loggingFile(c, text, "INFO", err)
	}
}

// Сбор сессий systemd из /var/run/systemd/sessions
func getSessions(c *Collector, infoSys *Info) {
	loggingFilePlusConsole(c, "Starting to retrieve systemd sessions...", "INFO", nil)
	loggingFile(c, "Starting to retrieve \"systemd sessions\".", "INFO", nil)
	infoSys.Title = "systemd sessions"
	infoSys.Time = getTimeUtc()

	sessions_directory := fmt.Sprintf("%v/users/sessions/", c.MainDirectory)
	loggingFile(c, fmt.Sprintf("Creating directory \"%v\".", sessions_directory), "INFO", nil)
	err := makeDirectory(sessions_directory)
	if err != nil {
		loggingFilePlusConsole(c, fmt.Sprintf("Directory \"%v\" not created.", sessions_directory), "ERROR", err)
		infoSys.Value = fmt.Sprintf("Error: %v", err)
		return
	}
	loggingFile(c, fmt.Sprintf("Directory \"%v\" created.", sessions_directory), "INFO", nil)

	loggingFile(c, "Starting to copy \"/var/run/systemd/sessions\" directory.", "INFO", nil)
	err = copyDirectory(c, "/var/run/systemd/sessions", sessions_directory)
	if err != nil {
		loggingFilePlusConsole(c, fmt.Sprintf("Failed to copy \"/var/run/systemd/sessions\": %v", err), "ERROR", err)
		infoSys.Value = fmt.Sprintf("Error: %v", err)
		return
	}
	loggingFile(c, "Successfully copied \"/var/run/systemd/sessions\" directory.", "INFO", nil)

	loggingFilePlusConsole(c, fmt.Sprintf("Systemd sessions added to \"%v\".", sessions_directory), "INFO", nil)
	loggingFilePlusConsole(c, "\"Systemd sessions\" added to JSON.", "INFO", nil)
	infoSys.Value = "./users/sessions/"
}
