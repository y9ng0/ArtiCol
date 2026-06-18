package main

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

type Anomaly struct {
	Title     string
	Message   string
	Timestamp string
}

type HTMLReport struct {
	Hostname  string
	StartTime time.Time
	Anomalies []Anomaly
}

var systemProcessesWhitelist = map[string]bool{
	"kworker": true, "systemd": true, "sshd": true, "cron": true, "bash": true,
	"zsh": true, "ps": true, "grep": true, "awk": true, "sed": true,
	"init": true, "kthreadd": true, "rcu_gp": true, "ksoftirqd": true,
	"migration": true, "watchdog": true, "kswapd0": true, "kdevtmpfs": true,
	"articol": true, "go": true, "dlv": true, "dbus": true, "udevd": true,
	"journald": true, "logind": true, "networkd": true, "resolved": true,
}

var trustedExternalNetworks = []struct {
	start string
	end   string
}{
	{"8.8.8.0", "8.8.8.255"}, {"8.8.4.0", "8.8.4.255"},
	{"64.233.0.0", "64.233.255.255"}, {"142.250.0.0", "142.251.255.255"},
	{"173.194.0.0", "173.194.255.255"}, {"74.125.0.0", "74.125.255.255"},
	{"108.177.0.0", "108.177.255.255"}, {"34.0.0.0", "34.255.255.255"},
	{"35.0.0.0", "35.255.255.255"}, {"162.159.0.0", "162.159.255.255"},
	{"172.64.0.0", "172.71.255.255"}, {"151.101.0.0", "151.101.255.255"},
	{"13.32.0.0", "13.79.255.255"}, {"13.224.0.0", "13.255.255.255"},
	{"52.46.0.0", "52.47.255.255"}, {"204.246.0.0", "204.246.255.255"},
	{"8.6.0.0", "8.7.255.255"}, {"8.47.0.0", "8.47.255.255"},
	{"20.0.0.0", "20.255.255.255"}, {"40.0.0.0", "40.255.255.255"},
}

func createHtmlReport(c *Collector, jsonInfo []Info) []Info {
	err := generateHTMLReport(c, jsonInfo)
	if err != nil {
		loggingFilePlusConsole(c, "Failed to generate HTML report", "WARNING", err)
	} else {
		infoHtml := Info{
			Title: "HTML Report",
			Value: c.MainDirectory + "/report.html",
			Time:  getTimeUtc(),
		}
		jsonInfo = append(jsonInfo, infoHtml)
	}
	return jsonInfo
}

func isIPInTrustedRange(ip string) bool {
	if ip == "" {
		return false
	}
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}
	var ipNum uint32
	for i := 0; i < 4; i++ {
		num, _ := strconv.Atoi(parts[i])
		ipNum = (ipNum << 8) + uint32(num)
	}
	for _, net := range trustedExternalNetworks {
		startParts := strings.Split(net.start, ".")
		endParts := strings.Split(net.end, ".")
		if len(startParts) != 4 || len(endParts) != 4 {
			continue
		}
		var startNum, endNum uint32
		for i := 0; i < 4; i++ {
			s, _ := strconv.Atoi(startParts[i])
			e, _ := strconv.Atoi(endParts[i])
			startNum = (startNum << 8) + uint32(s)
			endNum = (endNum << 8) + uint32(e)
		}
		if ipNum >= startNum && ipNum <= endNum {
			return true
		}
	}
	return false
}

func isPrivateIP(ip string) bool {
	if ip == "" || ip == "0.0.0.0" || ip == "::" {
		return true
	}
	if strings.HasPrefix(ip, "127.") || strings.HasPrefix(ip, "10.") {
		return true
	}
	if strings.HasPrefix(ip, "172.") {
		parts := strings.Split(ip, ".")
		if len(parts) >= 2 {
			second, _ := strconv.Atoi(parts[1])
			if second >= 16 && second <= 31 {
				return true
			}
		}
	}
	if strings.HasPrefix(ip, "192.168.") || strings.HasPrefix(ip, "169.254.") {
		return true
	}
	if strings.HasPrefix(ip, "224.") || strings.HasPrefix(ip, "239.") {
		return true
	}
	if ip == "::1" || strings.HasPrefix(ip, "fe80:") || strings.HasPrefix(ip, "ff02") {
		return true
	}
	return false
}

func analyzeProcesses(processes []processesId) []Anomaly {
	var anomalies []Anomaly
	suspiciousNames := []string{
		"netcat", "ncat", "socat", "reverse", "backdoor", "meterpreter",
		"msfconsole", "cobaltstrike", "beacon", "miner", "xmrig",
	}

	for _, p := range processes {
		nameStr := fmt.Sprintf("%v", p.Name)
		nameLower := strings.ToLower(nameStr)

		skip := false
		for sysProc := range systemProcessesWhitelist {
			if strings.HasPrefix(nameLower, sysProc) || strings.Contains(nameLower, sysProc) {
				skip = true
				break
			}
		}
		if skip {
			continue
		}

		for _, susp := range suspiciousNames {
			if strings.Contains(nameLower, susp) {
				anomalies = append(anomalies, Anomaly{
					Title:     "Подозрительный процесс",
					Message:   fmt.Sprintf("%s (PID: %v)", nameStr, p.Pid),
					Timestamp: getTimeUtc(),
				})
				break
			}
		}

		locStr := fmt.Sprintf("%v", p.Location)
		if strings.Contains(locStr, "/tmp/") || strings.Contains(locStr, "/dev/shm/") {
			anomalies = append(anomalies, Anomaly{
				Title:     "Процесс из временной директории",
				Message:   fmt.Sprintf("%s (PID: %v) - %s", nameStr, p.Pid, locStr),
				Timestamp: getTimeUtc(),
			})
		}
	}
	return anomalies
}

func analyzeNetwork(connections []networks) []Anomaly {
	var anomalies []Anomaly
	seen := make(map[string]bool)

	for _, conn := range connections {
		remoteAddr := fmt.Sprintf("%v", conn.RemoteAddr)
		status := fmt.Sprintf("%v", conn.Status)
		connType := fmt.Sprintf("%v", conn.Type)
		pid := fmt.Sprintf("%v", conn.Pid)

		if status == "TIME_WAIT" || status == "CLOSE_WAIT" {
			continue
		}

		ip := strings.Split(remoteAddr, ":")[0]
		if ip == "" || ip == "::" {
			continue
		}

		if isPrivateIP(ip) {
			continue
		}

		if isIPInTrustedRange(ip) {
			continue
		}

		key := fmt.Sprintf("%s_%s_%s", remoteAddr, status, pid)
		if seen[key] {
			continue
		}
		seen[key] = true

		anomalies = append(anomalies, Anomaly{
			Title:     "Внешнее соединение",
			Message:   fmt.Sprintf("%s (%s, %s, PID: %v)", remoteAddr, connType, status, conn.Pid),
			Timestamp: getTimeUtc(),
		})
	}
	return anomalies
}

func analyzeEmptyLogs(c *Collector) []Anomaly {
	var anomalies []Anomaly
	logsDir := fmt.Sprintf("%s/log/", c.MainDirectory)

	fd, err := unix.Open(logsDir, unix.O_RDONLY, 0)
	if err != nil {
		return anomalies
	}
	defer unix.Close(fd)

	buf := make([]byte, 8192)
	for {
		n, err := unix.ReadDirent(fd, buf)
		if n == 0 || err != nil {
			break
		}
		for bpos := 0; bpos < n; {
			reclen := uint16(buf[bpos+16]) | uint16(buf[bpos+17])<<8
			if reclen == 0 || int(reclen) > n-bpos {
				break
			}
			nameStart := bpos + 19
			nameEnd := nameStart
			for nameEnd < bpos+int(reclen) && nameEnd < n && buf[nameEnd] != 0 {
				nameEnd++
			}
			filename := string(buf[nameStart:nameEnd])
			if filename == "." || filename == ".." || filename == "" {
				bpos += int(reclen)
				continue
			}
			filePath := logsDir + filename
			var stat unix.Stat_t
			if unix.Stat(filePath, &stat) == nil && stat.Size == 0 {
				anomalies = append(anomalies, Anomaly{
					Title:     "Пустой лог-файл",
					Message:   filename,
					Timestamp: getTimeUtc(),
				})
			}
			bpos += int(reclen)
		}
	}
	return anomalies
}

func analyzeDeletedBashHistory(c *Collector) []Anomaly {
	var anomalies []Anomaly
	usersDir := fmt.Sprintf("%s/users/", c.MainDirectory)

	fd, err := unix.Open(usersDir, unix.O_RDONLY, 0)
	if err != nil {
		return anomalies
	}
	defer unix.Close(fd)

	skipItems := map[string]bool{
		"passwd": true, "shadow": true, "sessions": true,
		".": true, "..": true, "sudoers.d": true, "sudoers": true, "group": true,
	}

	buf := make([]byte, 8192)
	for {
		n, err := unix.ReadDirent(fd, buf)
		if n == 0 || err != nil {
			break
		}
		for bpos := 0; bpos < n; {
			reclen := uint16(buf[bpos+16]) | uint16(buf[bpos+17])<<8
			if reclen == 0 || int(reclen) > n-bpos {
				break
			}
			nameStart := bpos + 19
			nameEnd := nameStart
			for nameEnd < bpos+int(reclen) && nameEnd < n && buf[nameEnd] != 0 {
				nameEnd++
			}
			itemName := string(buf[nameStart:nameEnd])

			if skipItems[itemName] {
				bpos += int(reclen)
				continue
			}

			itemPath := usersDir + itemName
			var stat unix.Stat_t
			if unix.Stat(itemPath, &stat) != nil {
				bpos += int(reclen)
				continue
			}

			if stat.Mode&unix.S_IFDIR == 0 {
				bpos += int(reclen)
				continue
			}

			historyPath := itemPath + "/bash_history"
			var historyStat unix.Stat_t
			if unix.Stat(historyPath, &historyStat) != nil {
				anomalies = append(anomalies, Anomaly{
					Title:     "Удаленный .bash_history",
					Message:   fmt.Sprintf("Пользователь %s: файл .bash_history отсутствует", itemName),
					Timestamp: getTimeUtc(),
				})
			} else if historyStat.Size == 0 {
				anomalies = append(anomalies, Anomaly{
					Title:     "Пустой .bash_history",
					Message:   fmt.Sprintf("Пользователь %s: файл .bash_history пуст", itemName),
					Timestamp: getTimeUtc(),
				})
			}

			zshHistoryPath := itemPath + "/zsh_history"
			var zshHistoryStat unix.Stat_t
			if unix.Stat(zshHistoryPath, &zshHistoryStat) != nil {
				anomalies = append(anomalies, Anomaly{
					Title:     "Удаленный .zsh_history",
					Message:   fmt.Sprintf("Пользователь %s: файл .zsh_history отсутствует", itemName),
					Timestamp: getTimeUtc(),
				})
			} else if zshHistoryStat.Size == 0 {
				anomalies = append(anomalies, Anomaly{
					Title:     "Пустой .zsh_history",
					Message:   fmt.Sprintf("Пользователь %s: файл .zsh_history пуст", itemName),
					Timestamp: getTimeUtc(),
				})
			}
			bpos += int(reclen)
		}
	}
	return anomalies
}

func analyzeDataExfiltration(c *Collector) []Anomaly {
	var anomalies []Anomaly
	usersDir := fmt.Sprintf("%s/users/", c.MainDirectory)

	fd, err := unix.Open(usersDir, unix.O_RDONLY, 0)
	if err != nil {
		return anomalies
	}
	defer unix.Close(fd)

	buf := make([]byte, 8192)
	for {
		n, err := unix.ReadDirent(fd, buf)
		if n == 0 || err != nil {
			break
		}
		for bpos := 0; bpos < n; {
			reclen := uint16(buf[bpos+16]) | uint16(buf[bpos+17])<<8
			if reclen == 0 || int(reclen) > n-bpos {
				break
			}
			nameStart := bpos + 19
			nameEnd := nameStart
			for nameEnd < bpos+int(reclen) && nameEnd < n && buf[nameEnd] != 0 {
				nameEnd++
			}
			userName := string(buf[nameStart:nameEnd])
			if userName == "." || userName == ".." || userName == "" {
				bpos += int(reclen)
				continue
			}

			for _, histFile := range []string{"bash_history", "zsh_history"} {
				historyPath := usersDir + userName + "/" + histFile
				content, err := readSmallFile(historyPath)
				if err == nil && content != "" {
					lines := strings.Split(content, "\n")
					for _, line := range lines {
						if strings.Contains(line, "scp ") || strings.Contains(line, "rsync ") {
							fields := strings.Fields(line)
							for _, field := range fields {
								var hostPart string
								if strings.Contains(field, "@") {
									parts := strings.Split(field, "@")
									if len(parts) > 1 {
										hostPart = strings.Split(parts[1], ":")[0]
									}
								} else if strings.Contains(field, ":") && !strings.Contains(field, "://") {
									hostPart = strings.Split(field, ":")[0]
								}
								if hostPart != "" && !isPrivateIP(hostPart) && !isIPInTrustedRange(hostPart) {
									anomalies = append(anomalies, Anomaly{
										Title:     "Эксфильтрация данных",
										Message:   fmt.Sprintf("Пользователь %s: %s", userName, strings.TrimSpace(line)),
										Timestamp: getTimeUtc(),
									})
									break
								}
							}
						}
					}
				}
			}
			bpos += int(reclen)
		}
	}
	return anomalies
}

func analyzeSecurityDisabled(c *Collector) []Anomaly {
	var anomalies []Anomaly
	usersDir := fmt.Sprintf("%s/users/", c.MainDirectory)

	suspiciousCommands := []string{
		"setenforce 0", "selinux=0", "selinux=disabled",
		"systemctl stop apparmor", "systemctl disable apparmor", "aa-disable",
	}

	fd, err := unix.Open(usersDir, unix.O_RDONLY, 0)
	if err != nil {
		return anomalies
	}
	defer unix.Close(fd)

	buf := make([]byte, 8192)
	for {
		n, err := unix.ReadDirent(fd, buf)
		if n == 0 || err != nil {
			break
		}
		for bpos := 0; bpos < n; {
			reclen := uint16(buf[bpos+16]) | uint16(buf[bpos+17])<<8
			if reclen == 0 || int(reclen) > n-bpos {
				break
			}
			nameStart := bpos + 19
			nameEnd := nameStart
			for nameEnd < bpos+int(reclen) && nameEnd < n && buf[nameEnd] != 0 {
				nameEnd++
			}
			userName := string(buf[nameStart:nameEnd])
			if userName == "." || userName == ".." || userName == "" {
				bpos += int(reclen)
				continue
			}

			for _, histFile := range []string{"bash_history", "zsh_history"} {
				historyPath := usersDir + userName + "/" + histFile
				content, err := readSmallFile(historyPath)
				if err == nil && content != "" {
					lines := strings.Split(content, "\n")
					for _, line := range lines {
						for _, cmd := range suspiciousCommands {
							if strings.Contains(line, cmd) {
								anomalies = append(anomalies, Anomaly{
									Title:     "Отключение защиты",
									Message:   fmt.Sprintf("Пользователь %s: %s", userName, strings.TrimSpace(line)),
									Timestamp: getTimeUtc(),
								})
								break
							}
						}
					}
				}
			}
			bpos += int(reclen)
		}
	}
	return anomalies
}

func analyzeSudoWithoutTTY(processes []processesId) []Anomaly {
	var anomalies []Anomaly

	for _, p := range processes {
		processName := fmt.Sprintf("%v", p.Name)
		if processName != "sudo" {
			continue
		}
		fdInterface := p.FileDescriptor
		hasTTY := false

		switch v := fdInterface.(type) {
		case []interface{}:
			for _, f := range v {
				fdMap, ok := f.(map[string]interface{})
				if ok {
					path := fmt.Sprintf("%v", fdMap["path"])
					if strings.Contains(path, "/dev/pts/") || strings.Contains(path, "/dev/tty") {
						hasTTY = true
						break
					}
				}
			}
		case string:
			if strings.Contains(v, "/dev/pts/") || strings.Contains(v, "/dev/tty") {
				hasTTY = true
			}
		}

		if !hasTTY {
			pid := fmt.Sprintf("%v", p.Pid)
			user := fmt.Sprintf("%v", p.User)
			anomalies = append(anomalies, Anomaly{
				Title:     "sudo без терминала",
				Message:   fmt.Sprintf("sudo (PID: %s) от пользователя %s без привязки к терминалу", pid, user),
				Timestamp: getTimeUtc(),
			})
		}
	}
	return anomalies
}

func readSmallFile(path string) (string, error) {
	fd, err := unix.Open(path, unix.O_RDONLY, 0)
	if err != nil {
		return "", err
	}
	defer unix.Close(fd)
	buf := make([]byte, 1024*1024)
	n, err := unix.Read(fd, buf)
	if err != nil || n == 0 {
		return "", err
	}
	return string(buf[:n]), nil
}

func generateHTMLReport(c *Collector, jsonInfo []Info) error {
	startTime := time.Now().UTC()
	loggingFilePlusConsole(c, "Generating HTML report...", "INFO", nil)

	report := HTMLReport{
		Hostname:  getHostname(),
		StartTime: startTime,
		Anomalies: []Anomaly{},
	}

	processesPath := fmt.Sprintf("%s/processes.json", c.MainDirectory)
	processesData, _ := readJSONFile(processesPath)
	var processes []processesId
	if processesData != nil {
		jsonBytes, _ := json.Marshal(processesData)
		json.Unmarshal(jsonBytes, &processes)
		report.Anomalies = append(report.Anomalies, analyzeProcesses(processes)...)
		report.Anomalies = append(report.Anomalies, analyzeSudoWithoutTTY(processes)...)
	}

	networksPath := fmt.Sprintf("%s/active_networks.json", c.MainDirectory)
	networksData, _ := readJSONFile(networksPath)
	var connections []networks
	if networksData != nil {
		jsonBytes, _ := json.Marshal(networksData)
		json.Unmarshal(jsonBytes, &connections)
		report.Anomalies = append(report.Anomalies, analyzeNetwork(connections)...)
	}

	report.Anomalies = append(report.Anomalies, analyzeDataExfiltration(c)...)
	report.Anomalies = append(report.Anomalies, analyzeSecurityDisabled(c)...)
	report.Anomalies = append(report.Anomalies, analyzeDeletedBashHistory(c)...)
	report.Anomalies = append(report.Anomalies, analyzeEmptyLogs(c)...)

	systemData, _ := readJSONFile(fmt.Sprintf("%s/system_info.json", c.MainDirectory))
	kernelData, _ := readJSONFile(fmt.Sprintf("%s/kernel_modules.json", c.MainDirectory))

	htmlContent := buildHTMLTables(report, systemData, processesData, networksData, kernelData)

	htmlPath := fmt.Sprintf("%s/report.html", c.MainDirectory)
	fd, err := unix.Open(htmlPath, unix.O_CREAT|unix.O_WRONLY|unix.O_TRUNC, 0700)
	if err != nil {
		loggingFilePlusConsole(c, "Failed to create HTML report", "ERROR", err)
		return err
	}
	defer unix.Close(fd)
	unix.Write(fd, []byte(htmlContent))

	unix.Chmod(htmlPath, 0644)
	unix.Chmod(c.MainDirectory, 0755)

	loggingFilePlusConsole(c, fmt.Sprintf("HTML report: %s (anomalies: %d)", htmlPath, len(report.Anomalies)), "INFO", nil)
	return nil
}

func getHostname() string {
	var utsname unix.Utsname
	unix.Uname(&utsname)
	hostname := make([]byte, 0, 64)
	for _, b := range utsname.Nodename {
		if b == 0 {
			break
		}
		hostname = append(hostname, byte(b))
	}
	if len(hostname) == 0 {
		return "unknown"
	}
	return string(hostname)
}

func readJSONFile(path string) (interface{}, error) {
	fd, err := unix.Open(path, unix.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	buf := make([]byte, 1024*1024)
	var data []byte
	for {
		n, err := unix.Read(fd, buf)
		if n == 0 || err != nil {
			break
		}
		data = append(data, buf[:n]...)
	}
	var result interface{}
	json.Unmarshal(data, &result)
	return result, nil
}

func formatSystemTable(data interface{}) string {
	sysSlice, ok := data.([]interface{})
	if !ok {
		return "<tr><td colspan=\"2\">Нет данных</td></tr>"
	}

	var rows string
	for _, item := range sysSlice {
		itemMap, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		title := fmt.Sprintf("%v", itemMap["title"])
		value := fmt.Sprintf("%v", itemMap["value"])

		var displayTitle string
		switch title {
		case "Kernel":
			displayTitle = "Ядро"
		case "Hostname":
			displayTitle = "Имя хоста"
		case "Uptime":
			displayTitle = "Время работы"
		case "OS":
			displayTitle = "Операционная система"
		default:
			displayTitle = title
		}
		rows += fmt.Sprintf("<tr><td class=\"label\">%s</td><td>%s</td></tr>", displayTitle, value)
	}
	return rows
}

func formatKernelTable(data interface{}) string {
	modules, ok := data.([]interface{})
	if !ok || len(modules) == 0 {
		return "<tr><td colspan=\"4\">Нет данных</td></tr>"
	}

	var rows string
	for _, module := range modules {
		modMap, ok := module.(map[string]interface{})
		if !ok {
			continue
		}
		name := fmt.Sprintf("%v", modMap["name"])
		size := fmt.Sprintf("%v", modMap["size"])
		refcnt := fmt.Sprintf("%v", modMap["refcnt"])
		usedby := fmt.Sprintf("%v", modMap["usedby"])
		if usedby == "-" || usedby == "" {
			usedby = "нет"
		}

		rows += fmt.Sprintf("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>", 
			name, size, refcnt, usedby)
	}
	return rows
}

func formatProcessesTable(data interface{}) string {
	processes, ok := data.([]interface{})
	if !ok || len(processes) == 0 {
		return "<tr><td colspan=\"6\">Нет данных</td></tr>"
	}

	var rows string
	for _, proc := range processes {
		procMap, ok := proc.(map[string]interface{})
		if !ok {
			continue
		}
		if procMap["pid"] == nil && procMap["title"] == nil {
			continue
		}
		pid := fmt.Sprintf("%v", procMap["pid"])
		name := fmt.Sprintf("%v", procMap["title"])
		user := fmt.Sprintf("%v", procMap["user"])
		ram := fmt.Sprintf("%v", procMap["ram"])
		status := fmt.Sprintf("%v", procMap["status"])
		uptime := fmt.Sprintf("%v", procMap["uptime"])

		rows += fmt.Sprintf("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>",
			pid, name, user, ram, status, uptime)
	}
	return rows
}

func formatNetworkTable(data interface{}) string {
	connections, ok := data.([]interface{})
	if !ok || len(connections) == 0 {
		return "<tr><td colspan=\"5\">Нет данных</td></tr>"
	}

	var rows string
	for _, conn := range connections {
		connMap, ok := conn.(map[string]interface{})
		if !ok {
			continue
		}
		pid := fmt.Sprintf("%v", connMap["pid"])
		localAddr := fmt.Sprintf("%v", connMap["localaddr"])
		remoteAddr := fmt.Sprintf("%v", connMap["remoteaddr"])
		connType := fmt.Sprintf("%v", connMap["type"])
		status := fmt.Sprintf("%v", connMap["status"])

		rows += fmt.Sprintf("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>",
			pid, localAddr, remoteAddr, connType, status)
	}
	return rows
}

func buildHTMLTables(report HTMLReport, systemData, processesData, networksData, kernelData interface{}) string {
	seen := make(map[string]bool)
	var uniqueAnomalies []Anomaly
	for _, a := range report.Anomalies {
		key := a.Title + a.Message
		if !seen[key] {
			seen[key] = true
			uniqueAnomalies = append(uniqueAnomalies, a)
		}
	}

	var anomaliesHTML string
	for _, a := range uniqueAnomalies {
		title := a.Title
		msg := a.Message
		ts := a.Timestamp
		if ts == "" {
			ts = getTimeUtc()
		}
		if len(ts) > 19 {
			ts = ts[:19]
		}
		anomaliesHTML += fmt.Sprintf("<div class=\"anomaly-item\">• %s: %s (%s)</div>", title, msg, ts)
	}
	if anomaliesHTML == "" {
		anomaliesHTML = "<div>-</div>"
	}



	systemTable := formatSystemTable(systemData)
	kernelTable := formatKernelTable(kernelData)
	processesTable := formatProcessesTable(processesData)
	networkTable := formatNetworkTable(networksData)

	hostname := report.Hostname
	if hostname == "" {
		hostname = "unknown"
	}
	startTime := report.StartTime.Format("2006-01-02 15:04:05")

	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>ArtiCol - отчет</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            background-color: #0a0e1a;
            color: #c0c0c0;
            font-family: 'Segoe UI', 'Monaco', monospace;
            padding: 20px;
            line-height: 1.5;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        h1 {
            font-size: 1.5em;
            margin-bottom: 20px;
            color: #c0c0c0;
            font-weight: normal;
        }
        .info {
            color: #808080;
            margin-bottom: 20px;
            font-size: 13px;
        }
        hr {
            border: none;
            border-top: 1px solid #2a2a3a;
            margin: 20px 0;
        }
        .section {
            margin-bottom: 30px;
            border: 1px solid #2a2a3a;
            border-radius: 6px;
            overflow: hidden;
        }
        .section-title {
            background-color: #111118;
            padding: 10px 15px;
            font-weight: bold;
            border-bottom: 1px solid #2a2a3a;
            cursor: pointer;
            user-select: none;
            font-size: 14px;
        }
        .section-title:hover {
            background-color: #1a1a22;
        }
        .section-content {
            padding: 15px;
            display: block;
            overflow-x: auto;
        }
        .section-content.collapsed {
            display: none;
        }
        table {
            width: 100%%;
            border-collapse: collapse;
            font-size: 12px;
        }
        th {
            text-align: left;
            padding: 8px 10px;
            background-color: #111118;
            border-bottom: 1px solid #2a2a3a;
            font-weight: 600;
            color: #e0e0e0;
        }
        td {
            padding: 6px 10px;
            border-bottom: 1px solid #1a1a22;
            vertical-align: top;
        }
        tr:hover td {
            background-color: #111118;
        }
        td.label {
            font-weight: 600;
            width: 200px;
            color: #a0a0a0;
        }
        .anomaly-item {
            padding: 6px 0;
            font-family: monospace;
            font-size: 12px;
            border-left: 3px solid #ffaa44;
            padding-left: 10px;
            margin: 5px 0;
        }
        .collapsed-indicator {
            float: right;
            font-size: 12px;
        }
        @media (max-width: 768px) {
            body { padding: 10px; }
            .section-content { padding: 10px; }
            th, td { padding: 4px 6px; font-size: 10px; }
            td.label { width: 120px; }
        }
    </style>
</head>
<body>
<div class="container">
<h1>ArtiCol - отчет по сбору артефактов</h1>
<div class="info">Хост: %s | Время сбора: %s</div>
<hr>

<div class="section">
    <div class="section-title" onclick="toggleSection(this)">
        Аномалии (%d)
        <span class="collapsed-indicator">▼</span>
    </div>
    <div class="section-content">%s</div>
</div>



<div class="section">
    <div class="section-title" onclick="toggleSection(this)">
        Системная информация
        <span class="collapsed-indicator">▼</span>
    </div>
    <div class="section-content">
        <table>
            <tbody>%s</tbody>
        </table>
    </div>
</div>

<div class="section">
    <div class="section-title" onclick="toggleSection(this)">
        Запущенные процессы
        <span class="collapsed-indicator">▼</span>
    </div>
    <div class="section-content">
        <div style="overflow-x: auto;">
            <table>
                <thead>
                    <tr>
                        <th>PID</th>
                        <th>Название</th>
                        <th>Пользователь</th>
                        <th>RAM (МБ)</th>
                        <th>Статус</th>
                        <th>Время работы (с)</th>
                    </tr>
                </thead>
                <tbody>%s</tbody>
            </table>
        </div>
    </div>
</div>

<div class="section">
    <div class="section-title" onclick="toggleSection(this)">
        Сетевые соединения
        <span class="collapsed-indicator">▼</span>
    </div>
    <div class="section-content">
        <div style="overflow-x: auto;">
            <table>
                <thead>
                    <tr>
                        <th>PID</th>
                        <th>Локальный адрес</th>
                        <th>Удалённый адрес</th>
                        <th>Тип</th>
                        <th>Статус</th>
                    </tr>
                </thead>
                <tbody>%s</tbody>
            </table>
        </div>
    </div>
</div>

<div class="section">
    <div class="section-title" onclick="toggleSection(this)">
        Модули ядра
        <span class="collapsed-indicator">▼</span>
    </div>
    <div class="section-content">
        <div style="overflow-x: auto;">
            <table>
                <thead>
                    <tr>
                        <th>Название модуля</th>
                        <th>Объём (байт)</th>
                        <th>Количество ссылок</th>
                        <th>Используется модулями</th>
                    </tr>
                </thead>
                <tbody>%s</tbody>
            </table>
        </div>
    </div>
</div>

<script>
function toggleSection(title) {
    var content = title.nextElementSibling;
    var indicator = title.querySelector('.collapsed-indicator');
    content.classList.toggle('collapsed');
    if (indicator) {
        indicator.style.transform = content.classList.contains('collapsed') ? 'rotate(-90deg)' : 'rotate(0deg)';
    }
}
</script>
</div>
</body>
</html>`,
		hostname, startTime,
		len(uniqueAnomalies),
		anomaliesHTML,
		systemTable,
		processesTable,
		networkTable,
		kernelTable,
	)
}