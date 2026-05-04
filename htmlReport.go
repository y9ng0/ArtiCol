package main

import (
	"encoding/json"
	"fmt"
	"sort"
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

type TimelineEvent struct {
	Timestamp string
	Event     string
}

type HTMLReport struct {
	Hostname  string
	StartTime time.Time
	Anomalies []Anomaly
	Timeline  []TimelineEvent
}
// processes whitelist (to prevent inclusion in report)
var systemProcessesWhitelist = map[string]bool{
	"kworker": true, "systemd": true, "sshd": true, "cron": true, "bash": true,
	"zsh": true, "ps": true, "grep": true, "awk": true, "sed": true,
	"init": true, "kthreadd": true, "rcu_gp": true, "ksoftirqd": true,
	"migration": true, "watchdog": true, "kswapd0": true, "kdevtmpfs": true,
}
// same stuff but for IPs
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

func isIPInTrustedRange(ip string) bool {
	if ip == "" {
		return false
	}
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}
// conversion into 32bit
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
// checks if IP is from class A-C private networks
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
	return false
}
// input: slice of processes from processes.json, return: slice of anomalies
// suspicious names - take a wild guess
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
			if strings.HasPrefix(nameLower, sysProc) || nameLower == sysProc {
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
// input: slice of connections from active_networks.json, return: anomalies slice, seen - deduplication map
func analyzeNetwork(connections []networks) []Anomaly {
	var anomalies []Anomaly
	seen := make(map[string]bool)

	for _, conn := range connections {
		remoteAddr := fmt.Sprintf("%v", conn.RemoteAddr)
		status := fmt.Sprintf("%v", conn.Status)
		connType := fmt.Sprintf("%v", conn.Type)
		pid := fmt.Sprintf("%v", conn.Pid)
// looks only for ESTABLISHED connections
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
// generates key from addr, status and pid, if it exists - skips
		key := fmt.Sprintf("%s_%s_%s", remoteAddr, status, pid)
		if seen[key] {
			continue
		}
		seen[key] = true
// adds anomaly
		anomalies = append(anomalies, Anomaly{
			Title:     "Внешнее соединение",
			Message:   fmt.Sprintf("%s (%s, %s, PID: %v)", remoteAddr, connType, status, conn.Pid),
			Timestamp: getTimeUtc(),
		})
	}
	return anomalies
}
// I fail to explain things happening here
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

// somehow, it was triggered by these, so I had to add another whitelist
	skipItems := map[string]bool{
		"passwd":   true,
		"shadow":   true,
		"sessions": true,
		".":        true,
		"..":       true,
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
// reads user's bash_history
			historyPath := usersDir + userName + "/bash_history"
			content, err := readSmallFile(historyPath)
			if err == nil && content != "" {
				lines := strings.Split(content, "\n")
				for _, line := range lines {
				// looks for scp and rsync
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
							// if host is external and not trusted, adds an anomaly to report
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
			bpos += int(reclen)
		}
	}
	return anomalies
}
// looks for signs of disabling security systems
func analyzeSecurityDisabled(c *Collector) []Anomaly {
	var anomalies []Anomaly
	usersDir := fmt.Sprintf("%s/users/", c.MainDirectory)
// another whitelist
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
//reads .bash_history and adds an anomaly if something suspicious is found
			historyPath := usersDir + userName + "/bash_history"
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
			bpos += int(reclen)
		}
	}
	return anomalies
}
// seeks for sudo without TTY (oh whoah really?)
func analyzeSudoWithoutTTY(processes []processesId) []Anomaly {
	var anomalies []Anomaly
// looks for sudo processes in general
	for _, p := range processes {
		processName := fmt.Sprintf("%v", p.Name)
		if processName != "sudo" {
			continue
		}
		fdInterface := p.FileDescriptor
		hasTTY := false
// looks for sudo with terminal, if sudo is without terminal - anomaly found
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
// creates timeline beginning from assembly launch
func buildTimeline(anomalies []Anomaly, processes []processesId, connections []networks) []TimelineEvent {
	var timeline []TimelineEvent
	now := getTimeUtc()
	timeline = append(timeline, TimelineEvent{Timestamp: now, Event: "Запуск сбора"})
// deduplication for timeline
	seen := make(map[string]bool)
	for _, a := range anomalies {
		key := a.Title + a.Message
		if seen[key] {
			continue
		}
		seen[key] = true
		timeline = append(timeline, TimelineEvent{Timestamp: a.Timestamp, Event: a.Title + ": " + a.Message})
	}

	timeline = append(timeline, TimelineEvent{Timestamp: now, Event: fmt.Sprintf("Процессов: %d, Соединений: %d", len(processes), len(connections))})
	// lists resulting count of the processes and connections
	sort.Slice(timeline, func(i, j int) bool { return timeline[i].Timestamp > timeline[j].Timestamp })
	return timeline
}
// from here starts some sort of magic that builds all the HTML so u should not bother
func generateHTMLReport(c *Collector, jsonInfo []Info) error {
	startTime := time.Now().UTC()
	loggingFilePlusConsole(c, "Generating HTML report...", "INFO", nil)

	report := HTMLReport{
		Hostname:  getHostname(),
		StartTime: startTime,
		Anomalies: []Anomaly{},
		Timeline:  []TimelineEvent{},
	}

	processesPath := fmt.Sprintf("%s/processes.json", c.MainDirectory)
	processesData, _ := readJSONFile(processesPath)
	var processes []processesId
	processesStr := "[]"
	if processesData != nil {
		jsonBytes, _ := json.MarshalIndent(processesData, "", "  ")
		processesStr = string(jsonBytes)
		json.Unmarshal(jsonBytes, &processes)

		report.Anomalies = append(report.Anomalies, analyzeProcesses(processes)...)
		report.Anomalies = append(report.Anomalies, analyzeSudoWithoutTTY(processes)...)
	}

	networksPath := fmt.Sprintf("%s/active_networks.json", c.MainDirectory)
	networksData, _ := readJSONFile(networksPath)
	var connections []networks
	networksStr := "[]"
	if networksData != nil {
		jsonBytes, _ := json.MarshalIndent(networksData, "", "  ")
		networksStr = string(jsonBytes)
		json.Unmarshal(jsonBytes, &connections)
		report.Anomalies = append(report.Anomalies, analyzeNetwork(connections)...)
	}

	report.Anomalies = append(report.Anomalies, analyzeDataExfiltration(c)...)
	report.Anomalies = append(report.Anomalies, analyzeSecurityDisabled(c)...)
	report.Anomalies = append(report.Anomalies, analyzeDeletedBashHistory(c)...)
	report.Anomalies = append(report.Anomalies, analyzeEmptyLogs(c)...)

	systemPath := fmt.Sprintf("%s/system_info.json", c.MainDirectory)
	systemData, _ := readJSONFile(systemPath)
	systemStr := "{}"
	if systemData != nil {
		sysBytes, _ := json.MarshalIndent(systemData, "", "  ")
		systemStr = string(sysBytes)
	}

	kernelPath := fmt.Sprintf("%s/kernel_modules.json", c.MainDirectory)
	kernelData, _ := readJSONFile(kernelPath)
	kernelStr := "[]"
	if kernelData != nil {
		kernelBytes, _ := json.MarshalIndent(kernelData, "", "  ")
		kernelStr = string(kernelBytes)
	}

	report.Timeline = buildTimeline(report.Anomalies, processes, connections)


	htmlContent := buildHTMLString(report, systemStr, processesStr, networksStr, kernelStr)

	htmlPath := fmt.Sprintf("%s/report.html", c.MainDirectory)
	fd, err := unix.Open(htmlPath, unix.O_CREAT|unix.O_WRONLY|unix.O_TRUNC, 0644)
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

func buildHTMLString(report HTMLReport, systemStr, processesStr, networksStr, kernelStr string) string {
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
		anomaliesHTML += fmt.Sprintf("<div>• %s: %s (%s)</div>", title, msg, ts)
	}
	if anomaliesHTML == "" {
		anomaliesHTML = "<div>-</div>"
	}

	var timelineHTML string
	for _, t := range report.Timeline {
		event := t.Event
		ts := t.Timestamp
		if len(ts) > 19 {
			ts = ts[:19]
		}
		timelineHTML += fmt.Sprintf("<div>• %s: %s</div>", ts, event)
	}
	if timelineHTML == "" {
		timelineHTML = "<div>-</div>"
	}

	systemStr = escapeJSON(systemStr)
	processesStr = escapeJSON(processesStr)
	networksStr = escapeJSON(networksStr)
	kernelStr = escapeJSON(kernelStr)

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
        body { background-color: #000000; color: #ffffff; font-family: monospace; padding: 20px; margin: 0; }
        pre { background-color: #111111; color: #00ff00; padding: 15px; overflow-x: auto; white-space: pre-wrap; word-wrap: break-word; font-family: monospace; font-size: 13px; border: none; margin: 0; }
        .section { margin-bottom: 30px; border: 1px solid #333333; }
        .section-title { background-color: #111111; padding: 10px; font-weight: bold; border-bottom: 1px solid #333333; cursor: pointer; user-select: none; }
        .section-title:hover { background-color: #1a1a1a; }
        .section-content { padding: 15px; display: block; }
        .section-content.collapsed { display: none; }
        h1 { font-size: 1.5em; margin-bottom: 20px; color: #00ff00; }
        .info { color: #888888; margin-bottom: 20px; }
        hr { border-color: #333333; }
    </style>
</head>
<body>
<h1>ArtiCol - отчет по сбору артефактов</h1>
<div class="info">Хост: %s | Время: %s</div>
<hr>

<div class="section">
    <div class="section-title" onclick="toggleSection(this)">Аномалии (%d)</div>
    <div class="section-content">%s</div>
</div>

<div class="section">
    <div class="section-title" onclick="toggleSection(this)">Таймлайн</div>
    <div class="section-content">%s</div>
</div>

<div class="section">
    <div class="section-title" onclick="toggleSection(this)">Система</div>
    <div class="section-content"><pre>%s</pre></div>
</div>

<div class="section">
    <div class="section-title" onclick="toggleSection(this)">Процессы</div>
    <div class="section-content"><pre>%s</pre></div>
</div>

<div class="section">
    <div class="section-title" onclick="toggleSection(this)">Сеть</div>
    <div class="section-content"><pre>%s</pre></div>
</div>

<div class="section">
    <div class="section-title" onclick="toggleSection(this)">Модули ядра</div>
    <div class="section-content"><pre>%s</pre></div>
</div>

<script>
function toggleSection(title) {
    var content = title.nextElementSibling;
    content.classList.toggle('collapsed');
}
</script>
</body>
</html>`,
		hostname, startTime,
		len(uniqueAnomalies),
		anomaliesHTML,
		timelineHTML,
		systemStr,
		processesStr,
		networksStr,
		kernelStr,
	)
}

func escapeJSON(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}
