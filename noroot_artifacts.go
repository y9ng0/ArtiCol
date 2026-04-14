package main

import (
	"fmt"
	"time"

	"github.com/shirou/gopsutil/v4/host"
)

func systemInfo(str *sysInfo, value string) {
	info, err := host.Info()
	str.Title = value
	str.Time = string(time.Now().UTC().Format(time.DateTime))
	if err != nil {
		str.Value = err
	}
	switch value {
	case "uptime":
		str.Value = fmt.Sprintf("%ds", info.Uptime)
	case "hostname":
		str.Value = info.Hostname
	case "kernel":
		str.Value = info.KernelVersion + " " + info.KernelArch
	}
	loggingJson(str)
}
