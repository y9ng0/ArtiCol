package main

func mainArtifacts(c *Collector, json_info []Info, flag bool) []Info {

	// Информация о системе
	infoSys := Info{}
	systemInfo(c, &infoSys)
	json_info = append(json_info, infoSys)

	// Информация о модулях ядра
	infoSys = Info{}
	getKernelModules(c, &infoSys)
	json_info = append(json_info, infoSys)

	// Сбор системных логов
	infoSys = Info{}
	getSystemLogs(c, &infoSys)
	json_info = append(json_info, infoSys)

	// Информация о процессах
	infoSys = Info{}
	getPids(c, &infoSys, flag)
	json_info = append(json_info, infoSys)

	// Информация о TCP/UDP(V4/v6) соединениях
	json_info = getAllConnections(c, json_info)

	// Копирование файла passwd
	infoSys = Info{}
	getPasswd(c, &infoSys)
	json_info = append(json_info, infoSys)

	// Копирование файла shadow
	infoSys = Info{}
	getShadow(c, &infoSys, flag)
	json_info = append(json_info, infoSys)

	// Копирование bash_history
	infoSys = Info{}
	getHomeDir(c, &infoSys, flag)
	json_info = append(json_info, infoSys)

	// Копирование systemd sessions
	infoSys = Info{}
	getSessions(c, &infoSys)
	json_info = append(json_info, infoSys)

	return json_info
}
