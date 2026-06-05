// mainArtifacts.go - обновленная версия
package main

func mainArtifacts(c *Collector, json_info []Info, flag bool) []Info {

	// Информация о процессах
	infoSys := Info{}
	getPids(c, &infoSys, flag)
	json_info = append(json_info, infoSys)

	// Информация о TCP/UDP(V4/v6) соединениях
	json_info = getAllConnections(c, json_info)

	// Копирование таблицы маршрутизации
	infoSys = Info{}
	getRoute(c, &infoSys)
	json_info = append(json_info, infoSys)

	// Копирование таблицы ARP
	infoSys = Info{}
	getArp(c, &infoSys)
	json_info = append(json_info, infoSys)

	// Копирование временных директорий (/tmp, /dev/shm, /var/tmp)
	json_info = getTempDirs(c, json_info)

	// Копирование systemd sessions
	infoSys = Info{}
	getSessions(c, &infoSys)
	json_info = append(json_info, infoSys)

	// Информация о системе
	infoSys = Info{}
	systemInfo(c, &infoSys)
	json_info = append(json_info, infoSys)

	// Информация о модулях ядра
	infoSys = Info{}
	getKernelModules(c, &infoSys)
	json_info = append(json_info, infoSys)

	// Копирование bash_history и zsh_history
	infoSys = Info{}
	getHomeDir(c, &infoSys, flag)
	json_info = append(json_info, infoSys)

	// Копирование файла passwd
	infoSys = Info{}
	getPasswd(c, &infoSys)
	json_info = append(json_info, infoSys)

	// Копирование файла shadow
	infoSys = Info{}
	getShadow(c, &infoSys, flag)
	json_info = append(json_info, infoSys)

	// Копирование файла group
	infoSys = Info{}
	getGroup(c, &infoSys)
	json_info = append(json_info, infoSys)

	// Копирование файла sudoers
	infoSys = Info{}
	getSudoers(c, &infoSys, flag)
	json_info = append(json_info, infoSys)

	// Копирование /etc/sudoers.d/
	infoSys = Info{}
	getSudoersD(c, &infoSys, flag)
	json_info = append(json_info, infoSys)

	// Копирование конфигураций DNS (hosts, resolv.conf)
	json_info = getDnsConfigs(c, json_info)

	// Копирование сетевых конфигураций (ufw, iptables, ssh)
	json_info = getNetworkConfigs(c, json_info)

	// Копирование файлов автозапуска (rc.local, crontab)
	json_info = getAutorunConfigs(c, json_info)

	// Копирование cron-директорий и systemd-юнитов
	json_info = getAutorunDirs(c, json_info)

	// Сбор системных логов
	infoSys = Info{}
	getSystemLogs(c, &infoSys)
	json_info = append(json_info, infoSys)

	// Генерация HTML отчета
	json_info = createHtmlReport(c, json_info)

	return json_info
}
