package main

type Info struct {
	Title any `json:"title"`          // Говорящее название
	Value any `json:"value"`          // Тут может быть какое-то значение или путь к файлу
	Time  any `json:"utc_time"`       // Время сбора информации по UTC
	Hash  any `json:"hash,omitempty"` // Вычисленный хэш (если не нужно будет, то можно и удалить)
}

type sysInfo struct {
	NameInfo any `json:"title"`
	Value    any `json:"value"`
}

type processesId struct {
	Pid            any `json:"pid"`
	Uids           any `json:"uids"`
	Name           any `json:"title"`
	Status         any `json:"status"`
	Memory         any `json:"ram"`    // Количество Мегабайт, округление до 2 знаков после запятой
	Uptime         any `json:"uptime"` // Количество секунд, округление до 3 знаков после запятой
	User           any `json:"user"`
	Location       any `json:"location,omitempty"`
	FileDescriptor any `json:"fd,omitempty"`
}

type networks struct {
	Pid          any `json:"pid"`
	RemoteAddr   any `json:"remoteaddr"`
	LocalAddress any `json:"localaddr"`
	Type         any `json:"type"`
	Status       any `json:"status"`
}

type kernelModule struct {
	Name   any `json:"name"`
	Size   any `json:"size"`
	UsedBy any `json:"usedby"`
	RefCnt any `json:"refcnt"`
}

type Collector struct {
	LogFile       int
	JsonFile      int
	MainDirectory string
	UserName      string
}
