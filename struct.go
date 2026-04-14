package main

type sysInfo struct {
	Title string `json:"title"`
	Value any    `json:"value"`
	Time  string `json:"time_utc"`
	Hash  string `json:"hash,omitempty"`
}
