package main

type sysInfo struct {
	Title string `json:"title"`
	Value any    `json:"value"`
	Time  string `json:"utc_time"`
	Hash  string `json:"hash,omitempty"`
}
