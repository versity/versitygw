package logger

import "log"

var Debug *bool

func PrintDebug(format string, args ...any) {
	if *Debug {
		log.Printf(format, args...)
	}
}
