package logger

import (
	"log"
	"os"
)

var Debug *bool
var LogFile *string

func PrintDebug(format string, args ...interface{}) {
	if *Debug {
		if *LogFile != "" {
			logFile, err := os.OpenFile(*LogFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
			if err != nil {
				log.Fatalf("Error opening logfile: %v", err)
			}
			defer logFile.Close()
			log.SetOutput(logFile)
		}
		log.Printf(format, args...)
	}
}

func LogFatal(format string, args ...interface{}) {
	PrintDebug(format, args...)
	os.Exit(1)
}
