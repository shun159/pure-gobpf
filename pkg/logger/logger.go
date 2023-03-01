package logger

import (
	"fmt"
	"os"

	logrus "github.com/sirupsen/logrus"
)

type Logger struct {
	*logrus.Logger
}

const (
	defaultLogFilePath = "/var/log/aws-routed-eni/ebpf-sdk.log"
	envLogFilePath     = "AWS_EBPF_SDK_LOG_FILE"
)

var log *Logger

func Get() *Logger {
	if log == nil {
		log = New()
	}
	return log
}

func New() *Logger {
	logFile := GetLogLocation()
	f := os.Stdout
	var err error
	if logFile != "stdout" {
		f, err = os.OpenFile(logFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
		if err != nil {
			fmt.Println("Failed to create logfile" + logFile)
			panic(err)
		}
	}

	var baseLogger = logrus.New()
	var standardLogger = &Logger{baseLogger}
	standardLogger.Formatter = &logrus.JSONFormatter{}

	standardLogger.SetOutput(f)
	standardLogger.Info("Constructed new logger instance")
	return standardLogger
}

func GetLogLocation() string {
	logFilePath := os.Getenv(envLogFilePath)
	if logFilePath == "" {
		logFilePath = defaultLogFilePath
	}
	return logFilePath
}
