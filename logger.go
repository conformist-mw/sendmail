package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"
)

type logLevel int

const (
	levelDebug logLevel = iota
	levelInfo
	levelWarn
	levelError
)

var levelNames = map[string]logLevel{
	"debug":   levelDebug,
	"info":    levelInfo,
	"warn":    levelWarn,
	"warning": levelWarn,
	"error":   levelError,
}

func parseLevel(name string) logLevel {
	if level, ok := levelNames[strings.ToLower(strings.TrimSpace(name))]; ok {
		return level
	}
	return levelInfo
}

type Logger struct {
	out   *log.Logger
	level logLevel
}

func newLogger(w io.Writer, level string) *Logger {
	return &Logger{out: log.New(w, "", log.LstdFlags), level: parseLevel(level)}
}

func (l *Logger) logf(level logLevel, label, format string, args ...interface{}) {
	if l == nil || level < l.level {
		return
	}
	l.out.Printf("%s - %s", label, fmt.Sprintf(format, args...))
}

func (l *Logger) Debugf(format string, args ...interface{}) {
	l.logf(levelDebug, "DEBUG", format, args...)
}

func (l *Logger) Infof(format string, args ...interface{}) {
	l.logf(levelInfo, "INFO", format, args...)
}

func (l *Logger) Warnf(format string, args ...interface{}) {
	l.logf(levelWarn, "WARNING", format, args...)
}

func (l *Logger) Errorf(format string, args ...interface{}) {
	l.logf(levelError, "ERROR", format, args...)
}

// openLogWriter opens the configured log file. A message must never be lost
// because logging is misconfigured, so any failure falls back to stderr.
func openLogWriter(path string) (io.Writer, func(), error) {
	noop := func() {}
	if strings.TrimSpace(path) == "" {
		return os.Stderr, noop, nil
	}
	// The binary runs as whichever user sends mail, so the log has to stay
	// writable by all of them.
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		return os.Stderr, noop, err
	}
	return file, func() { file.Close() }, nil
}
