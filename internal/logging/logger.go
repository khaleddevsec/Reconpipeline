// Package logging provides structured logging for Reconpipeline.
// Normal terminal output is clean and minimal.
// Detailed logs are written to ~/.reconpipeline/logs/.
package logging

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// Level defines the log verbosity level.
type Level int

const (
	LevelQuiet   Level = iota // only essential output
	LevelNormal               // default clean output
	LevelVerbose              // detailed output
)

// Logger is the Reconpipeline structured logger.
type Logger struct {
	level   Level
	logFile *os.File
	writer  io.Writer
}

var defaultLogger = &Logger{
	level:  LevelNormal,
	writer: os.Stdout,
}

// Init initialises the global logger with the given level and log directory.
func Init(level Level, logDir string) error {
	defaultLogger.level = level
	defaultLogger.writer = os.Stdout

	if err := os.MkdirAll(logDir, 0750); err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}

	logPath := filepath.Join(logDir, fmt.Sprintf("reconpipeline-%s.log", time.Now().Format("2006-01-02")))
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}
	defaultLogger.logFile = f
	return nil
}

// Close closes the log file if open.
func Close() {
	if defaultLogger.logFile != nil {
		_ = defaultLogger.logFile.Close()
	}
}

// Info prints an informational message to the terminal (normal+verbose).
func Info(format string, args ...interface{}) {
	if defaultLogger.level >= LevelNormal {
		fmt.Fprintf(defaultLogger.writer, format+"\n", args...)
	}
	writeFile("INFO", format, args...)
}

// Verbose prints a detailed message (verbose only).
func Verbose(format string, args ...interface{}) {
	if defaultLogger.level >= LevelVerbose {
		fmt.Fprintf(defaultLogger.writer, format+"\n", args...)
	}
	writeFile("VERB", format, args...)
}

// Warn prints a warning to the terminal (normal+verbose).
func Warn(format string, args ...interface{}) {
	if defaultLogger.level >= LevelNormal {
		fmt.Fprintf(defaultLogger.writer, "WARNING: "+format+"\n", args...)
	}
	writeFile("WARN", format, args...)
}

// Error prints an error to the terminal (all levels).
func Error(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "ERROR: "+format+"\n", args...)
	writeFile("ERR ", format, args...)
}

// Quiet prints only in quiet mode (and above).
func Quiet(format string, args ...interface{}) {
	fmt.Fprintf(defaultLogger.writer, format+"\n", args...)
	writeFile("QUIT", format, args...)
}

// Print always prints regardless of level.
func Print(format string, args ...interface{}) {
	fmt.Fprintf(defaultLogger.writer, format+"\n", args...)
}

// Printf always prints without newline.
func Printf(format string, args ...interface{}) {
	fmt.Fprintf(defaultLogger.writer, format, args...)
}

// IsVerbose returns true if verbose logging is enabled.
func IsVerbose() bool {
	return defaultLogger.level >= LevelVerbose
}

// IsQuiet returns true if quiet mode is active.
func IsQuiet() bool {
	return defaultLogger.level == LevelQuiet
}

// GetLevel returns the current log level.
func GetLevel() Level {
	return defaultLogger.level
}

func writeFile(prefix, format string, args ...interface{}) {
	if defaultLogger.logFile == nil {
		return
	}
	ts := time.Now().Format("2006-01-02 15:04:05")
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(defaultLogger.logFile, "[%s] [%s] %s\n", ts, prefix, msg)
}
