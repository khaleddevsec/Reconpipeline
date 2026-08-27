// Package logging provides structured logging for Reconpipeline.
// Normal terminal output is clean and minimal.
// Detailed logs are written to ~/.reconpipeline/logs/ and per-scan logs.
package logging

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

// Level defines the log verbosity level.
type Level int

const (
	LevelQuiet   Level = iota // only essential output
	LevelNormal               // default clean output
	LevelVerbose              // detailed output
	LevelDebug                // deep diagnostic output
)

// Logger is the Reconpipeline structured logger.
type Logger struct {
	level       Level
	noColor     bool
	logFile     *os.File
	scanLogFile *os.File
	writer      io.Writer
	mu          sync.Mutex
}

var defaultLogger = &Logger{
	level:   LevelNormal,
	noColor: false,
	writer:  os.Stdout,
}

var ansiRegex = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

// Init initialises the global logger with the given level and log directory.
func Init(level Level, logDir string) error {
	defaultLogger.mu.Lock()
	defer defaultLogger.mu.Unlock()

	defaultLogger.level = level
	defaultLogger.writer = os.Stdout

	if logDir != "" {
		if err := os.MkdirAll(logDir, 0750); err != nil {
			return fmt.Errorf("failed to create log directory: %w", err)
		}

		logPath := filepath.Join(logDir, fmt.Sprintf("reconpipeline-%s.log", time.Now().Format("2006-01-02")))
		f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
		if err != nil {
			return fmt.Errorf("failed to open log file: %w", err)
		}
		defaultLogger.logFile = f
	}

	return nil
}

// InitScanLog sets up a per-scan dedicated log file (e.g. logs/scan-<id>.log).
func InitScanLog(scanID, logDir string) error {
	defaultLogger.mu.Lock()
	defer defaultLogger.mu.Unlock()

	if logDir == "" || scanID == "" {
		return nil
	}

	if err := os.MkdirAll(logDir, 0750); err != nil {
		return err
	}

	scanLogPath := filepath.Join(logDir, fmt.Sprintf("%s.log", scanID))
	f, err := os.OpenFile(scanLogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		return err
	}
	defaultLogger.scanLogFile = f
	return nil
}

// SetNoColor configures whether ANSI colour sequences should be stripped.
func SetNoColor(noColor bool) {
	defaultLogger.mu.Lock()
	defer defaultLogger.mu.Unlock()
	defaultLogger.noColor = noColor
}

// Close closes all open log files.
func Close() {
	defaultLogger.mu.Lock()
	defer defaultLogger.mu.Unlock()

	if defaultLogger.logFile != nil {
		_ = defaultLogger.logFile.Close()
		defaultLogger.logFile = nil
	}
	if defaultLogger.scanLogFile != nil {
		_ = defaultLogger.scanLogFile.Close()
		defaultLogger.scanLogFile = nil
	}
}

// Info prints an informational message to the terminal (normal+verbose+debug).
func Info(format string, args ...interface{}) {
	if defaultLogger.level >= LevelNormal {
		printToWriter(defaultLogger.writer, format+"\n", args...)
	}
	writeFile("INFO", format, args...)
}

// Verbose prints a detailed message (verbose and debug only).
func Verbose(format string, args ...interface{}) {
	if defaultLogger.level >= LevelVerbose {
		printToWriter(defaultLogger.writer, format+"\n", args...)
	}
	writeFile("VERB", format, args...)
}

// Debug prints a debug message (debug only).
func Debug(format string, args ...interface{}) {
	if defaultLogger.level >= LevelDebug {
		printToWriter(defaultLogger.writer, "[DEBUG] "+format+"\n", args...)
	}
	writeFile("DBUG", format, args...)
}

// Warn prints a warning to the terminal (normal+verbose+debug).
func Warn(format string, args ...interface{}) {
	if defaultLogger.level >= LevelNormal {
		printToWriter(defaultLogger.writer, "WARNING: "+format+"\n", args...)
	}
	writeFile("WARN", format, args...)
}

// Error prints an error to the terminal (all levels).
func Error(format string, args ...interface{}) {
	printToWriter(os.Stderr, "ERROR: "+format+"\n", args...)
	writeFile("ERR ", format, args...)
}

// Quiet prints only in quiet mode (and above).
func Quiet(format string, args ...interface{}) {
	printToWriter(defaultLogger.writer, format+"\n", args...)
	writeFile("QUIT", format, args...)
}

// Print always prints regardless of level.
func Print(format string, args ...interface{}) {
	printToWriter(defaultLogger.writer, format+"\n", args...)
}

// Printf always prints without newline.
func Printf(format string, args ...interface{}) {
	printToWriter(defaultLogger.writer, format, args...)
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

func printToWriter(w io.Writer, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if defaultLogger.noColor {
		msg = StripANSI(msg)
	}
	_, _ = fmt.Fprint(w, msg)
}

// StripANSI removes ANSI escape sequences from strings.
func StripANSI(s string) string {
	return ansiRegex.ReplaceAllString(s, "")
}

func writeFile(prefix, format string, args ...interface{}) {
	defaultLogger.mu.Lock()
	defer defaultLogger.mu.Unlock()

	ts := time.Now().UTC().Format("2006-01-02 15:04:05")
	cleanMsg := StripANSI(fmt.Sprintf(format, args...))
	line := fmt.Sprintf("[%s] [%s] %s\n", ts, prefix, cleanMsg)

	if defaultLogger.logFile != nil {
		_, _ = defaultLogger.logFile.WriteString(line)
	}
	if defaultLogger.scanLogFile != nil {
		_, _ = defaultLogger.scanLogFile.WriteString(line)
	}
}
