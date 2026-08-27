// Package executor provides safe subprocess execution for Reconpipeline.
// All child processes are launched via exec.CommandContext — never via sh -c
// with user-supplied input.
package executor

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"

	"github.com/frozeniceee/Reconpipeline/internal/logging"
)

// Result holds the outcome of a subprocess execution.
type Result struct {
	// ExitCode is the process exit code. 0 = success.
	ExitCode int
	// Duration is how long the process ran.
	Duration time.Duration
	// Error is set if the process could not be started or was killed.
	Error error
}

// Options configures subprocess execution.
type Options struct {
	// Stdout is where process stdout is written. Nil = discard.
	Stdout io.Writer
	// Stderr is where process stderr is written. Nil = discard.
	Stderr io.Writer
	// Env is additional environment variables (KEY=VALUE format).
	Env []string
	// WorkDir is the working directory for the subprocess.
	WorkDir string
}

// Run executes a binary with the given arguments using exec.CommandContext.
// The binary path must be an absolute path from the managed tools directory.
// Arguments are passed as-is — no shell interpolation occurs.
func Run(ctx context.Context, binaryPath string, args []string, opts Options) Result {
	if binaryPath == "" {
		return Result{ExitCode: -1, Error: fmt.Errorf("binary path cannot be empty")}
	}

	logging.Verbose("Executing: %s %v", binaryPath, args)

	cmd := exec.CommandContext(ctx, binaryPath, args...)

	if opts.Stdout != nil {
		cmd.Stdout = opts.Stdout
	} else {
		cmd.Stdout = io.Discard
	}

	if opts.Stderr != nil {
		cmd.Stderr = opts.Stderr
	} else {
		cmd.Stderr = io.Discard
	}

	if len(opts.Env) > 0 {
		cmd.Env = append(os.Environ(), opts.Env...)
	}

	if opts.WorkDir != "" {
		cmd.Dir = opts.WorkDir
	}

	start := time.Now()
	err := cmd.Run()
	dur := time.Since(start)

	if err != nil {
		if ctx.Err() != nil {
			// Context cancelled — this is expected.
			return Result{ExitCode: -1, Duration: dur, Error: ctx.Err()}
		}
		if exitErr, ok := err.(*exec.ExitError); ok {
			return Result{ExitCode: exitErr.ExitCode(), Duration: dur, Error: err}
		}
		return Result{ExitCode: -1, Duration: dur, Error: err}
	}

	return Result{ExitCode: 0, Duration: dur}
}

// RunToFile executes a binary and writes stdout to outPath.
// stderr is written to the log.
func RunToFile(ctx context.Context, binaryPath string, args []string, outPath string) Result {
	outFile, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0640)
	if err != nil {
		return Result{ExitCode: -1, Error: fmt.Errorf("failed to open output file %q: %w", outPath, err)}
	}
	defer outFile.Close()

	return Run(ctx, binaryPath, args, Options{
		Stdout: outFile,
		Stderr: io.Discard,
	})
}
