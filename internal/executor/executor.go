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

	"github.com/khaleddevsec/Reconpipeline/internal/logging"
	"github.com/khaleddevsec/Reconpipeline/internal/workspace"
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
	// Timeout sets a per-command execution deadline.
	Timeout time.Duration
	// MaxRetries is the number of retries on transient errors.
	MaxRetries int
}

// Run executes a binary with the given arguments using exec.CommandContext.
// The binary path must be an absolute path from the managed tools directory.
// Arguments are passed as-is — no shell interpolation occurs.
func Run(ctx context.Context, binaryPath string, args []string, opts Options) Result {
	if binaryPath == "" {
		return Result{ExitCode: -1, Error: fmt.Errorf("binary path cannot be empty")}
	}

	execCtx := ctx
	var cancel context.CancelFunc
	if opts.Timeout > 0 {
		execCtx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}

	logging.Verbose("Executing: %s %v", binaryPath, args)

	cmd := exec.CommandContext(execCtx, binaryPath, args...)

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
		if execCtx.Err() != nil {
			// Context cancelled or timed out
			return Result{ExitCode: -1, Duration: dur, Error: execCtx.Err()}
		}
		if exitErr, ok := err.(*exec.ExitError); ok {
			return Result{ExitCode: exitErr.ExitCode(), Duration: dur, Error: err}
		}
		return Result{ExitCode: -1, Duration: dur, Error: err}
	}

	return Result{ExitCode: 0, Duration: dur}
}

// RunWithRetry executes a command, retrying up to maxRetries on transient errors.
func RunWithRetry(ctx context.Context, binaryPath string, args []string, opts Options) Result {
	maxRetries := opts.MaxRetries
	if maxRetries <= 0 {
		maxRetries = 1
	}

	var res Result
	backoff := 500 * time.Millisecond

	for attempt := 1; attempt <= maxRetries; attempt++ {
		select {
		case <-ctx.Done():
			return Result{ExitCode: -1, Error: ctx.Err()}
		default:
		}

		res = Run(ctx, binaryPath, args, opts)
		if res.ExitCode == 0 || ctx.Err() != nil {
			return res
		}

		if attempt < maxRetries {
			logging.Verbose("Command failed (attempt %d/%d), retrying in %s: %v", attempt, maxRetries, backoff, res.Error)
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return Result{ExitCode: -1, Error: ctx.Err()}
			}
			backoff *= 2
		}
	}

	return res
}

// RunToFile executes a binary and writes stdout to outPath using atomic file writing.
func RunToFile(ctx context.Context, binaryPath string, args []string, outPath string) Result {
	dir := os.TempDir()
	tmpFile, err := os.CreateTemp(dir, "reconpipe-out-*")
	if err != nil {
		return Result{ExitCode: -1, Error: fmt.Errorf("failed to create temporary file for %s: %w", outPath, err)}
	}
	tmpName := tmpFile.Name()
	defer func() {
		_ = tmpFile.Close()
		_ = os.Remove(tmpName)
	}()

	res := Run(ctx, binaryPath, args, Options{
		Stdout: tmpFile,
		Stderr: io.Discard,
	})

	_ = tmpFile.Sync()
	_ = tmpFile.Close()

	if res.ExitCode == 0 && res.Error == nil {
		if data, readErr := os.ReadFile(tmpName); readErr == nil && len(data) > 0 {
			_ = workspace.WriteFileAtomic(outPath, data, 0640)
		}
	}

	return res
}
