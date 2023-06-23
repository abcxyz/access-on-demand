// Copyright 2023 The Authors (see AUTHORS file)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// handler package that handles AOD request.
package handler

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/abcxyz/access-on-demand/apis/v1alpha1"
)

// CLIHandler runs cli commands in the CLIRequest.
type CLIHandler struct {
	// By default, stdout discards the command outputs, stderr is os.Stderr.
	stdout, stderr io.Writer
}

// CLIHandlerOption is the option to set up an CLIHandler.
type CLIHandlerOption func(h *CLIHandler) *CLIHandler

// WithStderr sets the handler's stderr.
func WithStderr(w io.Writer) CLIHandlerOption {
	return func(h *CLIHandler) *CLIHandler {
		h.stderr = w
		return h
	}
}

// WithDebugMode sets the handler's stdout to w.
func WithDebugMode(w io.Writer) CLIHandlerOption {
	return func(h *CLIHandler) *CLIHandler {
		h.stdout = w
		return h
	}
}

// WithDefaultDebugMode sets the handler's stdout to os.Stdout.
func WithDefaultDebugMode() CLIHandlerOption {
	return func(h *CLIHandler) *CLIHandler {
		h.stdout = os.Stdout
		return h
	}
}

// NewCLIHandler creates a new CLIHandler with provided options.
func NewCLIHandler(ctx context.Context, opts ...CLIHandlerOption) *CLIHandler {
	// Set default stderr.
	h := &CLIHandler{stderr: os.Stderr}
	for _, opt := range opts {
		h = opt(h)
	}
	return h
}

// Do runs the do commands.
func (h *CLIHandler) Do(ctx context.Context, r *v1alpha1.CLIRequest) error {
	return h.run(r.CLI, r.Do)
}

// Cleanup runs the cleanup commands.
func (h *CLIHandler) Cleanup(ctx context.Context, r *v1alpha1.CLIRequest) error {
	return h.run(r.CLI, r.Cleanup)
}

func (h *CLIHandler) run(cli string, cmds []string) error {
	for _, c := range cmds {
		cmd := exec.Command(cli, c)
		// If stdout is set, debug mode is on and it writes the command output to
		// stdout.
		if h.stdout != nil {
			cmd.Stdout = h.stdout
		}
		cmd.Stderr = h.stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to run command %q, error %w", c, err)
		}
	}
	return nil
}
