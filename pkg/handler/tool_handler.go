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

// ToolHandler runs tool commands in the ToolRequest.
type ToolHandler struct {
	// By default, stdout discards the command outputs, stderr is os.Stderr.
	stdout, stderr io.Writer
}

// ToolHandlerOption is the option to set up an ToolHandler.
type ToolHandlerOption func(h *ToolHandler) *ToolHandler

// WithStderr sets the handler's stderr.
func WithStderr(w io.Writer) ToolHandlerOption {
	return func(h *ToolHandler) *ToolHandler {
		h.stderr = w
		return h
	}
}

// WithDebugMode sets the handler's stdout to w.
func WithDebugMode(w io.Writer) ToolHandlerOption {
	return func(h *ToolHandler) *ToolHandler {
		h.stdout = w
		return h
	}
}

// WithDefaultDebugMode sets the handler's stdout to os.Stdout.
func WithDefaultDebugMode() ToolHandlerOption {
	return func(h *ToolHandler) *ToolHandler {
		h.stdout = os.Stdout
		return h
	}
}

// NewToolHandler creates a new ToolHandler with provided options.
func NewToolHandler(ctx context.Context, opts ...ToolHandlerOption) *ToolHandler {
	// Set default stderr.
	h := &ToolHandler{stderr: os.Stderr}
	for _, opt := range opts {
		h = opt(h)
	}
	return h
}

// Do runs the do commands.
func (h *ToolHandler) Do(ctx context.Context, r *v1alpha1.ToolRequest) error {
	return h.run(r.Tool, r.Do)
}

// Cleanup runs the cleanup commands.
func (h *ToolHandler) Cleanup(ctx context.Context, r *v1alpha1.ToolRequest) error {
	return h.run(r.Tool, r.Cleanup)
}

func (h *ToolHandler) run(tool string, cmds []string) error {
	for _, c := range cmds {
		cmd := exec.Command(tool, c)
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