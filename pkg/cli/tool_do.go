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

package cli

import (
	"context"
	"fmt"

	"github.com/posener/complete/v2/predict"

	"github.com/abcxyz/access-on-demand/apis/v1alpha1"
	"github.com/abcxyz/access-on-demand/pkg/handler"
	"github.com/abcxyz/access-on-demand/pkg/requestutil"
	"github.com/abcxyz/pkg/cli"
)

var _ cli.Command = (*ToolDoCommand)(nil)

// toolHandler interface that handles ToolRequest.
type toolHandler interface {
	Do(context.Context, *v1alpha1.ToolRequest) error
}

// ToolDoCommand handles tool requests "do" commands.
type ToolDoCommand struct {
	cli.BaseCommand

	flagPath string

	flagVerbose bool

	// testHandler is used for testing only.
	testHandler toolHandler
}

func (c *ToolDoCommand) Desc() string {
	return `Execute the "do" commands in request YAML file at the given path, ` +
		`this command only works where bash is available`
}

func (c *ToolDoCommand) Help() string {
	return `
Usage: {{ COMMAND }} [options]

Execute commands in tool request YAML file at the given path:

      {{ COMMAND }} -path "/path/to/file.yaml"

Execute commands in tool request YAML file at the given path in debug mode:

      {{ COMMAND }} -path "/path/to/file.yaml" -debug

Execute commands in tool request YAML file and output commands executed:

      {{ COMMAND }} -path "/path/to/file.yaml" -verbose
`
}

func (c *ToolDoCommand) Flags() *cli.FlagSet {
	set := c.NewFlagSet()

	// Command options
	f := set.NewSection("COMMAND OPTIONS")

	f.StringVar(&cli.StringVar{
		Name:    "path",
		Target:  &c.flagPath,
		Example: "/path/to/file.yaml",
		Predict: predict.Files("*"),
		Usage:   `The path of tool request file, in YAML format.`,
	})

	f.BoolVar(&cli.BoolVar{
		Name:    "verbose",
		Target:  &c.flagVerbose,
		Default: false,
		Usage:   `Turn on verbose mode to print commands output. Note that outputs may contain sensitive information`,
	})

	return set
}

func (c *ToolDoCommand) Run(ctx context.Context, args []string) error {
	f := c.Flags()
	if err := f.Parse(args); err != nil {
		return fmt.Errorf("failed to parse flags: %w", err)
	}
	args = f.Args()
	if len(args) > 0 {
		return fmt.Errorf("unexpected arguments: %q", args)
	}

	if c.flagPath == "" {
		return fmt.Errorf("path is required")
	}

	// Read request from file path.
	var req v1alpha1.ToolRequest
	if err := requestutil.ReadRequestFromPath(c.flagPath, &req); err != nil {
		return fmt.Errorf("failed to read %T: %w", &req, err)
	}

	if err := v1alpha1.ValidateToolRequest(&req); err != nil {
		return fmt.Errorf("failed to validate %T: %w", &req, err)
	}

	var h toolHandler
	// Use testhandler if it is for testing.
	if c.testHandler != nil {
		h = c.testHandler
	} else {
		opts := []handler.ToolHandlerOption{handler.WithStderr(c.Stderr())}
		if c.flagVerbose {
			printHeader(c.Stdout(), "Tool Commands Output")
			opts = append(opts, handler.WithStdout(c.Stdout()))
		}
		h = handler.NewToolHandler(ctx, opts...)
	}

	if err := h.Do(ctx, &req); err != nil {
		return fmt.Errorf(`failed to run "do" commands: %w`, err)
	}

	if err := c.output(req.Do, req.Tool); err != nil {
		return fmt.Errorf("failed to print outputs: %w", err)
	}

	return nil
}

func (c *ToolDoCommand) output(subcmds []string, tool string) error {
	printHeader(c.Stdout(), "Successfully Completed Commands")
	cmds := make([]string, 0, len(subcmds))
	for _, sub := range subcmds {
		cmds = append(cmds, fmt.Sprintf("%s %s", tool, sub))
	}
	if err := encodeYaml(c.Stdout(), cmds); err != nil {
		return fmt.Errorf("failed to output executed commands: %w", err)
	}
	return nil
}
