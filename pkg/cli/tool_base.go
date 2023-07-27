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

	"github.com/abcxyz/access-on-demand/apis/v1alpha1"
	"github.com/abcxyz/access-on-demand/pkg/handler"
	"github.com/abcxyz/access-on-demand/pkg/requestutil"
	"github.com/abcxyz/pkg/cli"
	"github.com/posener/complete/v2/predict"
	"gopkg.in/yaml.v3"
)

// toolHandler interface that handles ToolRequest.
type toolHandler interface {
	Do(context.Context, *v1alpha1.ToolRequest) error
	Cleanup(context.Context, *v1alpha1.ToolRequest) error
}

// ToolBaseCommand is the base command for handling tool requests.
type ToolBaseCommand struct {
	cli.BaseCommand

	flagPath string

	flagDebug bool

	flagVerbose bool

	// testHandler is used for testing only.
	testHandler toolHandler
}

func (c *ToolBaseCommand) Help() string {
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

func (c *ToolBaseCommand) Flags() *cli.FlagSet {
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
		Name:    "debug",
		Target:  &c.flagDebug,
		Default: false,
		Usage:   `Turn on debug mode to print command outputs.`,
	})

	f.BoolVar(&cli.BoolVar{
		Name:    "verbose",
		Target:  &c.flagVerbose,
		Default: false,
		Usage:   `Turn on verbose mode to print commands executed.`,
	})

	return set
}

func (c *ToolBaseCommand) setup(ctx context.Context, args []string) (*v1alpha1.ToolRequest, toolHandler, error) {
	f := c.Flags()
	if err := f.Parse(args); err != nil {
		return nil, nil, fmt.Errorf("failed to parse flags: %w", err)
	}
	args = f.Args()
	if len(args) > 0 {
		return nil, nil, fmt.Errorf("unexpected arguments: %q", args)
	}

	if c.flagPath == "" {
		return nil, nil, fmt.Errorf("path is required")
	}

	// Read request from file path.
	var req v1alpha1.ToolRequest
	if err := requestutil.ReadRequestFromPath(c.flagPath, &req); err != nil {
		return nil, nil, fmt.Errorf("failed to read %T: %w", &req, err)
	}

	if err := v1alpha1.ValidateToolRequest(&req); err != nil {
		return nil, nil, fmt.Errorf("failed to validate %T: %w", &req, err)
	}

	var h toolHandler
	// Use testhandler if it is for testing.
	if c.testHandler != nil {
		h = c.testHandler
	} else {
		opts := []handler.ToolHandlerOption{handler.WithStderr(c.Stderr())}
		if c.flagDebug {
			opts = append(opts, handler.WithDebugMode(c.Stdout()))
		}
		h = handler.NewToolHandler(ctx, opts...)
	}

	return &req, h, nil
}

func (c *ToolBaseCommand) output(subcmds []string, tool string) error {
	if c.flagVerbose {
		var cmds []string
		for _, sub := range subcmds {
			cmds = append(cmds, fmt.Sprintf("%s %s", tool, sub))
		}
		enc := yaml.NewEncoder(c.Stdout())
		enc.SetIndent(2)
		if err := enc.Encode(cmds); err != nil {
			return fmt.Errorf("failed to encode to yaml: %w", err)
		}

		if err := enc.Close(); err != nil {
			return fmt.Errorf("failed to close yaml encoder: %w", err)
		}
	} else {
		c.Outf(`Successfully completed commands`)
	}
	return nil
}
