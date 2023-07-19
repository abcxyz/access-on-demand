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
)

var _ cli.Command = (*ToolHandleCommand)(nil)

// ToolHandleCommand handles tool requests.
type ToolHandleCommand struct {
	cli.BaseCommand

	flagPath string

	flagDebug bool

	// Run Cleanup instead of Do if true.
	Cleanup bool

	// testTool is used for testing only.
	testTool string
}

func (c *ToolHandleCommand) Desc() string {
	return `Handle the tool request YAML file at the given path`
}

func (c *ToolHandleCommand) Help() string {
	return `
Usage: {{ COMMAND }} [options]

Handle tool request YAML file at the given path:

      {{ COMMAND }} -path "/path/to/file.yaml"

Handle tool request YAML file at the given path in debug mode:

      {{ COMMAND }} -path "/path/to/file.yaml" -debug
`
}

func (c *ToolHandleCommand) Flags() *cli.FlagSet {
	set := cli.NewFlagSet()

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

	return set
}

func (c *ToolHandleCommand) Run(ctx context.Context, args []string) error {
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

	return c.handle(ctx)
}

func (c *ToolHandleCommand) handle(ctx context.Context) error {
	// Read request from file path.
	var req v1alpha1.ToolRequest
	if err := requestutil.ReadRequestFromPath(c.flagPath, &req); err != nil {
		return fmt.Errorf("failed to read %T: %w", &req, err)
	}

	if err := v1alpha1.ValidateToolRequest(&req); err != nil {
		return fmt.Errorf("failed to validate %T: %w", &req, err)
	}

	opts := []handler.ToolHandlerOption{handler.WithStderr(c.Stderr())}
	if c.flagDebug {
		opts = append(opts, handler.WithDebugMode(c.Stdout()))
	}
	h := handler.NewToolHandler(ctx, opts...)

	// Use testTool if it is for testing.
	if c.testTool != "" {
		req.Tool = c.testTool
	}
	var err error
	if c.Cleanup {
		err = h.Cleanup(ctx, &req)
	} else {
		err = h.Do(ctx, &req)
	}
	if err != nil {
		return fmt.Errorf(`failed to run commands: %w`, err)
	}
	c.Outf(`Successfully completed commands`)

	return nil
}
