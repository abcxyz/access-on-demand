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

	"github.com/abcxyz/pkg/cli"
)

var _ cli.Command = (*ToolCleanupCommand)(nil)

// ToolCleanupCommand handles tool requests "cleanup" commands.
type ToolCleanupCommand struct {
	ToolBaseCommand
}

func (c *ToolCleanupCommand) Desc() string {
	return `Handle the "cleanup" commands in request YAML file at the given path`
}

func (c *ToolCleanupCommand) Help() string {
	return `
Usage: {{ COMMAND }} [options]

Handle the "cleanup" commands in tool request YAML file at the given path:

      {{ COMMAND }} -path "/path/to/file.yaml"

Handle the "cleanup" commands in tool request YAML file at the given path in debug mode:

      {{ COMMAND }} -path "/path/to/file.yaml" -debug
`
}

func (c *ToolCleanupCommand) Run(ctx context.Context, args []string) error {
	req, h, err := c.setup(ctx, args)
	if err != nil {
		return fmt.Errorf("failed to setup command: %w", err)
	}

	if err := h.Cleanup(ctx, req); err != nil {
		return fmt.Errorf(`failed to run "cleanup" commands: %w`, err)
	}
	c.Outf(`Successfully completed commands`)

	return nil
}
