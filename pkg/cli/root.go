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

// Package cli implements the commands for the AOD(Access On Demand) CLI.
package cli

import (
	"context"

	"github.com/abcxyz/access-on-demand/internal/version"
	"github.com/abcxyz/pkg/cli"
)

// rootCmd defines the starting command structure.
var rootCmd = func() cli.Command {
	return &cli.RootCommand{
		Name:    "aod",
		Version: version.HumanVersion,
		Commands: map[string]cli.CommandFactory{
			"iam": func() cli.Command {
				return &cli.RootCommand{
					Name:        "iam",
					Description: "Perform operations related to the IAM request",
					Commands: map[string]cli.CommandFactory{
						"handle": func() cli.Command {
							return &IAMHandleCommand{}
						},
						"validate": func() cli.Command {
							return &IAMValidateCommand{}
						},
					},
				}
			},
			"cli": func() cli.Command {
				return &cli.RootCommand{
					Name:        "cli",
					Description: "Perform operations related to the CLI request",
					Commands: map[string]cli.CommandFactory{
						"do": func() cli.Command {
							return &CLIHandleCommand{}
						},
						"cleanup": func() cli.Command {
							return &CLIHandleCommand{Cleanup: true}
						},
					},
				}
			},
		},
	}
}

// Run executes the CLI.
func Run(ctx context.Context, args []string) error {
	return rootCmd().Run(ctx, args) //nolint:wrapcheck // Want passthrough
}
