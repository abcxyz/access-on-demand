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
	"github.com/abcxyz/access-on-demand/pkg/requestutil"
	"github.com/abcxyz/pkg/cli"
	"github.com/posener/complete/v2/predict"
)

var _ cli.Command = (*IAMValidateCommand)(nil)

// IAMValidateCommand validates IAM requests.
type IAMValidateCommand struct {
	cli.BaseCommand

	flagPath string
}

func (c *IAMValidateCommand) Desc() string {
	return `Validate the IAM request YAML file at the given path`
}

func (c *IAMValidateCommand) Help() string {
	return `
Usage: {{ COMMAND }} [options]

Validate the IAM request YAML file at the given path:

      aod iam validate -path "/path/to/file.yaml"
`
}

func (c *IAMValidateCommand) Flags() *cli.FlagSet {
	set := cli.NewFlagSet()

	// Command options
	f := set.NewSection("COMMAND OPTIONS")

	f.StringVar(&cli.StringVar{
		Name:    "path",
		Target:  &c.flagPath,
		Example: "/path/to/file.yaml",
		Predict: predict.Files("*"),
		Usage:   `The path of IAM request file, in YAML format.`,
	})

	return set
}

func (c *IAMValidateCommand) Run(ctx context.Context, args []string) error {
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

	return c.validate(ctx)
}

func (c *IAMValidateCommand) validate(ctx context.Context) error {
	// Read request from YAML file.
	var req v1alpha1.IAMRequest
	if err := requestutil.ReadRequestFromPath(c.flagPath, &req); err != nil {
		return fmt.Errorf("failed to read %T: %w", &req, err)
	}

	if err := v1alpha1.ValidateIAMRequest(&req); err != nil {
		return fmt.Errorf("failed to validate %T: %w", &req, err)
	}
	c.Outf("Successfully validated IAM request")

	return nil
}
