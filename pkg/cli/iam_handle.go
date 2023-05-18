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
	"os"
	"time"

	"github.com/abcxyz/access-on-demand/apis/v1alpha1"
	"github.com/abcxyz/access-on-demand/pkg/handler"
	"github.com/abcxyz/pkg/cli"
	"gopkg.in/yaml.v3"

	resourcemanager "cloud.google.com/go/resourcemanager/apiv3"
)

var _ cli.Command = (*IAMHandleCommand)(nil)

// Handler interface that handles the IAMRequestWrapper.
type Handler interface {
	Do(context.Context, *v1alpha1.IAMRequestWrapper) ([]*v1alpha1.IAMResponse, error)
}

// IAMHandleCommand handles IAM requests.
type IAMHandleCommand struct {
	cli.BaseCommand

	flagPath string

	flagDuration time.Duration

	// testHandler is used for testing only.
	testHandler Handler
}

func (c *IAMHandleCommand) Desc() string {
	return `Handle the IAM request YAML file in the given path`
}

func (c *IAMHandleCommand) Help() string {
	return `
Usage: {{ COMMAND }} [options]

Handle the IAM request YAML file in the given path:

      aod iam handle -path "/path/to/file" -duration "2h"
`
}

func (c *IAMHandleCommand) Flags() *cli.FlagSet {
	set := cli.NewFlagSet()

	// Command options
	f := set.NewSection("COMMAND OPTIONS")

	f.StringVar(&cli.StringVar{
		Name:    "path",
		Target:  &c.flagPath,
		Example: "/path/to/file",
		Usage:   `The path of IAM request file.`,
	})

	f.DurationVar(&cli.DurationVar{
		Name:    "duration",
		Target:  &c.flagDuration,
		Example: "2h",
		Usage:   `The IAM permission lifecycle, as a duration.`,
	})

	return set
}

func (c *IAMHandleCommand) Run(ctx context.Context, args []string) error {
	f := c.Flags()
	if err := f.Parse(args); err != nil {
		return fmt.Errorf("failed to parse flags: %w", err)
	}
	args = f.Args()
	if len(args) > 0 {
		return fmt.Errorf("unexpected arguments: %v", args)
	}

	if c.flagPath == "" {
		return fmt.Errorf("path is required")
	}

	if c.flagDuration <= 0 {
		return fmt.Errorf("a positive duration is required")
	}

	return c.handleIAM(ctx)
}

func (c *IAMHandleCommand) handleIAM(ctx context.Context) error {
	// Unmarshal the YAML file to IAMRequest
	data, err := os.ReadFile(c.flagPath)
	if err != nil {
		return fmt.Errorf("failed to read file from %q, %w", c.flagPath, err)
	}
	var req *v1alpha1.IAMRequest
	if err := yaml.Unmarshal(data, &req); err != nil {
		return fmt.Errorf("failed to unmarshal yaml to IAMRequest: %w", err)
	}

	var h Handler
	if c.testHandler != nil {
		// Use testHandler is it is for testing.
		h = c.testHandler
	} else {
		// Create resource manager clients.
		organizationsClient, err := resourcemanager.NewOrganizationsClient(ctx)
		if err != nil {
			return fmt.Errorf("failed to create organizations client: %w", err)
		}
		defer organizationsClient.Close()

		foldersClient, err := resourcemanager.NewFoldersClient(ctx)
		if err != nil {
			return fmt.Errorf("failed to create folders client: %w", err)
		}
		defer foldersClient.Close()

		projectsClient, err := resourcemanager.NewProjectsClient(ctx)
		if err != nil {
			return fmt.Errorf("failed to create projects client: %w", err)
		}
		defer projectsClient.Close()

		// Create IAMHandler with the clients.
		h, err = handler.NewIAMHandler(
			ctx,
			organizationsClient,
			foldersClient,
			projectsClient,
		)
		if err != nil {
			return fmt.Errorf("failed to create IAM handler: %w", err)
		}
	}

	// Wrap IAMRequest to include Duration.
	reqWrapper := &v1alpha1.IAMRequestWrapper{
		IAMRequest: req,
		Duration:   c.flagDuration,
	}
	if _, err := h.Do(ctx, reqWrapper); err != nil {
		return fmt.Errorf("failed to handle IAM request: %w", err)
	}
	c.Outf("Successfully handled IAM request")

	return nil
}
