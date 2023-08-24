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

	resourcemanager "cloud.google.com/go/resourcemanager/apiv3"
)

var _ cli.Command = (*IAMCleanupCommand)(nil)

// iamCleanupHandler interface that handles the cleanup of IAMRequest.
type iamCleanupHandler interface {
	Cleanup(context.Context, *v1alpha1.IAMRequest) ([]*v1alpha1.IAMResponse, error)
}

// IAMCleanupCommand handles the cleanup of IAM requests, which removed the
// requested bindings and expires AOD bindings from IAM policy.
type IAMCleanupCommand struct {
	cli.BaseCommand

	flagPath string

	flagVerbose bool

	// testHandler is used for testing only.
	testHandler iamCleanupHandler
}

func (c *IAMCleanupCommand) Desc() string {
	return `Cleanup of the IAM request YAML file in the given path, which ` +
		`removes bindings in the request and expired AOD bindings from the IAM policy`
}

func (c *IAMCleanupCommand) Help() string {
	return `
Usage: {{ COMMAND }} [options]

Cleanup of the IAM request YAML file in the given path:

      {{ COMMAND }} -path "/path/to/file.yaml"

Cleanup of the IAM request YAML file and output applied IAM changes:

      {{ COMMAND }} -path "/path/to/file.yaml" -verbose
`
}

func (c *IAMCleanupCommand) Flags() *cli.FlagSet {
	set := c.NewFlagSet()

	// Command options
	f := set.NewSection("COMMAND OPTIONS")

	f.StringVar(&cli.StringVar{
		Name:    "path",
		Target:  &c.flagPath,
		Example: "/path/to/file.yaml",
		Predict: predict.Files("*"),
		Usage:   `The path of IAM request file, in YAML format.`,
	})

	f.BoolVar(&cli.BoolVar{
		Name:    "verbose",
		Target:  &c.flagVerbose,
		Default: false,
		Usage:   `Turn on verbose mode to print updated IAM policies. Note that it may contain sensitive information`,
	})

	return set
}

func (c *IAMCleanupCommand) Run(ctx context.Context, args []string) error {
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

	return c.cleanupIAM(ctx)
}

func (c *IAMCleanupCommand) cleanupIAM(ctx context.Context) error {
	// Read request from file path.
	var req v1alpha1.IAMRequest
	if err := requestutil.ReadRequestFromPath(c.flagPath, &req); err != nil {
		return fmt.Errorf("failed to read %T: %w", &req, err)
	}

	if err := v1alpha1.ValidateIAMRequest(&req); err != nil {
		return fmt.Errorf("failed to validate %T: %w", &req, err)
	}

	var h iamCleanupHandler
	if c.testHandler != nil {
		// Use testHandler if it is for testing.
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

	resp, err := h.Cleanup(ctx, &req)
	// The error here might only be errrors of parsing the condition expiration
	// expression of some IAM bindings, it does not necessarily mean that it
	// failed to cleanup the requested bindings.
	if err != nil {
		return fmt.Errorf("encountered error when cleanning up IAM policy: %w", err)
	}

	printHeader(c.Stdout(), "Successfully Removed Requested Bindings")
	if err := encodeYaml(c.Stdout(), &req); err != nil {
		return fmt.Errorf("failed to output applied request: %w", err)
	}

	if c.flagVerbose {
		printHeader(c.Stdout(), "Cleaned Up IAM Policies")
		if err := encodeYaml(c.Stdout(), resp); err != nil {
			return fmt.Errorf("failed to output IAM policies: %w", err)
		}
	}

	return nil
}
