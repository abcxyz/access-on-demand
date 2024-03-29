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
	"github.com/abcxyz/access-on-demand/pkg/requestutil"
	"github.com/abcxyz/pkg/cli"
	"github.com/abcxyz/pkg/logging"
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

	// Optional custom condition title as AOD bindings identifier, required for
	// integration test.
	flagCustomConditionTitle string

	// testHandler is used for testing only.
	testHandler iamCleanupHandler
}

func (c *IAMCleanupCommand) Desc() string {
	return "Clean up the IAM bindings requested in the given request YAML file " +
		"along with other expired AOD IAM bindings"
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
		Usage:   "The path of IAM request file, in YAML format.",
	})

	f.BoolVar(&cli.BoolVar{
		Name:    "verbose",
		Target:  &c.flagVerbose,
		Default: false,
		Usage:   "Turn on verbose mode to print updated IAM policies. Note that it may contain sensitive information.",
	})

	f.StringVar(&cli.StringVar{
		Name:    "custom-condition-title",
		Target:  &c.flagCustomConditionTitle,
		Hidden:  true,
		Example: "foo-aod-expiry",
		Usage:   "The custom title for the aod expiry condition.",
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
	logger := logging.FromContext(ctx)

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
		iamHandler, closer, newHandlerErr := newIAMHandler(ctx, c.flagCustomConditionTitle)
		if newHandlerErr != nil {
			return newHandlerErr
		}
		h = iamHandler
		defer func() {
			if err := closer.Close(); err != nil {
				logger.ErrorContext(ctx, "failed to close", "error", err)
			}
		}()
	}

	resp, err := h.Cleanup(ctx, &req)
	// The error here might only be errrors of parsing the condition expiration
	// expression of some IAM bindings, it does not necessarily mean that it
	// failed to cleanup the requested bindings.
	if err != nil {
		return fmt.Errorf("failed to clean up IAM policy: %w", err)
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
