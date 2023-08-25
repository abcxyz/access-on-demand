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
	"time"

	"github.com/abcxyz/access-on-demand/apis/v1alpha1"
	"github.com/abcxyz/access-on-demand/pkg/requestutil"
	"github.com/abcxyz/pkg/cli"
	"github.com/abcxyz/pkg/logging"
	"github.com/posener/complete/v2/predict"
)

var _ cli.Command = (*IAMHandleCommand)(nil)

// iamHandler interface that handles the IAMRequestWrapper.
type iamHandler interface {
	Do(context.Context, *v1alpha1.IAMRequestWrapper) ([]*v1alpha1.IAMResponse, error)
}

// IAMHandleCommand handles IAM requests.
type IAMHandleCommand struct {
	cli.BaseCommand

	flagPath string

	flagDuration time.Duration

	flagStartTime time.Time

	flagVerbose bool

	// Optional custom condition title for IAM bindings expiration, required for
	// integration test.
	flagCustomConditionTitle string

	// testHandler is used for testing only.
	testHandler iamHandler
}

func (c *IAMHandleCommand) Desc() string {
	return `Handle the IAM request YAML file in the given path`
}

func (c *IAMHandleCommand) Help() string {
	return `
Usage: {{ COMMAND }} [options]

Handle the IAM request YAML file in the given path:

      {{ COMMAND }} -path "/path/to/file.yaml" -duration "2h" -start-time "2009-11-10T23:00:00Z"

Handle the IAM request YAML file and output applied IAM changes:

      {{ COMMAND }} -path "/path/to/file.yaml" -duration "2h" -start-time "2009-11-10T23:00:00Z" -verbose
`
}

func (c *IAMHandleCommand) Flags() *cli.FlagSet {
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

	f.DurationVar(&cli.DurationVar{
		Name:    "duration",
		Target:  &c.flagDuration,
		Example: "2h",
		Usage:   `The IAM permission lifecycle, as a duration.`,
	})

	f.TimeVar(time.RFC3339, &cli.TimeVar{
		Name:    "start-time",
		Target:  &c.flagStartTime,
		Example: "2009-11-10T23:00:00Z",
		Default: time.Now().UTC(),
		Usage: `The start time of the IAM permission lifecycle in RFC3339 format. ` +
			`Default is current UTC time.`,
	})

	f.BoolVar(&cli.BoolVar{
		Name:    "verbose",
		Target:  &c.flagVerbose,
		Default: false,
		Usage:   `Turn on verbose mode to print updated IAM policies. Note that it may contain sensitive information`,
	})

	f.StringVar(&cli.StringVar{
		Name:    "custom-condition-title",
		Target:  &c.flagCustomConditionTitle,
		Hidden:  true,
		Example: "foo-aod-expiry",
		Usage:   `The custom title for the aod expiry condition.`,
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
		return fmt.Errorf("unexpected arguments: %q", args)
	}

	if c.flagPath == "" {
		return fmt.Errorf("path is required")
	}

	if c.flagDuration <= 0 {
		return fmt.Errorf("a positive duration is required")
	}

	if c.flagStartTime.Add(c.flagDuration).Before(time.Now()) {
		return fmt.Errorf("expiry (start time + duration) already passed")
	}

	return c.handleIAM(ctx)
}

func (c *IAMHandleCommand) handleIAM(ctx context.Context) error {
	logger := logging.FromContext(ctx)

	// Read request from file path.
	var req v1alpha1.IAMRequest
	if err := requestutil.ReadRequestFromPath(c.flagPath, &req); err != nil {
		return fmt.Errorf("failed to read %T: %w", &req, err)
	}

	if err := v1alpha1.ValidateIAMRequest(&req); err != nil {
		return fmt.Errorf("failed to validate %T: %w", &req, err)
	}

	var h iamHandler
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

	// Wrap IAMRequest to include Duration.
	reqWrapper := &v1alpha1.IAMRequestWrapper{
		IAMRequest: &req,
		Duration:   c.flagDuration,
		StartTime:  c.flagStartTime,
	}

	resp, err := h.Do(ctx, reqWrapper)
	if err != nil {
		return fmt.Errorf("failed to handle IAM request: %w", err)
	}
	printHeader(c.Stdout(), "Successfully Handled IAM Request")
	if err := encodeYaml(c.Stdout(), reqWrapper); err != nil {
		return fmt.Errorf("failed to output applied request: %w", err)
	}

	if c.flagVerbose {
		printHeader(c.Stdout(), "Updated IAM Policies")
		if err := encodeYaml(c.Stdout(), resp); err != nil {
			return fmt.Errorf("failed to output IAM policies: %w", err)
		}
	}

	return nil
}
