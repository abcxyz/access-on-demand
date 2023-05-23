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
	"github.com/abcxyz/access-on-demand/pkg/handler"
	"github.com/abcxyz/access-on-demand/pkg/requestutil"
	"github.com/abcxyz/pkg/cli"

	resourcemanager "cloud.google.com/go/resourcemanager/apiv3"
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

      aod iam handle -path "/path/to/file.yaml" -duration "2h" -start-time "2009-11-10T23:00:00Z"
`
}

func (c *IAMHandleCommand) Flags() *cli.FlagSet {
	set := cli.NewFlagSet()

	// Command options
	f := set.NewSection("COMMAND OPTIONS")

	f.StringVar(&cli.StringVar{
		Name:    "path",
		Target:  &c.flagPath,
		Example: "/path/to/file.yaml",
		Usage:   `The path of IAM request file, in YAML format.`,
	})

	f.DurationVar(&cli.DurationVar{
		Name:    "duration",
		Target:  &c.flagDuration,
		Example: "2h",
		Usage:   `The IAM permission lifecycle, as a duration.`,
	})

	cli.Flag(f, &cli.Var[time.Time]{
		Name:    "start-time",
		Usage:   `The start time of the IAM permission lifecycle in RFC3339 format. Default is current UTC time.`,
		Example: "2009-11-10T23:00:00Z",
		Default: time.Now().UTC(),
		Target:  &c.flagStartTime,
		Parser:  timeParser,
		Printer: timePrinter,
	})

	return set
}

// Parse the string representation of time, it must be in RFC3339 format.
func timeParser(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return t, fmt.Errorf("failed to parse the time with RFC3339 layout: %w", err)
	}
	return t, nil
}

// Print time in RFC3339 format.
func timePrinter(t time.Time) string {
	return t.Format(time.RFC3339)
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
	// Read request from file path.
	req, err := requestutil.ReadFromPath(c.flagPath)
	if err != nil {
		return fmt.Errorf("failed to read %T: %w", req, err)
	}

	var h iamHandler
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

	// Wrap IAMRequest to include Duration.
	reqWrapper := &v1alpha1.IAMRequestWrapper{
		IAMRequest: req,
		Duration:   c.flagDuration,
		StartTime:  c.flagStartTime,
	}
	// TODO(#15): add a log level to output handler response.
	if _, err := h.Do(ctx, reqWrapper); err != nil {
		return fmt.Errorf("failed to handle IAM request: %w", err)
	}
	c.Outf("Successfully handled IAM request")

	return nil
}
