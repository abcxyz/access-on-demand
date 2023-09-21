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

// Package integration tests the aod root command.
package integration

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/iam/apiv1/iampb"
	"github.com/abcxyz/access-on-demand/pkg/cli"
	"github.com/google/go-cmp/cmp"
	"github.com/sethvargo/go-retry"
	"google.golang.org/genproto/googleapis/type/expr"
	"google.golang.org/protobuf/testing/protocmp"

	resourcemanager "cloud.google.com/go/resourcemanager/apiv3"
)

const (
	iamReqDataTmpl = `
policies:
  - resource: 'projects/%s'
    bindings:
      - members:
          - '%s'
        role: 'roles/actions.Viewer'
      - members:
          - '%s'
        role: 'roles/ml.viewer'
`
	toolReqData = `
do:
  - 'projects list --uri --sort-by=projectId --limit=1'
  - 'projects list --format json --uri --sort-by=projectId --limit=1'
`
)

var (
	cfg           *config
	projectClient *resourcemanager.ProjectsClient
	iamReqData    string
)

func TestMain(m *testing.M) {
	os.Exit(func() int {
		ctx := context.Background()

		if strings.ToLower(os.Getenv("TEST_INTEGRATION")) != "true" {
			log.Printf("skipping (not integration)")
			// Not integration test. Exit.
			return 0
		}

		// Set up global test config.
		c, err := newTestConfig(ctx)
		if err != nil {
			log.Printf("Failed to parse integration test config: %v", err)
			return 1
		}
		cfg = c

		iamReqData = fmt.Sprintf(iamReqDataTmpl, cfg.ProjectID, cfg.IAMUser, cfg.IAMUser)

		// Set up global resource manager client.
		pc, err := resourcemanager.NewProjectsClient(ctx)
		if err != nil {
			log.Printf("failed to create projects client: %v", err)
			return 1
		}
		defer pc.Close()
		projectClient = pc

		return m.Run()
	}())
}

func TestIAMHandleAndCleanup(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	reqFilePath := testWriteReqFile(t, iamReqData, "iam.yaml")

	now := time.Now().UTC().Round(time.Second)
	d := 3 * time.Hour

	// IAM policy will sort the bindings based on role alphabetical order.
	wantBindings := []*iampb.Binding{
		{
			Role:    "roles/actions.Viewer",
			Members: []string{cfg.IAMUser},
			Condition: &expr.Expr{
				Title:      cfg.ConditionTitle,
				Expression: fmt.Sprintf("request.time < timestamp('%s')", now.Add(d).Format(time.RFC3339)),
			},
		},
		{
			Role:    "roles/ml.viewer",
			Members: []string{cfg.IAMUser},
			Condition: &expr.Expr{
				Title:      cfg.ConditionTitle,
				Expression: fmt.Sprintf("request.time < timestamp('%s')", now.Add(d).Format(time.RFC3339)),
			},
		},
	}
	wantHandleOutput := fmt.Sprintf(`------Successfully Handled IAM Request------
iamrequest:
  policies:
    - resource: projects/access-on-demand-i-12af76
      bindings:
        - members:
            - %s
          role: roles/actions.Viewer
        - members:
            - %s
          role: roles/ml.viewer
duration: %s
starttime: %s
`, cfg.IAMUser, cfg.IAMUser, d.String(), now.Format(time.RFC3339))

	wantCleanupOutput := fmt.Sprintf(`------Successfully Removed Requested Bindings------
policies:
  - resource: projects/access-on-demand-i-12af76
    bindings:
      - members:
          - %s
        role: roles/actions.Viewer
      - members:
          - %s
        role: roles/ml.viewer
`, cfg.IAMUser, cfg.IAMUser)

	handleArgs := []string{
		"iam", "handle",
		"-path", reqFilePath,
		"-start-time", now.Format(time.RFC3339),
		"-duration", d.String(),
		"-custom-condition-title", cfg.ConditionTitle,
	}

	// Cleanup/Reset the IAM policy.
	t.Cleanup(func() {
		testGetAndResetBindings(ctx, t, cfg, true)
	})

	_, handleStdout, handleStderr := testPipeAndRun(ctx, t, handleArgs)

	gotHandleBindings := testGetAndResetBindings(ctx, t, cfg, false)

	if diff := cmp.Diff(wantBindings, gotHandleBindings, protocmp.Transform()); diff != "" {
		t.Errorf("Handle got project bindings diff (-want, +got): %v", diff)
	}
	if got, want := strings.TrimSpace(handleStdout.String()), strings.TrimSpace(wantHandleOutput); got != want {
		t.Errorf("Handle output response got %q, want %q)", got, want)
	}
	if handleStderr.String() != "" {
		t.Errorf("Handle got unexpected error: %q)", handleStderr.String())
	}

	cleanupArgs := []string{"iam", "cleanup", "-path", reqFilePath}

	_, cleanupStdout, cleanupStderr := testPipeAndRun(ctx, t, cleanupArgs)

	gotCleanupBindings := testGetAndResetBindings(ctx, t, cfg, false)
	if diff := cmp.Diff(wantBindings, gotCleanupBindings, protocmp.Transform()); diff != "" {
		t.Errorf("Cleanup got project bindings diff (-want, +got): %v", diff)
	}
	if got, want := strings.TrimSpace(cleanupStdout.String()), strings.TrimSpace(wantCleanupOutput); got != want {
		t.Errorf("Cleanup output response got %q, want %q)", got, want)
	}
	if cleanupStderr.String() != "" {
		t.Errorf("Cleanup got unexpected error: %q)", cleanupStderr.String())
	}
}

func TestIAMValidate(t *testing.T) {
	t.Parallel()

	reqFilePath := testWriteReqFile(t, iamReqData, "iam.yaml")
	wantOutput := "Successfully validated IAM request"

	ctx := context.Background()

	args := []string{
		"iam", "validate",
		"-path", reqFilePath,
	}

	_, stdout, stderr := testPipeAndRun(ctx, t, args)

	if got, want := strings.TrimSpace(stdout.String()), strings.TrimSpace(wantOutput); got != want {
		t.Errorf("Output response got %q, want %q)", got, want)
	}
	if stderr.String() != "" {
		t.Errorf("Got unexpected error: %q)", stderr.String())
	}
}

func TestToolDo(t *testing.T) {
	t.Parallel()

	reqFilePath := testWriteReqFile(t, toolReqData, "tool.yaml")

	cases := []struct {
		name       string
		verbose    bool
		wantOutput string
	}{
		{
			name: "success",
			wantOutput: `
------Successfully Completed Commands------
- gcloud projects list --uri --sort-by=projectId --limit=1
- gcloud projects list --format json --uri --sort-by=projectId --limit=1`,
		},
		{
			name:    "success_verbose",
			verbose: true,
			wantOutput: fmt.Sprintf(`------Tool Commands Output------
gcloud projects list --uri --sort-by=projectId --limit=1
https://cloudresourcemanager.googleapis.com/v1/projects/%s

gcloud projects list --format json --uri --sort-by=projectId --limit=1
[
  "https://cloudresourcemanager.googleapis.com/v1/projects/%s"
]
------Successfully Completed Commands------
- gcloud projects list --uri --sort-by=projectId --limit=1
- gcloud projects list --format json --uri --sort-by=projectId --limit=1
`, cfg.ProjectID, cfg.ProjectID),
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()

			args := []string{
				"tool", "do",
				"-path", reqFilePath,
			}
			if tc.verbose {
				args = append(args, "-verbose")
			}

			_, stdout, stderr := testPipeAndRun(ctx, t, args)

			if got, want := strings.TrimSpace(stdout.String()), strings.TrimSpace(tc.wantOutput); got != want {
				t.Errorf("Process(%+v) output response got %q, want %q)", tc.name, got, want)
			}
			if stderr.String() != "" {
				t.Errorf("Process(%+v) got unexpected error: %q)", tc.name, stderr.String())
			}
		})
	}
}

func TestToolValidate(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	reqFilePath := testWriteReqFile(t, toolReqData, "tool.yaml")
	wantOutput := "Successfully validated tool request"

	args := []string{
		"tool", "validate",
		"-path", reqFilePath,
	}

	_, stdout, stderr := testPipeAndRun(ctx, t, args)

	if got, want := strings.TrimSpace(stdout.String()), strings.TrimSpace(wantOutput); got != want {
		t.Errorf("Output response got %q, want %q)", got, want)
	}
	if stderr.String() != "" {
		t.Errorf("Got unexpected error: %q)", stderr.String())
	}
}

// testGetAndResetBindings is a helper function that returns the IAM bindings
// of matched condition title in the cfg. It also removes them from the project
// IAM policy if reset is true.
func testGetAndResetBindings(ctx context.Context, tb testing.TB, cfg *config, reset bool) (result []*iampb.Binding) {
	tb.Helper()

	getIAMReq := &iampb.GetIamPolicyRequest{
		Resource: fmt.Sprintf("projects/%s", cfg.ProjectID),
		Options: &iampb.GetPolicyOptions{
			RequestedPolicyVersion: 3,
		},
	}
	backoff := retry.WithMaxRetries(cfg.QueryRetryLimit, retry.NewConstant(cfg.QueryRetryWaitDuration))

	if err := retry.Do(ctx, backoff, func(ctx context.Context) error {
		p, err := projectClient.GetIamPolicy(ctx, getIAMReq)
		if err != nil {
			return retry.RetryableError(fmt.Errorf("failed to get IAM policy: %w", err))
		}
		var bs []*iampb.Binding
		for _, b := range p.Bindings {
			if b.Condition != nil && b.Condition.Title == cfg.ConditionTitle {
				result = append(result, b)
				continue
			}
			bs = append(bs, b)
		}

		// Stop if the no bindings was added or reset is not needed.
		if len(result) == 0 || !reset {
			return nil
		}

		p.Bindings = bs
		setIAMReq := &iampb.SetIamPolicyRequest{
			Resource: fmt.Sprintf("projects/%s", cfg.ProjectID),
			Policy:   p,
		}
		if _, err := projectClient.SetIamPolicy(ctx, setIAMReq); err != nil {
			return retry.RetryableError(fmt.Errorf("failed to set IAM policy: %w", err))
		}
		return nil
	}); err != nil {
		tb.Fatal(err)
	}

	return result
}

func testWriteReqFile(tb testing.TB, data, fileName string) (filePath string) {
	tb.Helper()

	filePath = filepath.Join(tb.TempDir(), fileName)
	if err := os.WriteFile(filePath, []byte(data), 0o600); err != nil {
		tb.Fatalf("failed to write %s data to file: %v", fileName, err)
	}
	return
}

// testPipeAndRun creates new unqiue stdin, stdout, and stderr buffers, sets
// them on the command, and run the command.
func testPipeAndRun(ctx context.Context, tb testing.TB, args []string) (stdin, stdout, stderr *bytes.Buffer) {
	tb.Helper()

	stdin = bytes.NewBuffer(nil)
	stdout = bytes.NewBuffer(nil)
	stderr = bytes.NewBuffer(nil)
	c := cli.RootCmd()
	c.SetStdin(stdin)
	c.SetStdout(stdout)
	c.SetStderr(stderr)

	if err := c.Run(ctx, args); err != nil {
		tb.Fatalf("failed to run root command: %v", err)
	}
	return
}
