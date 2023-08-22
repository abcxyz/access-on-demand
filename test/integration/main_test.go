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

// integration package that tests the lumberctl root command.
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
cleanup:
  - 'projects list --format json --uri --sort-by=projectId --limit=1'
  - 'projects list --uri --sort-by=projectId --limit=1'
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

func TestIAMHandle(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	filePath := testWriteDataToFile(t, iamReqData, "iam.yaml")

	now := time.Now().UTC().Round(time.Second)
	d := 3 * time.Hour

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
	wantOutput := fmt.Sprintf(`------Successfully Handled IAM Request------
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
`, cfg.IAMUser, cfg.IAMUser, d.String(), now)

	args := []string{
		"iam", "handle",
		"-path", filePath,
		"-start-time", now.Format(time.RFC3339),
		"-duration", d.String(),
		"-custom-condition-title", cfg.ConditionTitle,
	}

	// Cleanup the IAM policy again in case testPipeAndRun failed and ended
	// the test.
	t.Cleanup(func() {
		testAddedPolicyBindings(ctx, t, cfg)
	})

	_, stdout, stderr := testPipeAndRun(ctx, t, args)

	bs := testAddedPolicyBindings(ctx, t, cfg)

	if diff := cmp.Diff(wantBindings, bs, protocmp.Transform()); diff != "" {
		t.Errorf("Got project bindings diff (-want, +got): %v", diff)
	}
	if strings.TrimSpace(wantOutput) != strings.TrimSpace(stdout.String()) {
		t.Errorf("Output response got %q, want %q)", stdout.String(), wantOutput)
	}
	if stderr.String() != "" {
		t.Errorf("Got unexpected error: %q)", stderr.String())
	}
}

func TestIAMValidate(t *testing.T) {
	t.Parallel()

	filePath := testWriteDataToFile(t, iamReqData, "iam.yaml")
	wantOutput := "Successfully validated IAM request"

	ctx := context.Background()

	args := []string{
		"iam", "validate",
		"-path", filePath,
	}

	_, stdout, stderr := testPipeAndRun(ctx, t, args)

	if strings.TrimSpace(wantOutput) != strings.TrimSpace(stdout.String()) {
		t.Errorf("Output response got %q, want %q)", stdout.String(), wantOutput)
	}
	if stderr.String() != "" {
		t.Errorf("Got unexpected error: %q)", stderr.String())
	}
}

func TestToolDo(t *testing.T) {
	t.Parallel()

	filePath := testWriteDataToFile(t, toolReqData, "tool.yaml")

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
- gcloud projects list --format json --sort-by=projectId --limit=1`,
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
				"-path", filePath,
			}
			if tc.verbose {
				args = append(args, "-verbose")
			}

			_, stdout, stderr := testPipeAndRun(ctx, t, args)

			if strings.TrimSpace(tc.wantOutput) != strings.TrimSpace(stdout.String()) {
				t.Errorf("Process(%+v) output response got %q, want %q)", tc.name, stdout.String(), tc.wantOutput)
			}
			if stderr.String() != "" {
				t.Errorf("Process(%+v) got unexpected error: %q)", tc.name, stderr.String())
			}
		})
	}
}

func TestToolCleanup(t *testing.T) {
	t.Parallel()

	filePath := testWriteDataToFile(t, toolReqData, "tool.yaml")

	cases := []struct {
		name       string
		verbose    bool
		wantOutput string
	}{
		{
			name: "success",
			wantOutput: `
------Successfully Completed Commands------
- gcloud projects list --format json --uri --sort-by=projectId --limit=1
- gcloud projects list --uri --sort-by=projectId --limit=1`,
		},
		{
			name:    "success_verbose",
			verbose: true,
			wantOutput: fmt.Sprintf(`------Tool Commands Output------
gcloud projects list --format json --uri --sort-by=projectId --limit=1
[
  "https://cloudresourcemanager.googleapis.com/v1/projects/%s"
]

gcloud projects list --uri --sort-by=projectId --limit=1
https://cloudresourcemanager.googleapis.com/v1/projects/%s
------Successfully Completed Commands------
- gcloud projects list --format json --uri --sort-by=projectId --limit=1
- gcloud projects list --uri --sort-by=projectId --limit=1
`, cfg.ProjectID, cfg.ProjectID),
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()

			args := []string{
				"tool", "cleanup",
				"-path", filePath,
			}
			if tc.verbose {
				args = append(args, "-verbose")
			}

			_, stdout, stderr := testPipeAndRun(ctx, t, args)

			if strings.TrimSpace(tc.wantOutput) != strings.TrimSpace(stdout.String()) {
				t.Errorf("Process(%+v) output response got %q, want %q)", tc.name, stdout.String(), tc.wantOutput)
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
	filePath := testWriteDataToFile(t, toolReqData, "tool.yaml")
	wantOutput := "Successfully validated tool request"

	args := []string{
		"tool", "validate",
		"-path", filePath,
	}

	_, stdout, stderr := testPipeAndRun(ctx, t, args)

	if strings.TrimSpace(wantOutput) != strings.TrimSpace(stdout.String()) {
		t.Errorf("Output response got %q, want %q)", stdout.String(), wantOutput)
	}
	if stderr.String() != "" {
		t.Errorf("Got unexpected error: %q)", stderr.String())
	}
}

// testAddedPolicyBindings is a helper function that returns the IAM bindings
// of matched condition title in the cfg. It also removes them from the project
// IAM policy as cleanup.
func testAddedPolicyBindings(ctx context.Context, tb testing.TB, cfg *config) (result []*iampb.Binding) {
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

func testWriteDataToFile(tb testing.TB, data string, fileName string) (filePath string) {
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
