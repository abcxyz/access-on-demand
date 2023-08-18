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

package integration

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"testing"

	"cloud.google.com/go/iam/apiv1/iampb"
	"github.com/google/go-cmp/cmp"
	"github.com/sethvargo/go-retry"
	"google.golang.org/genproto/googleapis/type/expr"
	"google.golang.org/protobuf/testing/protocmp"

	resourcemanager "cloud.google.com/go/resourcemanager/apiv3"
)

var (
	cfg           *config
	projectClient *resourcemanager.ProjectsClient
)

func TestMain(m *testing.M) {
	os.Exit(func() int {
		ctx := context.Background()

		if strings.ToLower(os.Getenv("TEST_INTEGRATION")) != "true" {
			log.Printf("skipping (not integration)")
			// Not integration test. Exit.
			return 0
		}

		// set up global test config.
		c, err := newTestConfig(ctx)
		if err != nil {
			log.Printf("Failed to parse integration test config: %v", err)
			return 2
		}
		cfg = c

		// Set up global resource manager client.
		pc, err := resourcemanager.NewProjectsClient(ctx)
		if err != nil {
			log.Printf("failed to create projects client: %v", err)
			return 2
		}
		defer pc.Close()
		projectClient = pc

		return m.Run()
	}())
}

func TestIAMHandle(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name         string
		filePath     string
		wantBindings []*iampb.Binding
		wantOutput   string
	}{
		{
			name:     "success",
			filePath: "iam.yaml",
			wantBindings: []*iampb.Binding{
				{
					Role:    "roles/actions.Viewer",
					Members: []string{"user:aod-test-bot@tycho.joonix.net"},
					Condition: &expr.Expr{
						Title:      cfg.ConditionTitle,
						Expression: fmt.Sprintf("request.time < timestamp('%s')", cfg.IAMExpiration),
					},
				},
				{
					Role:    "roles/ml.viewer",
					Members: []string{"user:aod-test-bot@tycho.joonix.net"},
					Condition: &expr.Expr{
						Title:      cfg.ConditionTitle,
						Expression: fmt.Sprintf("request.time < timestamp('%s')", cfg.IAMExpiration),
					},
				},
			},
			wantOutput: fmt.Sprintf(`------Successfully Handled IAM Request------
iamrequest:
  policies:
    - resource: projects/access-on-demand-i-12af76
      bindings:
        - members:
            - user:aod-test-bot@tycho.joonix.net
          role: roles/actions.Viewer
        - members:
            - user:aod-test-bot@tycho.joonix.net
          role: roles/ml.viewer
duration: %sh0m0s
starttime: %s
`, cfg.IAMExpirationDurationHour, cfg.IAMExpirationStartTime),
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()

			args := []string{
				"iam", "handle",
				"-path", tc.filePath,
				"-start-time", cfg.IAMExpirationStartTime,
				"-duration", fmt.Sprintf("%sh", cfg.IAMExpirationDurationHour),
				"-custom-condition-title", cfg.ConditionTitle,
			}

			cmd := exec.Command("aod", args...)
			cmd.Dir = cfg.WorkingDir

			gotOut, err := cmd.CombinedOutput()
			if err != nil {
				t.Errorf("Process(%+v) got unwanted error: %q", tc.name, string(gotOut))
			}

			bs, err := testGetPolicyBindings(ctx, t, cfg)
			if err != nil {
				t.Fatal(err)
			}

			if diff := cmp.Diff(tc.wantBindings, testGotBindings(t, bs, cfg.ConditionTitle), protocmp.Transform()); diff != "" {
				t.Errorf("Process(%+v) got project bindings diff (-want, +got): %v", tc.name, diff)
			}
			if strings.TrimSpace(tc.wantOutput) != strings.TrimSpace(string(gotOut)) {
				t.Errorf("Process(%+v) output response got %q, want %q)", tc.name, string(gotOut), tc.wantOutput)
			}
		})
	}
}

func TestIAMValidate(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		filePath   string
		wantOutput string
	}{
		{
			name:       "success",
			filePath:   "iam.yaml",
			wantOutput: "Successfully validated IAM request",
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			args := []string{
				"iam", "validate",
				"-path", tc.filePath,
			}

			cmd := exec.Command("aod", args...)
			cmd.Dir = cfg.WorkingDir

			gotOut, err := cmd.CombinedOutput()
			if err != nil {
				t.Errorf("Process(%+v) got unwanted error: %q", tc.name, string(gotOut))
			}

			if strings.TrimSpace(tc.wantOutput) != string(gotOut) {
				t.Errorf("Process(%+v) output response got %q, want %q)", tc.name, string(gotOut), tc.wantOutput)
			}
		})
	}
}

func TestToolDo(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		filePath   string
		verbose    bool
		wantOutput string
	}{
		{
			name:     "success",
			filePath: "tool.yaml",
			wantOutput: strings.ReplaceAll(`
------Successfully Completed Commands------
- gcloud projects list --uri --filter projectId:INTEG_TEST_PROJECT_ID
- gcloud projects list --format json --uri --filter projectId:INTEG_TEST_PROJECT_ID`,
				"INTEG_TEST_PROJECT_ID", cfg.ProjectID),
		},
		{
			name:     "success_verbose",
			filePath: "tool.yaml",
			verbose:  true,
			wantOutput: strings.ReplaceAll(`------Tool Commands Output------
gcloud projects list --uri --filter projectId:INTEG_TEST_PROJECT_ID
https://cloudresourcemanager.googleapis.com/v1/projects/INTEG_TEST_PROJECT_ID

gcloud projects list --format json --uri --filter projectId:INTEG_TEST_PROJECT_ID
[
  "https://cloudresourcemanager.googleapis.com/v1/projects/INTEG_TEST_PROJECT_ID"
]
------Successfully Completed Commands------
- gcloud projects list --uri --filter projectId:INTEG_TEST_PROJECT_ID
- gcloud projects list --format json --uri --filter projectId:INTEG_TEST_PROJECT_ID
`, "INTEG_TEST_PROJECT_ID", cfg.ProjectID),
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			args := []string{
				"tool", "do",
				"-path", tc.filePath,
			}
			if tc.verbose {
				args = append(args, "-verbose")
			}

			cmd := exec.Command("aod", args...)
			cmd.Dir = cfg.WorkingDir

			gotOut, err := cmd.CombinedOutput()
			if err != nil {
				t.Errorf("Process(%+v) got unwanted error: %q", tc.name, string(gotOut))
			}

			if strings.TrimSpace(tc.wantOutput) != string(gotOut) {
				t.Errorf("Process(%+v) output response got %q, want %q)", tc.name, string(gotOut), tc.wantOutput)
			}
		})
	}
}

func TestToolCleanup(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name         string
		filePath     string
		verbose      bool
		wantBindings []*iampb.Binding
		wantOutput   string
	}{
		{
			name:     "success",
			filePath: "tool.yaml",
			wantOutput: strings.ReplaceAll(`
------Successfully Completed Commands------
- gcloud projects list --format json --uri --filter projectId:INTEG_TEST_PROJECT_ID
- gcloud projects list --uri --filter projectId:INTEG_TEST_PROJECT_ID`,
				"INTEG_TEST_PROJECT_ID", cfg.ProjectID),
		},
		{
			name:     "success_verbose",
			filePath: "tool.yaml",
			verbose:  true,
			wantOutput: strings.ReplaceAll(`------Tool Commands Output------
gcloud projects list --format json --uri --filter projectId:INTEG_TEST_PROJECT_ID
[
  "https://cloudresourcemanager.googleapis.com/v1/projects/INTEG_TEST_PROJECT_ID"
]

gcloud projects list --uri --filter projectId:INTEG_TEST_PROJECT_ID
https://cloudresourcemanager.googleapis.com/v1/projects/INTEG_TEST_PROJECT_ID
------Successfully Completed Commands------
- gcloud projects list --format json --uri --filter projectId:INTEG_TEST_PROJECT_ID
- gcloud projects list --uri --filter projectId:INTEG_TEST_PROJECT_ID
`, "INTEG_TEST_PROJECT_ID", cfg.ProjectID),
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			args := []string{
				"tool", "cleanup",
				"-path", tc.filePath,
			}
			if tc.verbose {
				args = append(args, "-verbose")
			}

			cmd := exec.Command("aod", args...)
			cmd.Dir = cfg.WorkingDir

			gotOut, err := cmd.CombinedOutput()
			if err != nil {
				t.Errorf("Process(%+v) got unwanted error: %q", tc.name, string(gotOut))
			}

			if strings.TrimSpace(tc.wantOutput) != string(gotOut) {
				t.Errorf("Process(%+v) output response got %q, want %q)", tc.name, string(gotOut), tc.wantOutput)
			}
		})
	}
}

func TestToolValidate(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		filePath   string
		wantOutput string
	}{
		{
			name:       "success",
			filePath:   "tool.yaml",
			wantOutput: "Successfully validated tool request",
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			args := []string{
				"tool", "validate",
				"-path", tc.filePath,
			}

			cmd := exec.Command("aod", args...)
			cmd.Dir = cfg.WorkingDir

			gotOut, err := cmd.CombinedOutput()
			if err != nil {
				t.Errorf("Process(%+v) got unwanted error: %q", tc.name, string(gotOut))
			}

			if strings.TrimSpace(tc.wantOutput) != string(gotOut) {
				t.Errorf("Process(%+v) output response got %q, want %q)", tc.name, string(gotOut), tc.wantOutput)
			}
		})
	}
}

func testGetPolicyBindings(ctx context.Context, tb testing.TB, cfg *config) ([]*iampb.Binding, error) {
	tb.Helper()

	req := &iampb.GetIamPolicyRequest{
		Resource: fmt.Sprintf("projects/%s", cfg.ProjectID),
		Options: &iampb.GetPolicyOptions{
			RequestedPolicyVersion: 3,
		},
	}
	backoff := retry.WithMaxRetries(cfg.QueryRetryLimit, retry.NewConstant(cfg.QueryRetryWaitDuration))
	var bs []*iampb.Binding

	if err := retry.Do(ctx, backoff, func(ctx context.Context) error {
		p, err := projectClient.GetIamPolicy(ctx, req)
		if err != nil {
			return retry.RetryableError(fmt.Errorf("failed to get IAM policy: %w", err))
		}
		bs = p.Bindings
		return nil
	}); err != nil {
		return nil, err
	}

	return bs, nil
}

func testGotBindings(tb testing.TB, bs []*iampb.Binding, matchTitle string) (result []*iampb.Binding) {
	tb.Helper()

	for _, b := range bs {
		if b.Condition != nil && b.Condition.Title == matchTitle {
			result = append(result, b)
		}
	}
	return result
}
