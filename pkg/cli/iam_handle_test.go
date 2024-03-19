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
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/abcxyz/access-on-demand/apis/v1alpha1"
	"github.com/abcxyz/pkg/logging"
	"github.com/abcxyz/pkg/testutil"
)

func TestIAMHandleCommand(t *testing.T) {
	t.Parallel()

	// Set up IAM request file.
	requestFileContentByName := map[string]string{
		"valid.yaml": `
policies:
- resource: organizations/foo
  bindings:
  - members:
    - user:test-org-userA@example.com
    - user:test-org-userB@example.com
    role: roles/cloudkms.cryptoOperator
  - members:
    - user:test-org-userA@example.com
    - user:test-org-userB@example.com
    role: roles/accessapproval.approver
- resource: folders/bar
  bindings:
    - members:
      - user:test-folder-user@example.com
      role: roles/cloudkms.cryptoOperator
- resource: projects/baz
  bindings:
    - members:
      - user:test-project-user@example.com
      role: roles/bigquery.dataViewer
`,
		"invalid-request.yaml": `
policies:
- resource: organizations/foo
  bindings:
  - members:
    - group:test-org-group@example.com
    - user:test-org-userB@example.com
    role: roles/cloudkms.cryptoOperator
`,
		"invalid.yaml": `bananas`,
	}
	dir := t.TempDir()
	for name, content := range requestFileContentByName {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// The request expected from the valid request yaml file.
	validRequest := &v1alpha1.IAMRequest{
		ResourcePolicies: []*v1alpha1.ResourcePolicy{
			{
				Resource: "organizations/foo",
				Bindings: []*v1alpha1.Binding{
					{
						Members: []string{
							"user:test-org-userA@example.com",
							"user:test-org-userB@example.com",
						},
						Role: "roles/cloudkms.cryptoOperator",
					},
					{
						Members: []string{
							"user:test-org-userA@example.com",
							"user:test-org-userB@example.com",
						},
						Role: "roles/accessapproval.approver",
					},
				},
			},
			{
				Resource: "folders/bar",
				Bindings: []*v1alpha1.Binding{
					{
						Members: []string{
							"user:test-folder-user@example.com",
						},
						Role: "roles/cloudkms.cryptoOperator",
					},
				},
			},
			{
				Resource: "projects/baz",
				Bindings: []*v1alpha1.Binding{
					{
						Members: []string{
							"user:test-project-user@example.com",
						},
						Role: "roles/bigquery.dataViewer",
					},
				},
			},
		},
	}

	st := time.Now().UTC().Round(time.Second)

	cases := []struct {
		name    string
		args    []string
		handler *fakeIAMHandler
		expReq  *v1alpha1.IAMRequestWrapper
		expOut  string
		expErr  string
	}{
		{
			name:    "success",
			args:    []string{"-path", filepath.Join(dir, "valid.yaml"), "-duration", "2h", "-start-time", st.Format(time.RFC3339)},
			handler: &fakeIAMHandler{},
			expOut: fmt.Sprintf(`
------Successfully Handled IAM Request------
iamrequest:
  policies:
    - resource: organizations/foo
      bindings:
        - members:
            - user:test-org-userA@example.com
            - user:test-org-userB@example.com
          role: roles/cloudkms.cryptoOperator
        - members:
            - user:test-org-userA@example.com
            - user:test-org-userB@example.com
          role: roles/accessapproval.approver
    - resource: folders/bar
      bindings:
        - members:
            - user:test-folder-user@example.com
          role: roles/cloudkms.cryptoOperator
    - resource: projects/baz
      bindings:
        - members:
            - user:test-project-user@example.com
          role: roles/bigquery.dataViewer
duration: 2h0m0s
starttime: %s`, st.Format(time.RFC3339)),
			expReq: &v1alpha1.IAMRequestWrapper{
				IAMRequest: validRequest,
				Duration:   2 * time.Hour,
				StartTime:  st,
			},
		},
		{
			name: "success_verbose",
			args: []string{
				"-path", filepath.Join(dir, "valid.yaml"),
				"-duration", "2h",
				"-start-time", st.Format(time.RFC3339),
				"-verbose",
			},
			handler: &fakeIAMHandler{
				resp: []*v1alpha1.IAMResponse{
					{
						Resource: "test",
					},
				},
			},
			expOut: fmt.Sprintf(`
------Successfully Handled IAM Request------
iamrequest:
  policies:
    - resource: organizations/foo
      bindings:
        - members:
            - user:test-org-userA@example.com
            - user:test-org-userB@example.com
          role: roles/cloudkms.cryptoOperator
        - members:
            - user:test-org-userA@example.com
            - user:test-org-userB@example.com
          role: roles/accessapproval.approver
    - resource: folders/bar
      bindings:
        - members:
            - user:test-folder-user@example.com
          role: roles/cloudkms.cryptoOperator
    - resource: projects/baz
      bindings:
        - members:
            - user:test-project-user@example.com
          role: roles/bigquery.dataViewer
duration: 2h0m0s
starttime: %s
------Updated IAM Policies------
- policy: null
  resource: test
`, st.Format(time.RFC3339)),
			expReq: &v1alpha1.IAMRequestWrapper{
				IAMRequest: validRequest,
				Duration:   2 * time.Hour,
				StartTime:  st,
			},
		},
		{
			name:    "unexpected_args",
			args:    []string{"foo"},
			handler: &fakeIAMHandler{},
			expErr:  `unexpected arguments: ["foo"]`,
		},
		{
			name:    "missing_path",
			args:    []string{},
			handler: &fakeIAMHandler{},
			expErr:  `path is required`,
		},
		{
			name:    "missing_duration",
			args:    []string{"-path", filepath.Join(dir, "valid.yaml")},
			handler: &fakeIAMHandler{},
			expErr:  `duration is required`,
		},
		{
			name:    "invalid_duration",
			args:    []string{"-path", filepath.Join(dir, "valid.yaml"), "-duration", "-2h"},
			handler: &fakeIAMHandler{},
			expErr:  "a positive duration is required",
		},
		{
			name:    "invalid_start_time",
			args:    []string{"-path", filepath.Join(dir, "valid.yaml"), "-duration", "2h", "-start-time", "2009"},
			handler: &fakeIAMHandler{},
			expErr:  `invalid value "2009" for flag -start-time`,
		},
		{
			name:    "expiry_passed",
			args:    []string{"-path", filepath.Join(dir, "valid.yaml"), "-duration", "2h", "-start-time", "2009-11-10T23:00:00Z"},
			handler: &fakeIAMHandler{},
			expErr:  `expiry (start time: "2009-11-10 23:00:00 +0000 UTC" + duration: "2h0m0s") already passed`,
		},
		{
			name:    "invalid_yaml",
			args:    []string{"-path", filepath.Join(dir, "invalid.yaml"), "-duration", "2h"},
			handler: &fakeIAMHandler{},
			expErr:  "failed to read *v1alpha1.IAMRequest",
		},
		{
			name: "handler_failure",
			args: []string{"-path", filepath.Join(dir, "valid.yaml"), "-duration", "1h", "-start-time", st.Format(time.RFC3339)},
			handler: &fakeIAMHandler{
				injectErr: fmt.Errorf("injected error"),
			},
			expErr: "injected error",
			expReq: &v1alpha1.IAMRequestWrapper{
				IAMRequest: validRequest,
				Duration:   1 * time.Hour,
				StartTime:  st,
			},
		},
		{
			name:    "invalid_request",
			args:    []string{"-path", filepath.Join(dir, "invalid-request.yaml"), "-duration", "2h", "-start-time", st.Format(time.RFC3339)},
			handler: &fakeIAMHandler{},
			expErr:  "failed to validate *v1alpha1.IAMRequest",
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := logging.WithLogger(context.Background(), logging.TestLogger(t))

			var cmd IAMHandleCommand
			cmd.testHandler = tc.handler
			_, stdout, _ := cmd.Pipe()

			args := append([]string{}, tc.args...)

			err := cmd.Run(ctx, args)
			if diff := testutil.DiffErrString(err, tc.expErr); diff != "" {
				t.Errorf("Process(%+v) got error diff (-want, +got):\n%s", tc.name, diff)
			}
			if diff := cmp.Diff(strings.TrimSpace(tc.expOut), strings.TrimSpace(stdout.String())); diff != "" {
				t.Errorf("Process(%+v) got output diff (-want, +got):\n%s", tc.name, diff)
			}
			if diff := cmp.Diff(tc.expReq, tc.handler.gotReq); diff != "" {
				t.Errorf("Process(%+v) got request diff (-want, +got):\n%s", tc.name, diff)
			}
		})
	}
}

type fakeIAMHandler struct {
	injectErr error
	gotReq    *v1alpha1.IAMRequestWrapper
	resp      []*v1alpha1.IAMResponse
}

func (h *fakeIAMHandler) Do(ctx context.Context, req *v1alpha1.IAMRequestWrapper) ([]*v1alpha1.IAMResponse, error) {
	h.gotReq = req
	return h.resp, h.injectErr
}
