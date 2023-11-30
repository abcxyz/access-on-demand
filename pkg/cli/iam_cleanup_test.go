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

	"github.com/google/go-cmp/cmp"

	"github.com/abcxyz/access-on-demand/apis/v1alpha1"
	"github.com/abcxyz/pkg/logging"
	"github.com/abcxyz/pkg/testutil"
)

func TestIAMCleanupCommand(t *testing.T) {
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

	cases := []struct {
		name    string
		args    []string
		handler *fakeIAMCleanupHandler
		expReq  *v1alpha1.IAMRequest
		expOut  string
		expErr  string
	}{
		{
			name:    "success",
			args:    []string{"-path", filepath.Join(dir, "valid.yaml")},
			handler: &fakeIAMCleanupHandler{},
			expOut: `
------Successfully Removed Requested Bindings------
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
			expReq: validRequest,
		},
		{
			name: "success_verbose",
			args: []string{
				"-path", filepath.Join(dir, "valid.yaml"),
				"-verbose",
			},
			handler: &fakeIAMCleanupHandler{
				resp: []*v1alpha1.IAMResponse{
					{
						Resource: "test",
					},
				},
			},
			expOut: `
------Successfully Removed Requested Bindings------
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
------Cleaned Up IAM Policies------
- policy: null
  resource: test
`,
			expReq: validRequest,
		},
		{
			name:    "unexpected_args",
			args:    []string{"foo"},
			handler: &fakeIAMCleanupHandler{},
			expErr:  `unexpected arguments: ["foo"]`,
		},
		{
			name:    "missing_path",
			args:    []string{},
			handler: &fakeIAMCleanupHandler{},
			expErr:  `path is required`,
		},
		{
			name:    "invalid_yaml",
			args:    []string{"-path", filepath.Join(dir, "invalid.yaml")},
			handler: &fakeIAMCleanupHandler{},
			expErr:  "failed to read *v1alpha1.IAMRequest",
		},
		{
			name: "handler_failure",
			args: []string{"-path", filepath.Join(dir, "valid.yaml")},
			handler: &fakeIAMCleanupHandler{
				injectErr: fmt.Errorf("injected error"),
			},
			expErr: "injected error",
			expReq: validRequest,
		},
		{
			name:    "invalid_request",
			args:    []string{"-path", filepath.Join(dir, "invalid-request.yaml")},
			handler: &fakeIAMCleanupHandler{},
			expErr:  "failed to validate *v1alpha1.IAMRequest",
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := logging.WithLogger(context.Background(), logging.TestLogger(t))

			var cmd IAMCleanupCommand
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

type fakeIAMCleanupHandler struct {
	injectErr error
	gotReq    *v1alpha1.IAMRequest
	resp      []*v1alpha1.IAMResponse
}

func (h *fakeIAMCleanupHandler) Cleanup(ctx context.Context, req *v1alpha1.IAMRequest) ([]*v1alpha1.IAMResponse, error) {
	h.gotReq = req
	return h.resp, h.injectErr
}
