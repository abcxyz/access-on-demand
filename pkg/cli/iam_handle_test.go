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

	"github.com/abcxyz/access-on-demand/apis/v1alpha1"
	"github.com/abcxyz/pkg/logging"
	"github.com/abcxyz/pkg/testutil"
	"github.com/google/go-cmp/cmp"
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
		"invalid.yaml": `bananas`,
	}
	dir := t.TempDir()
	for name, content := range requestFileContentByName {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	cases := []struct {
		name     string
		args     []string
		fileData []byte
		handler  iamHandler
		expOut   string
		expErr   string
	}{
		{
			name:    "success",
			args:    []string{"-path", filepath.Join(dir, "valid.yaml"), "-duration", "2h"},
			handler: &fakeHandler{},
			expOut:  "Successfully handled IAM request",
		},
		{
			name:    "unexpected_args",
			args:    []string{"foo"},
			handler: &fakeHandler{},
			expErr:  `unexpected arguments: ["foo"]`,
		},
		{
			name:    "missing_path",
			args:    []string{},
			handler: &fakeHandler{},
			expErr:  `path is required`,
		},
		{
			name:    "missing_duration",
			args:    []string{"-path", filepath.Join(dir, "valid.yaml")},
			handler: &fakeHandler{},
			expErr:  `duration is required`,
		},
		{
			name:    "invalid_duration",
			args:    []string{"-path", filepath.Join(dir, "valid.yaml"), "-duration", "-2h"},
			handler: &fakeHandler{},
			expErr:  "a positive duration is required",
		},
		{
			name:    "invalid_yaml",
			args:    []string{"-path", filepath.Join(dir, "invalid.yaml"), "-duration", "2h"},
			handler: &fakeHandler{},
			expErr:  "failed to unmarshal yaml to v1alpha1.IAMRequest",
		},
		{
			name:    "handler_failure",
			args:    []string{"-path", filepath.Join(dir, "valid.yaml"), "-duration", "2h"},
			handler: &fakeFailureHandler{},
			expErr:  "always fail",
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
		})
	}
}

type fakeHandler struct{}

func (h *fakeHandler) Do(context.Context, *v1alpha1.IAMRequestWrapper) ([]*v1alpha1.IAMResponse, error) {
	return nil, nil
}

type fakeFailureHandler struct{}

func (h *fakeFailureHandler) Do(context.Context, *v1alpha1.IAMRequestWrapper) ([]*v1alpha1.IAMResponse, error) {
	return nil, fmt.Errorf("always fail")
}
