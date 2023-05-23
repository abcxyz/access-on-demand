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

package requestutil

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/abcxyz/access-on-demand/apis/v1alpha1"
	"github.com/abcxyz/pkg/testutil"
	"github.com/google/go-cmp/cmp"
)

func TestIAMValidateCommand(t *testing.T) {
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
		name, path, expErr string
		expReq             *v1alpha1.IAMRequest
	}{
		{
			name: "success",
			path: filepath.Join(dir, "valid.yaml"),
			expReq: &v1alpha1.IAMRequest{
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
			},
		},
		{
			name:   "invalid_path",
			path:   "foo",
			expErr: `failed to read file at "foo"`,
		},
		{
			name:   "invalid_yaml",
			path:   filepath.Join(dir, "invalid.yaml"),
			expErr: "failed to unmarshal yaml to v1alpha1.IAMRequest",
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			req, err := ReadFromPath(tc.path)
			if diff := testutil.DiffErrString(err, tc.expErr); diff != "" {
				t.Errorf("Process(%+v) got error diff (-want, +got):\n%s", tc.name, diff)
			}

			if diff := cmp.Diff(tc.expReq, req); diff != "" {
				t.Errorf("Process(%+v) got request diff (-want, +got): %v", tc.name, diff)
			}
		})
	}
}
