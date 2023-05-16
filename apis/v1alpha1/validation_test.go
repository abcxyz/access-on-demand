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

package v1alpha1

import (
	"testing"

	"github.com/abcxyz/pkg/testutil"
)

func TestValidateIAMRequest(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		request *IAMRequest
		wantErr string
	}{
		{
			name: "success",
			request: &IAMRequest{
				ResourcePolicies: []*ResourcePolicy{
					{
						Resource: "organizations/foo",
						Bindings: []*Binding{
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
						Bindings: []*Binding{
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
						Bindings: []*Binding{
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
			name: "invalid_email",
			request: &IAMRequest{
				ResourcePolicies: []*ResourcePolicy{
					{
						Resource: "organizations/foo",
						Bindings: []*Binding{
							{
								Members: []string{
									"user:example.com",
								},
								Role: "roles/accessapproval.approver",
							},
						},
					},
				},
			},
			wantErr: "member \"example.com\" does not appear to be a valid email address",
		},
		{
			name: "invalid_member",
			request: &IAMRequest{
				ResourcePolicies: []*ResourcePolicy{
					{
						Resource: "folders/foo",
						Bindings: []*Binding{
							{
								Members: []string{
									"group:test-group@example.com",
									"user:test-user@example.com",
								},
								Role: "roles/accessapproval.approver",
							},
						},
					},
				},
			},
			wantErr: "member \"group:test-group@example.com\" is not of \"user\" type",
		},
		{
			name: "invalid_resource",
			request: &IAMRequest{
				ResourcePolicies: []*ResourcePolicy{
					{
						Resource: "foo",
						Bindings: []*Binding{
							{
								Members: []string{
									"group:test-group@example.com",
									"user:test-user@example.com",
								},
								Role: "roles/accessapproval.approver",
							},
						},
					},
				},
			},
			wantErr: "resource \"foo\" isn't one of [organizations, folders, projects]",
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			gotErr := ValidateIAMRequest(tc.request)
			if diff := testutil.DiffErrString(gotErr, tc.wantErr); diff != "" {
				t.Errorf("Process %s got unexpected error: %s", tc.name, diff)
			}
		})
	}
}
