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
			name: "empty_request",
			request: &IAMRequest{
				ResourcePolicies: []*ResourcePolicy{},
			},
			wantErr: `policies not found`,
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
			wantErr: `member "user:example.com" does not appear to be a valid email address (got "example.com")`,
		},
		{
			name: "invalid_member_invalid_type",
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
			wantErr: `member "group:test-group@example.com" is not of "user" type`,
		},
		{
			name: "invalid_member_missing_email",
			request: &IAMRequest{
				ResourcePolicies: []*ResourcePolicy{
					{
						Resource: "folders/foo",
						Bindings: []*Binding{
							{
								Members: []string{
									"user:",
								},
								Role: "roles/accessapproval.approver",
							},
						},
					},
				},
			},
			wantErr: `member "user:" does not appear to be a valid email address (got "")`,
		},
		{
			name: "invalid_member_missing_type",
			request: &IAMRequest{
				ResourcePolicies: []*ResourcePolicy{
					{
						Resource: "folders/foo",
						Bindings: []*Binding{
							{
								Members: []string{
									`:user@example.com`,
								},
								Role: "roles/accessapproval.approver",
							},
						},
					},
				},
			},
			wantErr: `member ":user@example.com" is not of "user" type (got "")`,
		},
		{
			name: "invalid_member_format_missing_delimiter",
			request: &IAMRequest{
				ResourcePolicies: []*ResourcePolicy{
					{
						Resource: "folders/foo",
						Bindings: []*Binding{
							{
								Members: []string{
									"user",
								},
								Role: "roles/accessapproval.approver",
							},
						},
					},
				},
			},
			wantErr: `member "user" is not a valid format (expected "user:<email>")`,
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
			wantErr: `resource "foo" isn't one of [organizations, folders, projects]`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			gotErr := ValidateIAMRequest(tc.request)
			if diff := testutil.DiffErrString(gotErr, tc.wantErr); diff != "" {
				t.Errorf("Process %s got unexpected error: %s", tc.name, diff)
			}
		})
	}
}

func TestValidateToolRequest(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		request *ToolRequest
		wantErr string
	}{
		{
			name: "success",
			request: &ToolRequest{
				Tool: "gcloud",
				Do: []string{
					"run jobs execute my-job1",
					"run jobs execute my-job2",
				},
			},
		},
		{
			name: "missing_do_commands",
			request: &ToolRequest{
				Tool: "gcloud",
				Do:   []string{},
			},
			wantErr: "do commands not found",
		},
		{
			name: "success_with_default_tool",
			request: &ToolRequest{
				Do: []string{
					"run jobs execute my-job1",
					"run jobs execute my-job2",
				},
			},
		},
		{
			name: "invalid_tool",
			request: &ToolRequest{
				Tool: "aws",
				Do: []string{
					"run jobs execute my-job",
				},
			},
			wantErr: `tool "aws" is not supported`,
		},
		{
			name: "invalid_do_command",
			request: &ToolRequest{
				Do: []string{
					`run
jobs execute my-job && rmdir dir`,
				},
			},
			wantErr: `disallowed command character '&' at 2:20
disallowed command character '&' at 2:21`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			gotErr := ValidateToolRequest(tc.request)
			if diff := testutil.DiffErrString(gotErr, tc.wantErr); diff != "" {
				t.Errorf("Process %s got unexpected error: %s", tc.name, diff)
			}
		})
	}
}
