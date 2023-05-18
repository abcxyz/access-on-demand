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

// handler package that handles IAM request and IAM policy updates.
package handler

import (
	"context"
	"fmt"
	"testing"
	"time"

	"cloud.google.com/go/iam/apiv1/iampb"
	"github.com/abcxyz/access-on-demand/apis/v1alpha1"
	"github.com/abcxyz/access-on-demand/pkg/testutil"
	"github.com/google/go-cmp/cmp"
	"github.com/sethvargo/go-retry"
	"google.golang.org/genproto/googleapis/type/expr"
	"google.golang.org/protobuf/testing/protocmp"

	pkgtestutil "github.com/abcxyz/pkg/testutil"
)

func TestDo(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	cases := []struct {
		name                    string
		organizationsServer     *testutil.FakeServer
		foldersServer           *testutil.FakeServer
		projectsServer          *testutil.FakeServer
		request                 *v1alpha1.IAMRequestWrapper
		wantPolicies            []*v1alpha1.IAMResponse
		wantErrSubstr           string
		wantOrganizationsPolicy *iampb.Policy
		wantFoldersPolicy       *iampb.Policy
		wantProjectsPolicy      *iampb.Policy
	}{
		{
			name: "happy_path",
			organizationsServer: &testutil.FakeServer{
				Policy: &iampb.Policy{},
			},
			foldersServer: &testutil.FakeServer{
				Policy: &iampb.Policy{},
			},
			projectsServer: &testutil.FakeServer{
				Policy: &iampb.Policy{},
			},
			request: &v1alpha1.IAMRequestWrapper{
				IAMRequest: &v1alpha1.IAMRequest{
					ResourcePolicies: []*v1alpha1.ResourcePolicy{
						{
							Resource: "organizations/foo",
							Bindings: []*v1alpha1.Binding{
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
				Duration: 2 * time.Hour,
			},
			wantPolicies: []*v1alpha1.IAMResponse{
				{
					Resource: "organizations/foo",
					Policy: &iampb.Policy{
						Bindings: []*iampb.Binding{
							{
								Members: []string{
									"user:test-org-userA@example.com",
									"user:test-org-userB@example.com",
								},
								Role: "roles/accessapproval.approver",
								Condition: &expr.Expr{
									Title:      ConditionTitle,
									Expression: fmt.Sprintf("request.time < timestamp('%s')", now.Add(2*time.Hour).Format(time.RFC3339)),
								},
							},
						},
					},
				},
				{
					Resource: "folders/bar",
					Policy: &iampb.Policy{
						Bindings: []*iampb.Binding{
							{
								Members: []string{
									"user:test-folder-user@example.com",
								},
								Role: "roles/cloudkms.cryptoOperator",
								Condition: &expr.Expr{
									Title:      ConditionTitle,
									Expression: fmt.Sprintf("request.time < timestamp('%s')", now.Add(2*time.Hour).Format(time.RFC3339)),
								},
							},
						},
					},
				},
				{
					Resource: "projects/baz",
					Policy: &iampb.Policy{
						Bindings: []*iampb.Binding{
							{
								Members: []string{
									"user:test-project-user@example.com",
								},
								Role: "roles/bigquery.dataViewer",
								Condition: &expr.Expr{
									Title:      ConditionTitle,
									Expression: fmt.Sprintf("request.time < timestamp('%s')", now.Add(2*time.Hour).Format(time.RFC3339)),
								},
							},
						},
					},
				},
			},
			wantOrganizationsPolicy: &iampb.Policy{
				Bindings: []*iampb.Binding{
					{
						Members: []string{
							"user:test-org-userA@example.com",
							"user:test-org-userB@example.com",
						},
						Role: "roles/accessapproval.approver",
						Condition: &expr.Expr{
							Title:      ConditionTitle,
							Expression: fmt.Sprintf("request.time < timestamp('%s')", now.Add(2*time.Hour).Format(time.RFC3339)),
						},
					},
				},
			},
			wantFoldersPolicy: &iampb.Policy{
				Bindings: []*iampb.Binding{
					{
						Members: []string{
							"user:test-folder-user@example.com",
						},
						Role: "roles/cloudkms.cryptoOperator",
						Condition: &expr.Expr{
							Title:      ConditionTitle,
							Expression: fmt.Sprintf("request.time < timestamp('%s')", now.Add(2*time.Hour).Format(time.RFC3339)),
						},
					},
				},
			},
			wantProjectsPolicy: &iampb.Policy{
				Bindings: []*iampb.Binding{
					{
						Members: []string{
							"user:test-project-user@example.com",
						},
						Role: "roles/bigquery.dataViewer",
						Condition: &expr.Expr{
							Title:      ConditionTitle,
							Expression: fmt.Sprintf("request.time < timestamp('%s')", now.Add(2*time.Hour).Format(time.RFC3339)),
						},
					},
				},
			},
		},
		{
			name: "clean_up_duplicated_members",
			organizationsServer: &testutil.FakeServer{
				Policy: &iampb.Policy{
					Bindings: []*iampb.Binding{
						// Unexpired bindings to be removed.
						{
							Members: []string{
								"user:test-org-userB@example.com",
							},
							Role: "roles/accessapproval.approver",
							Condition: &expr.Expr{
								Title:      ConditionTitle,
								Expression: fmt.Sprintf("request.time < timestamp('%s')", now.Add(1*time.Hour).Format(time.RFC3339)),
							},
						},
						// Unexpired bindings to be de-dupped.
						{
							Members: []string{
								"user:test-org-userA@example.com",
								"user:test-org-userC@example.com",
							},
							Role: "roles/accessapproval.approver",
							Condition: &expr.Expr{
								Title:      ConditionTitle,
								Expression: fmt.Sprintf("request.time < timestamp('%s')", now.Add(1*time.Hour).Format(time.RFC3339)),
							},
						},
					},
				},
			},
			foldersServer: &testutil.FakeServer{
				Policy: &iampb.Policy{},
			},
			projectsServer: &testutil.FakeServer{
				Policy: &iampb.Policy{},
			},
			request: &v1alpha1.IAMRequestWrapper{
				IAMRequest: &v1alpha1.IAMRequest{
					ResourcePolicies: []*v1alpha1.ResourcePolicy{
						{
							Resource: "organizations/foo",
							Bindings: []*v1alpha1.Binding{
								{
									Members: []string{
										"user:test-org-userA@example.com",
										"user:test-org-userB@example.com",
									},
									Role: "roles/accessapproval.approver",
								},
								// Dup bindings in the request to be removed.
								{
									Members: []string{
										"user:test-org-userB@example.com",
									},
									Role: "roles/accessapproval.approver",
								},
							},
						},
					},
				},
				Duration: 2 * time.Hour,
			},
			wantPolicies: []*v1alpha1.IAMResponse{
				{
					Resource: "organizations/foo",
					Policy: &iampb.Policy{
						Bindings: []*iampb.Binding{
							{
								Members: []string{
									"user:test-org-userC@example.com",
								},
								Role: "roles/accessapproval.approver",
								Condition: &expr.Expr{
									Title:      ConditionTitle,
									Expression: fmt.Sprintf("request.time < timestamp('%s')", now.Add(1*time.Hour).Format(time.RFC3339)),
								},
							},
							{
								Members: []string{
									"user:test-org-userA@example.com",
									"user:test-org-userB@example.com",
								},
								Role: "roles/accessapproval.approver",
								Condition: &expr.Expr{
									Title:      ConditionTitle,
									Expression: fmt.Sprintf("request.time < timestamp('%s')", now.Add(2*time.Hour).Format(time.RFC3339)),
								},
							},
						},
					},
				},
			},
			wantOrganizationsPolicy: &iampb.Policy{
				Bindings: []*iampb.Binding{
					{
						Members: []string{
							"user:test-org-userC@example.com",
						},
						Role: "roles/accessapproval.approver",
						Condition: &expr.Expr{
							Title:      ConditionTitle,
							Expression: fmt.Sprintf("request.time < timestamp('%s')", now.Add(1*time.Hour).Format(time.RFC3339)),
						},
					},
					{
						Members: []string{
							"user:test-org-userA@example.com",
							"user:test-org-userB@example.com",
						},
						Role: "roles/accessapproval.approver",
						Condition: &expr.Expr{
							Title:      ConditionTitle,
							Expression: fmt.Sprintf("request.time < timestamp('%s')", now.Add(2*time.Hour).Format(time.RFC3339)),
						},
					},
				},
			},
			wantFoldersPolicy:  &iampb.Policy{},
			wantProjectsPolicy: &iampb.Policy{},
		},
		{
			name: "ignore_non-AOD_bindings",
			organizationsServer: &testutil.FakeServer{
				Policy: &iampb.Policy{},
			},
			foldersServer: &testutil.FakeServer{
				Policy: &iampb.Policy{
					// Non-AOD bindings.
					Bindings: []*iampb.Binding{
						{
							Members: []string{
								"user:test-folder-user@example.com",
							},
							Role: "roles/accessapproval.approver",
						},
					},
				},
			},
			projectsServer: &testutil.FakeServer{
				Policy: &iampb.Policy{},
			},
			request: &v1alpha1.IAMRequestWrapper{
				IAMRequest: &v1alpha1.IAMRequest{
					ResourcePolicies: []*v1alpha1.ResourcePolicy{
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
					},
				},
				Duration: 2 * time.Hour,
			},
			wantPolicies: []*v1alpha1.IAMResponse{
				{
					Resource: "folders/bar",
					Policy: &iampb.Policy{
						Bindings: []*iampb.Binding{
							{
								Members: []string{
									"user:test-folder-user@example.com",
								},
								Role: "roles/accessapproval.approver",
							},
							{
								Members: []string{
									"user:test-folder-user@example.com",
								},
								Role: "roles/cloudkms.cryptoOperator",
								Condition: &expr.Expr{
									Title:      ConditionTitle,
									Expression: fmt.Sprintf("request.time < timestamp('%s')", now.Add(2*time.Hour).Format(time.RFC3339)),
								},
							},
						},
					},
				},
			},
			wantOrganizationsPolicy: &iampb.Policy{},
			wantFoldersPolicy: &iampb.Policy{
				Bindings: []*iampb.Binding{
					{
						Members: []string{
							"user:test-folder-user@example.com",
						},
						Role: "roles/accessapproval.approver",
					},
					{
						Members: []string{
							"user:test-folder-user@example.com",
						},
						Role: "roles/cloudkms.cryptoOperator",
						Condition: &expr.Expr{
							Title:      ConditionTitle,
							Expression: fmt.Sprintf("request.time < timestamp('%s')", now.Add(2*time.Hour).Format(time.RFC3339)),
						},
					},
				},
			},
			wantProjectsPolicy: &iampb.Policy{},
		},
		{
			name: "ignore_unrelated_roles",
			organizationsServer: &testutil.FakeServer{
				Policy: &iampb.Policy{},
			},
			foldersServer: &testutil.FakeServer{
				Policy: &iampb.Policy{},
			},
			projectsServer: &testutil.FakeServer{
				Policy: &iampb.Policy{
					Bindings: []*iampb.Binding{
						// Binding with role that not found in the request to be kept.
						{
							Members: []string{
								"user:test-project_user@example.com",
							},
							Role: "roles/accesscontextmanager.PolicyAdmin",
							Condition: &expr.Expr{
								Title:      ConditionTitle,
								Expression: fmt.Sprintf("request.time < timestamp('%s')", now.Add(1*time.Hour).Format(time.RFC3339)),
							},
						},
					},
				},
			},
			request: &v1alpha1.IAMRequestWrapper{
				IAMRequest: &v1alpha1.IAMRequest{
					ResourcePolicies: []*v1alpha1.ResourcePolicy{
						{
							Resource: "projects/baz",
							Bindings: []*v1alpha1.Binding{
								{
									Members: []string{
										"user:test-project_user@example.com",
									},
									Role: "roles/accessapproval.approver",
								},
							},
						},
					},
				},
				Duration: 2 * time.Hour,
			},
			wantPolicies: []*v1alpha1.IAMResponse{
				{
					Resource: "projects/baz",
					Policy: &iampb.Policy{
						Bindings: []*iampb.Binding{
							{
								Members: []string{
									"user:test-project_user@example.com",
								},
								Role: "roles/accesscontextmanager.PolicyAdmin",
								Condition: &expr.Expr{
									Title:      ConditionTitle,
									Expression: fmt.Sprintf("request.time < timestamp('%s')", now.Add(1*time.Hour).Format(time.RFC3339)),
								},
							},
							{
								Members: []string{
									"user:test-project_user@example.com",
								},
								Role: "roles/accessapproval.approver",
								Condition: &expr.Expr{
									Title:      ConditionTitle,
									Expression: fmt.Sprintf("request.time < timestamp('%s')", now.Add(2*time.Hour).Format(time.RFC3339)),
								},
							},
						},
					},
				},
			},
			wantOrganizationsPolicy: &iampb.Policy{},
			wantFoldersPolicy:       &iampb.Policy{},
			wantProjectsPolicy: &iampb.Policy{
				Bindings: []*iampb.Binding{
					{
						Members: []string{
							"user:test-project_user@example.com",
						},
						Role: "roles/accesscontextmanager.PolicyAdmin",
						Condition: &expr.Expr{
							Title:      ConditionTitle,
							Expression: fmt.Sprintf("request.time < timestamp('%s')", now.Add(1*time.Hour).Format(time.RFC3339)),
						},
					},
					{
						Members: []string{
							"user:test-project_user@example.com",
						},
						Role: "roles/accessapproval.approver",
						Condition: &expr.Expr{
							Title:      ConditionTitle,
							Expression: fmt.Sprintf("request.time < timestamp('%s')", now.Add(2*time.Hour).Format(time.RFC3339)),
						},
					},
				},
			},
		},
		{
			name: "failed_with_orgs_server_get_iam_policy_error",
			organizationsServer: &testutil.FakeServer{
				Policy:          &iampb.Policy{},
				GetIAMPolicyErr: fmt.Errorf("Get IAM policy encountered error: Internal Server Error"),
			},
			foldersServer: &testutil.FakeServer{
				Policy: &iampb.Policy{},
			},
			projectsServer: &testutil.FakeServer{
				Policy: &iampb.Policy{},
			},
			request: &v1alpha1.IAMRequestWrapper{
				IAMRequest: &v1alpha1.IAMRequest{
					ResourcePolicies: []*v1alpha1.ResourcePolicy{
						{
							Resource: "organizations/foo",
							Bindings: []*v1alpha1.Binding{
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
				Duration: 2 * time.Hour,
			},
			wantPolicies: []*v1alpha1.IAMResponse{
				{
					Resource: "projects/baz",
					Policy: &iampb.Policy{
						Bindings: []*iampb.Binding{
							{
								Members: []string{
									"user:test-project-user@example.com",
								},
								Role: "roles/bigquery.dataViewer",
								Condition: &expr.Expr{
									Title:      ConditionTitle,
									Expression: fmt.Sprintf("request.time < timestamp('%s')", now.Add(2*time.Hour).Format(time.RFC3339)),
								},
							},
						},
					},
				},
			},
			wantErrSubstr:           "Get IAM policy encountered error: Internal Server Error",
			wantOrganizationsPolicy: &iampb.Policy{},
			wantFoldersPolicy:       &iampb.Policy{},
			wantProjectsPolicy: &iampb.Policy{
				Bindings: []*iampb.Binding{
					{
						Members: []string{
							"user:test-project-user@example.com",
						},
						Role: "roles/bigquery.dataViewer",
						Condition: &expr.Expr{
							Title:      ConditionTitle,
							Expression: fmt.Sprintf("request.time < timestamp('%s')", now.Add(2*time.Hour).Format(time.RFC3339)),
						},
					},
				},
			},
		},
		{
			name: "failed_with_projects_server_set_iam_policy_error",
			organizationsServer: &testutil.FakeServer{
				Policy: &iampb.Policy{},
			},
			foldersServer: &testutil.FakeServer{
				Policy: &iampb.Policy{},
			},
			projectsServer: &testutil.FakeServer{
				Policy:          &iampb.Policy{},
				SetIAMPolicyErr: fmt.Errorf("Set IAM policy encountered error: Internal Server Error"),
			},
			request: &v1alpha1.IAMRequestWrapper{
				IAMRequest: &v1alpha1.IAMRequest{
					ResourcePolicies: []*v1alpha1.ResourcePolicy{
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
				Duration: 1 * time.Hour,
			},
			wantPolicies: []*v1alpha1.IAMResponse{
				{
					Resource: "folders/bar",
					Policy: &iampb.Policy{
						Bindings: []*iampb.Binding{
							{
								Members: []string{
									"user:test-folder-user@example.com",
								},
								Role: "roles/cloudkms.cryptoOperator",
								Condition: &expr.Expr{
									Title:      ConditionTitle,
									Expression: fmt.Sprintf("request.time < timestamp('%s')", now.Add(1*time.Hour).Format(time.RFC3339)),
								},
							},
						},
					},
				},
			},
			wantErrSubstr:           "Set IAM policy encountered error: Internal Server Error",
			wantOrganizationsPolicy: &iampb.Policy{},
			wantFoldersPolicy: &iampb.Policy{
				Bindings: []*iampb.Binding{
					{
						Members: []string{
							"user:test-folder-user@example.com",
						},
						Role: "roles/cloudkms.cryptoOperator",
						Condition: &expr.Expr{
							Title:      ConditionTitle,
							Expression: fmt.Sprintf("request.time < timestamp('%s')", now.Add(1*time.Hour).Format(time.RFC3339)),
						},
					},
				},
			},
			wantProjectsPolicy: &iampb.Policy{},
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()

			fakeOrganizationsClient, fakeFoldersClient, fakeProjectsClient := testutil.SetupFakeClients(
				t,
				ctx,
				tc.organizationsServer,
				tc.foldersServer,
				tc.projectsServer,
			)
			h, err := NewIAMHandler(
				ctx,
				fakeOrganizationsClient,
				fakeFoldersClient,
				fakeProjectsClient,
				WithRetry(retry.WithMaxRetries(0, retry.NewFibonacci(500*time.Millisecond))),
			)
			if err != nil {
				t.Fatalf("failed to create IAMHandler: %v", err)
			}

			// Run testutil.
			gotPolicies, gotErr := h.Do(ctx, tc.request)
			if diff := pkgtestutil.DiffErrString(gotErr, tc.wantErrSubstr); diff != "" {
				t.Errorf("Process(%+v) got unexpected error substring: %v", tc.name, diff)
			}
			// Verify that the Policies are modified accordingly.
			if diff := cmp.Diff(tc.wantPolicies, gotPolicies, protocmp.Transform()); diff != "" {
				t.Errorf("Process(%+v) got diff (-want, +got): %v", tc.name, diff)
			}

			if diff := cmp.Diff(tc.wantOrganizationsPolicy, tc.organizationsServer.Policy, protocmp.Transform()); diff != "" {
				t.Errorf("Process(%+v) got org policy diff (-want, +got): %v", tc.name, diff)
			}

			if diff := cmp.Diff(tc.wantFoldersPolicy, tc.foldersServer.Policy, protocmp.Transform()); diff != "" {
				t.Errorf("Process(%+v) got folder policy diff (-want, +got): %v", tc.name, diff)
			}

			if diff := cmp.Diff(tc.wantProjectsPolicy, tc.projectsServer.Policy, protocmp.Transform()); diff != "" {
				t.Errorf("Process(%+v) got project policy diff (-want, +got): %v", tc.name, diff)
			}
		})
	}
}
