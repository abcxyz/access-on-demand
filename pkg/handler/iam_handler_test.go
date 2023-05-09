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
	resourcemanager "cloud.google.com/go/resourcemanager/apiv3"
	"cloud.google.com/go/resourcemanager/apiv3/resourcemanagerpb"
	"github.com/abcxyz/access-on-demand/apis/v1alpha1"
	"github.com/abcxyz/pkg/testutil"
	"github.com/google/go-cmp/cmp"
	"google.golang.org/api/option"
	"google.golang.org/genproto/googleapis/type/expr"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestDo(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name           string
		orgsServer     *fakeOrgsServer
		foldersServer  *fakeFoldersServer
		projectsServer *fakeProjectsServer
		request        *v1alpha1.IAMRequestWrapper
		wantPolicies   []*v1alpha1.IAMResponse
		wantErrSubstr  string
	}{
		{
			name: "success",
			orgsServer: &fakeOrgsServer{
				policy: &iampb.Policy{
					Bindings: []*iampb.Binding{
						// Non-AOD bindings.
						{
							Members: []string{
								"user:test-org-userA@example.com",
							},
							Role: "roles/accessapproval.approver",
						},
						// Unexpired bindings to be de-dupped.
						{
							Members: []string{
								"user:test-org-userB@example.com",
							},
							Role: "roles/accessapproval.approver",
							Condition: &expr.Expr{
								Title:      conditionTitle,
								Expression: fmt.Sprintf("request.time < timestamp('%s')", time.Now().Add(1*time.Hour).Format(time.RFC3339)),
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
								Title:      conditionTitle,
								Expression: fmt.Sprintf("request.time < timestamp('%s')", time.Now().Add(1*time.Hour).Format(time.RFC3339)),
							},
						},
					},
				},
			},
			foldersServer: &fakeFoldersServer{
				policy: &iampb.Policy{},
			},
			projectsServer: &fakeProjectsServer{
				policy: &iampb.Policy{},
			},
			request: &v1alpha1.IAMRequestWrapper{
				Request: &v1alpha1.IAMRequest{
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
								},
								Role: "roles/accessapproval.approver",
							},
							{
								Members: []string{
									"user:test-org-userC@example.com",
								},
								Role: "roles/accessapproval.approver",
								Condition: &expr.Expr{
									Title:      conditionTitle,
									Expression: fmt.Sprintf("request.time < timestamp('%s')", time.Now().Add(1*time.Hour).Format(time.RFC3339)),
								},
							},
							{
								Members: []string{
									"user:test-org-userA@example.com",
									"user:test-org-userB@example.com",
								},
								Role: "roles/accessapproval.approver",
								Condition: &expr.Expr{
									Title:      conditionTitle,
									Expression: fmt.Sprintf("request.time < timestamp('%s')", time.Now().Add(2*time.Hour).Format(time.RFC3339)),
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
									Title:      conditionTitle,
									Expression: fmt.Sprintf("request.time < timestamp('%s')", time.Now().Add(2*time.Hour).Format(time.RFC3339)),
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
									Title:      conditionTitle,
									Expression: fmt.Sprintf("request.time < timestamp('%s')", time.Now().Add(2*time.Hour).Format(time.RFC3339)),
								},
							},
						},
					},
				},
			},
		},
		{
			name: "failed_with_orgs_server_get_iam_policy_error",
			orgsServer: &fakeOrgsServer{
				policy:          &iampb.Policy{},
				getIAMPolicyErr: fmt.Errorf("Get IAM policy encountered error: Internal Server Error"),
			},
			foldersServer: &fakeFoldersServer{
				policy: &iampb.Policy{},
			},
			projectsServer: &fakeProjectsServer{
				policy: &iampb.Policy{},
			},
			request: &v1alpha1.IAMRequestWrapper{
				Request: &v1alpha1.IAMRequest{
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
									Title:      conditionTitle,
									Expression: fmt.Sprintf("request.time < timestamp('%s')", time.Now().Add(2*time.Hour).Format(time.RFC3339)),
								},
							},
						},
					},
				},
			},
			wantErrSubstr: "Get IAM policy encountered error: Internal Server Error",
		},
		{
			name: "failed_with_projects_server_set_iam_policy_error",
			orgsServer: &fakeOrgsServer{
				policy: &iampb.Policy{},
			},
			foldersServer: &fakeFoldersServer{
				policy: &iampb.Policy{},
			},
			projectsServer: &fakeProjectsServer{
				policy:          &iampb.Policy{},
				setIAMPolicyErr: fmt.Errorf("Set IAM policy encountered error: Internal Server Error"),
			},
			request: &v1alpha1.IAMRequestWrapper{
				Request: &v1alpha1.IAMRequest{
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
									Title:      conditionTitle,
									Expression: fmt.Sprintf("request.time < timestamp('%s')", time.Now().Add(1*time.Hour).Format(time.RFC3339)),
								},
							},
						},
					},
				},
			},
			wantErrSubstr: "Set IAM policy encountered error: Internal Server Error",
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()

			// Setup fake servers.
			addrOrg, connOrg := testutil.FakeGRPCServer(t, func(s *grpc.Server) {
				resourcemanagerpb.RegisterOrganizationsServer(s, tc.orgsServer)
			})
			addrFol, connFol := testutil.FakeGRPCServer(t, func(s *grpc.Server) {
				resourcemanagerpb.RegisterFoldersServer(s, tc.foldersServer)
			})
			addrPro, connPro := testutil.FakeGRPCServer(t, func(s *grpc.Server) {
				resourcemanagerpb.RegisterProjectsServer(s, tc.projectsServer)
			})

			// Setup fake clients.
			fakeOrgClient, err := resourcemanager.NewOrganizationsClient(ctx, option.WithGRPCConn(connOrg))
			if err != nil {
				t.Fatalf("creating client for fake at %q: %v", addrOrg, err)
			}
			fakeFolClient, err := resourcemanager.NewFoldersClient(ctx, option.WithGRPCConn(connFol))
			if err != nil {
				t.Fatalf("creating client for fake at %q: %v", addrFol, err)
			}
			fakeProClient, err := resourcemanager.NewProjectsClient(ctx, option.WithGRPCConn(connPro))
			if err != nil {
				t.Fatalf("creating client for fake at %q: %v", addrPro, err)
			}

			h, err := NewIAMHandler(
				ctx,
				WithOrganizationsClient(fakeOrgClient),
				WithFoldersClient(fakeFolClient),
				WithProjectsClient(fakeProClient),
			)
			if err != nil {
				t.Fatalf("failed to create IAMHandler: %v", err)
			}

			// Run test.
			gotPolicies, gotErr := h.Do(ctx, tc.request)
			if diff := testutil.DiffErrString(gotErr, tc.wantErrSubstr); diff != "" {
				t.Errorf("Process(%+v) got unexpected error substring: %v", tc.name, diff)
			}
			// Verify that the Policy is modified accordingly.
			if diff := cmp.Diff(tc.wantPolicies, gotPolicies, protocmp.Transform()); diff != "" {
				t.Errorf("Process(%+v) got diff (-want, +got): %v", tc.name, diff)
			}

			if err := h.Cleanup(); err != nil {
				t.Fatalf("failed to clean up handler: %v", err)
			}
		})
	}
}

type fakeOrgsServer struct {
	resourcemanagerpb.UnimplementedOrganizationsServer

	policy          *iampb.Policy
	getIAMPolicyErr error
	setIAMPolicyErr error
}

func (s *fakeOrgsServer) GetIamPolicy(context.Context, *iampb.GetIamPolicyRequest) (*iampb.Policy, error) {
	return s.policy, s.getIAMPolicyErr
}

func (s *fakeOrgsServer) SetIamPolicy(c context.Context, r *iampb.SetIamPolicyRequest) (*iampb.Policy, error) {
	s.policy = r.Policy
	return s.policy, s.setIAMPolicyErr
}

type fakeFoldersServer struct {
	resourcemanagerpb.UnimplementedFoldersServer

	policy          *iampb.Policy
	getIAMPolicyErr error
	setIAMPolicyErr error
}

func (s *fakeFoldersServer) GetIamPolicy(context.Context, *iampb.GetIamPolicyRequest) (*iampb.Policy, error) {
	return s.policy, s.getIAMPolicyErr
}

func (s *fakeFoldersServer) SetIamPolicy(c context.Context, r *iampb.SetIamPolicyRequest) (*iampb.Policy, error) {
	s.policy = r.Policy
	return s.policy, s.setIAMPolicyErr
}

type fakeProjectsServer struct {
	resourcemanagerpb.UnimplementedProjectsServer

	policy          *iampb.Policy
	getIAMPolicyErr error
	setIAMPolicyErr error
}

func (s *fakeProjectsServer) GetIamPolicy(context.Context, *iampb.GetIamPolicyRequest) (*iampb.Policy, error) {
	return s.policy, s.getIAMPolicyErr
}

func (s *fakeProjectsServer) SetIamPolicy(c context.Context, r *iampb.SetIamPolicyRequest) (*iampb.Policy, error) {
	s.policy = r.Policy
	return s.policy, s.setIAMPolicyErr
}
