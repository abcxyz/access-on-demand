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

// handler package that handles AOD request.
package handler

import (
	"context"
	"fmt"
	"testing"
	"time"

	"cloud.google.com/go/iam/apiv1/iampb"
	"cloud.google.com/go/resourcemanager/apiv3/resourcemanagerpb"
	"github.com/abcxyz/access-on-demand/apis/v1alpha1"
	"github.com/abcxyz/pkg/testutil"
	"github.com/google/go-cmp/cmp"
	"github.com/sethvargo/go-retry"
	"google.golang.org/api/option"
	"google.golang.org/genproto/googleapis/type/expr"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/testing/protocmp"

	resourcemanager "cloud.google.com/go/resourcemanager/apiv3"
)

func TestDo(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	cases := []struct {
		name                    string
		organizationsServer     *fakeServer
		foldersServer           *fakeServer
		projectsServer          *fakeServer
		request                 *v1alpha1.IAMRequestWrapper
		customTitle             string
		wantPolicies            []*v1alpha1.IAMResponse
		wantErrSubstr           string
		wantOrganizationsPolicy *iampb.Policy
		wantFoldersPolicy       *iampb.Policy
		wantProjectsPolicy      *iampb.Policy
	}{
		{
			name: "happy_path",
			organizationsServer: &fakeServer{
				policy: &iampb.Policy{},
			},
			foldersServer: &fakeServer{
				policy: &iampb.Policy{},
			},
			projectsServer: &fakeServer{
				policy: &iampb.Policy{},
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
				Duration:  2 * time.Hour,
				StartTime: now,
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
									Title:      defaultConditionTitle,
									Expression: fmt.Sprintf("request.time < timestamp('%s')", now.Add(2*time.Hour).Format(time.RFC3339)),
								},
							},
						},
						Version: 3,
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
									Title:      defaultConditionTitle,
									Expression: fmt.Sprintf("request.time < timestamp('%s')", now.Add(2*time.Hour).Format(time.RFC3339)),
								},
							},
						},
						Version: 3,
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
									Title:      defaultConditionTitle,
									Expression: fmt.Sprintf("request.time < timestamp('%s')", now.Add(2*time.Hour).Format(time.RFC3339)),
								},
							},
						},
						Version: 3,
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
							Title:      defaultConditionTitle,
							Expression: fmt.Sprintf("request.time < timestamp('%s')", now.Add(2*time.Hour).Format(time.RFC3339)),
						},
					},
				},
				Version: 3,
			},
			wantFoldersPolicy: &iampb.Policy{
				Bindings: []*iampb.Binding{
					{
						Members: []string{
							"user:test-folder-user@example.com",
						},
						Role: "roles/cloudkms.cryptoOperator",
						Condition: &expr.Expr{
							Title:      defaultConditionTitle,
							Expression: fmt.Sprintf("request.time < timestamp('%s')", now.Add(2*time.Hour).Format(time.RFC3339)),
						},
					},
				},
				Version: 3,
			},
			wantProjectsPolicy: &iampb.Policy{
				Bindings: []*iampb.Binding{
					{
						Members: []string{
							"user:test-project-user@example.com",
						},
						Role: "roles/bigquery.dataViewer",
						Condition: &expr.Expr{
							Title:      defaultConditionTitle,
							Expression: fmt.Sprintf("request.time < timestamp('%s')", now.Add(2*time.Hour).Format(time.RFC3339)),
						},
					},
				},
				Version: 3,
			},
		},
		{
			name: "happy_path_custom_condition_title",
			organizationsServer: &fakeServer{
				policy: &iampb.Policy{},
			},
			foldersServer: &fakeServer{
				policy: &iampb.Policy{},
			},
			projectsServer: &fakeServer{
				policy: &iampb.Policy{},
			},
			request: &v1alpha1.IAMRequestWrapper{
				IAMRequest: &v1alpha1.IAMRequest{
					ResourcePolicies: []*v1alpha1.ResourcePolicy{
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
				Duration:  2 * time.Hour,
				StartTime: now,
			},
			customTitle: "custom-title",
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
									Title:      "custom-title",
									Expression: fmt.Sprintf("request.time < timestamp('%s')", now.Add(2*time.Hour).Format(time.RFC3339)),
								},
							},
						},
						Version: 3,
					},
				},
			},
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
							Title:      "custom-title",
							Expression: fmt.Sprintf("request.time < timestamp('%s')", now.Add(2*time.Hour).Format(time.RFC3339)),
						},
					},
				},
				Version: 3,
			},
		},
		{
			name: "clean_up_duplicated_members",
			organizationsServer: &fakeServer{
				policy: &iampb.Policy{
					Bindings: []*iampb.Binding{
						// Unexpired bindings to be removed.
						{
							Members: []string{
								"user:test-org-userB@example.com",
							},
							Role: "roles/accessapproval.approver",
							Condition: &expr.Expr{
								Title:      defaultConditionTitle,
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
								Title:      defaultConditionTitle,
								Expression: fmt.Sprintf("request.time < timestamp('%s')", now.Add(1*time.Hour).Format(time.RFC3339)),
							},
						},
					},
				},
			},
			foldersServer: &fakeServer{
				policy: &iampb.Policy{},
			},
			projectsServer: &fakeServer{
				policy: &iampb.Policy{},
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
				Duration:  2 * time.Hour,
				StartTime: now,
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
									Title:      defaultConditionTitle,
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
									Title:      defaultConditionTitle,
									Expression: fmt.Sprintf("request.time < timestamp('%s')", now.Add(2*time.Hour).Format(time.RFC3339)),
								},
							},
						},
						Version: 3,
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
							Title:      defaultConditionTitle,
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
							Title:      defaultConditionTitle,
							Expression: fmt.Sprintf("request.time < timestamp('%s')", now.Add(2*time.Hour).Format(time.RFC3339)),
						},
					},
				},
				Version: 3,
			},
			wantFoldersPolicy:  &iampb.Policy{},
			wantProjectsPolicy: &iampb.Policy{},
		},
		{
			name: "clean_up_expired_bindings",
			organizationsServer: &fakeServer{
				policy: &iampb.Policy{
					Bindings: []*iampb.Binding{
						// Expired bindings to be removed.
						{
							Members: []string{
								"user:test-org-userB@example.com",
							},
							Role: "roles/accessapproval.approver",
							Condition: &expr.Expr{
								Title:      defaultConditionTitle,
								Expression: fmt.Sprintf("request.time < timestamp('%s')", now.Add(-1*time.Hour).Format(time.RFC3339)),
							},
						},
					},
				},
			},
			foldersServer: &fakeServer{
				policy: &iampb.Policy{},
			},
			projectsServer: &fakeServer{
				policy: &iampb.Policy{},
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
									},
									Role: "roles/bigquery.dataViewer",
								},
							},
						},
					},
				},
				Duration:  2 * time.Hour,
				StartTime: now,
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
								Role: "roles/bigquery.dataViewer",
								Condition: &expr.Expr{
									Title:      defaultConditionTitle,
									Expression: fmt.Sprintf("request.time < timestamp('%s')", now.Add(2*time.Hour).Format(time.RFC3339)),
								},
							},
						},
						Version: 3,
					},
				},
			},
			wantOrganizationsPolicy: &iampb.Policy{
				Bindings: []*iampb.Binding{
					{
						Members: []string{
							"user:test-org-userA@example.com",
						},
						Role: "roles/bigquery.dataViewer",
						Condition: &expr.Expr{
							Title:      defaultConditionTitle,
							Expression: fmt.Sprintf("request.time < timestamp('%s')", now.Add(2*time.Hour).Format(time.RFC3339)),
						},
					},
				},
				Version: 3,
			},
			wantFoldersPolicy:  &iampb.Policy{},
			wantProjectsPolicy: &iampb.Policy{},
		},
		{
			name: "failed_clean_up_expired_bindings_invalid_expression",
			organizationsServer: &fakeServer{
				policy: &iampb.Policy{
					Bindings: []*iampb.Binding{
						{
							Members: []string{
								"user:test-org-userB@example.com",
							},
							Role: "roles/accessapproval.approver",
							Condition: &expr.Expr{
								Title:      defaultConditionTitle,
								Expression: fmt.Sprintf("request.time <= timestamp('%s')", now.Add(-1*time.Hour).Format(time.RFC3339)),
							},
						},
					},
				},
			},
			foldersServer: &fakeServer{
				policy: &iampb.Policy{},
			},
			projectsServer: &fakeServer{
				policy: &iampb.Policy{},
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
									},
									Role: "roles/bigquery.dataViewer",
								},
							},
						},
					},
				},
				Duration:  2 * time.Hour,
				StartTime: now,
			},
			wantPolicies: []*v1alpha1.IAMResponse{
				{
					Resource: "organizations/foo",
					Policy: &iampb.Policy{
						Bindings: []*iampb.Binding{
							{
								Members: []string{
									"user:test-org-userB@example.com",
								},
								Role: "roles/accessapproval.approver",
								Condition: &expr.Expr{
									Title:      defaultConditionTitle,
									Expression: fmt.Sprintf("request.time <= timestamp('%s')", now.Add(-1*time.Hour).Format(time.RFC3339)),
								},
							},
							{
								Members: []string{
									"user:test-org-userA@example.com",
								},
								Role: "roles/bigquery.dataViewer",
								Condition: &expr.Expr{
									Title:      defaultConditionTitle,
									Expression: fmt.Sprintf("request.time < timestamp('%s')", now.Add(2*time.Hour).Format(time.RFC3339)),
								},
							},
						},
						Version: 3,
					},
				},
			},
			wantOrganizationsPolicy: &iampb.Policy{
				Bindings: []*iampb.Binding{
					{
						Members: []string{
							"user:test-org-userB@example.com",
						},
						Role: "roles/accessapproval.approver",
						Condition: &expr.Expr{
							Title:      defaultConditionTitle,
							Expression: fmt.Sprintf("request.time <= timestamp('%s')", now.Add(-1*time.Hour).Format(time.RFC3339)),
						},
					},
					{
						Members: []string{
							"user:test-org-userA@example.com",
						},
						Role: "roles/bigquery.dataViewer",
						Condition: &expr.Expr{
							Title:      defaultConditionTitle,
							Expression: fmt.Sprintf("request.time < timestamp('%s')", now.Add(2*time.Hour).Format(time.RFC3339)),
						},
					},
				},
				Version: 3,
			},
			wantFoldersPolicy:  &iampb.Policy{},
			wantProjectsPolicy: &iampb.Policy{},
		},
		{
			name: "failed_clean_up_expired_bindings_wrong_expiration",
			organizationsServer: &fakeServer{
				policy: &iampb.Policy{
					Bindings: []*iampb.Binding{
						{
							Members: []string{
								"user:test-org-userB@example.com",
							},
							Role: "roles/accessapproval.approver",
							Condition: &expr.Expr{
								Title:      defaultConditionTitle,
								Expression: fmt.Sprintf("request.time < timestamp('%s')", now.Add(-1*time.Hour).Format(time.RFC850)),
							},
						},
					},
				},
			},
			foldersServer: &fakeServer{
				policy: &iampb.Policy{},
			},
			projectsServer: &fakeServer{
				policy: &iampb.Policy{},
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
									},
									Role: "roles/bigquery.dataViewer",
								},
							},
						},
					},
				},
				Duration:  2 * time.Hour,
				StartTime: now,
			},
			wantPolicies: []*v1alpha1.IAMResponse{
				{
					Resource: "organizations/foo",
					Policy: &iampb.Policy{
						Bindings: []*iampb.Binding{
							{
								Members: []string{
									"user:test-org-userB@example.com",
								},
								Role: "roles/accessapproval.approver",
								Condition: &expr.Expr{
									Title:      defaultConditionTitle,
									Expression: fmt.Sprintf("request.time < timestamp('%s')", now.Add(-1*time.Hour).Format(time.RFC850)),
								},
							},
							{
								Members: []string{
									"user:test-org-userA@example.com",
								},
								Role: "roles/bigquery.dataViewer",
								Condition: &expr.Expr{
									Title:      defaultConditionTitle,
									Expression: fmt.Sprintf("request.time < timestamp('%s')", now.Add(2*time.Hour).Format(time.RFC3339)),
								},
							},
						},
						Version: 3,
					},
				},
			},
			wantOrganizationsPolicy: &iampb.Policy{
				Bindings: []*iampb.Binding{
					{
						Members: []string{
							"user:test-org-userB@example.com",
						},
						Role: "roles/accessapproval.approver",
						Condition: &expr.Expr{
							Title:      defaultConditionTitle,
							Expression: fmt.Sprintf("request.time < timestamp('%s')", now.Add(-1*time.Hour).Format(time.RFC850)),
						},
					},
					{
						Members: []string{
							"user:test-org-userA@example.com",
						},
						Role: "roles/bigquery.dataViewer",
						Condition: &expr.Expr{
							Title:      defaultConditionTitle,
							Expression: fmt.Sprintf("request.time < timestamp('%s')", now.Add(2*time.Hour).Format(time.RFC3339)),
						},
					},
				},
				Version: 3,
			},
			wantFoldersPolicy:  &iampb.Policy{},
			wantProjectsPolicy: &iampb.Policy{},
		},
		{
			name: "ignore_non-AOD_bindings",
			organizationsServer: &fakeServer{
				policy: &iampb.Policy{},
			},
			foldersServer: &fakeServer{
				policy: &iampb.Policy{
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
			projectsServer: &fakeServer{
				policy: &iampb.Policy{},
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
				Duration:  2 * time.Hour,
				StartTime: now,
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
									Title:      defaultConditionTitle,
									Expression: fmt.Sprintf("request.time < timestamp('%s')", now.Add(2*time.Hour).Format(time.RFC3339)),
								},
							},
						},
						Version: 3,
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
							Title:      defaultConditionTitle,
							Expression: fmt.Sprintf("request.time < timestamp('%s')", now.Add(2*time.Hour).Format(time.RFC3339)),
						},
					},
				},
				Version: 3,
			},
			wantProjectsPolicy: &iampb.Policy{},
		},
		{
			name: "ignore_unrelated_roles",
			organizationsServer: &fakeServer{
				policy: &iampb.Policy{},
			},
			foldersServer: &fakeServer{
				policy: &iampb.Policy{},
			},
			projectsServer: &fakeServer{
				policy: &iampb.Policy{
					Bindings: []*iampb.Binding{
						// Binding with role that not found in the request to be kept.
						{
							Members: []string{
								"user:test-project_user@example.com",
							},
							Role: "roles/accesscontextmanager.policyAdmin",
							Condition: &expr.Expr{
								Title:      defaultConditionTitle,
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
				Duration:  2 * time.Hour,
				StartTime: now,
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
								Role: "roles/accesscontextmanager.policyAdmin",
								Condition: &expr.Expr{
									Title:      defaultConditionTitle,
									Expression: fmt.Sprintf("request.time < timestamp('%s')", now.Add(1*time.Hour).Format(time.RFC3339)),
								},
							},
							{
								Members: []string{
									"user:test-project_user@example.com",
								},
								Role: "roles/accessapproval.approver",
								Condition: &expr.Expr{
									Title:      defaultConditionTitle,
									Expression: fmt.Sprintf("request.time < timestamp('%s')", now.Add(2*time.Hour).Format(time.RFC3339)),
								},
							},
						},
						Version: 3,
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
						Role: "roles/accesscontextmanager.policyAdmin",
						Condition: &expr.Expr{
							Title:      defaultConditionTitle,
							Expression: fmt.Sprintf("request.time < timestamp('%s')", now.Add(1*time.Hour).Format(time.RFC3339)),
						},
					},
					{
						Members: []string{
							"user:test-project_user@example.com",
						},
						Role: "roles/accessapproval.approver",
						Condition: &expr.Expr{
							Title:      defaultConditionTitle,
							Expression: fmt.Sprintf("request.time < timestamp('%s')", now.Add(2*time.Hour).Format(time.RFC3339)),
						},
					},
				},
				Version: 3,
			},
		},
		{
			name: "failed_with_orgs_server_get_iam_policy_error",
			organizationsServer: &fakeServer{
				policy:          &iampb.Policy{},
				getIAMPolicyErr: fmt.Errorf("Get IAM policy encountered error: Internal Server Error"),
			},
			foldersServer: &fakeServer{
				policy: &iampb.Policy{},
			},
			projectsServer: &fakeServer{
				policy: &iampb.Policy{},
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
				Duration:  2 * time.Hour,
				StartTime: now,
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
									Title:      defaultConditionTitle,
									Expression: fmt.Sprintf("request.time < timestamp('%s')", now.Add(2*time.Hour).Format(time.RFC3339)),
								},
							},
						},
						Version: 3,
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
							Title:      defaultConditionTitle,
							Expression: fmt.Sprintf("request.time < timestamp('%s')", now.Add(2*time.Hour).Format(time.RFC3339)),
						},
					},
				},
				Version: 3,
			},
		},
		{
			name: "failed_with_projects_server_set_iam_policy_error",
			organizationsServer: &fakeServer{
				policy: &iampb.Policy{},
			},
			foldersServer: &fakeServer{
				policy: &iampb.Policy{},
			},
			projectsServer: &fakeServer{
				policy:          &iampb.Policy{},
				setIAMPolicyErr: fmt.Errorf("Set IAM policy encountered error: Internal Server Error"),
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
				Duration:  1 * time.Hour,
				StartTime: now,
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
									Title:      defaultConditionTitle,
									Expression: fmt.Sprintf("request.time < timestamp('%s')", now.Add(1*time.Hour).Format(time.RFC3339)),
								},
							},
						},
						Version: 3,
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
							Title:      defaultConditionTitle,
							Expression: fmt.Sprintf("request.time < timestamp('%s')", now.Add(1*time.Hour).Format(time.RFC3339)),
						},
					},
				},
				Version: 3,
			},
			wantProjectsPolicy: &iampb.Policy{},
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()

			fakeOrganizationsClient, fakeFoldersClient, fakeProjectsClient := setupFakeClients(
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

			// Run test.
			gotPolicies, gotErr := h.Do(ctx, tc.request)
			if diff := testutil.DiffErrString(gotErr, tc.wantErrSubstr); diff != "" {
				t.Errorf("Process(%+v) got unexpected error substring: %v", tc.name, diff)
			}
			// Verify that the Policies are modified accordingly.
			if diff := cmp.Diff(tc.wantPolicies, gotPolicies, protocmp.Transform()); diff != "" {
				t.Errorf("Process(%+v) got diff (-want, +got): %v", tc.name, diff)
			}

			if diff := cmp.Diff(tc.wantOrganizationsPolicy, tc.organizationsServer.policy, protocmp.Transform()); diff != "" {
				t.Errorf("Process(%+v) got org policy diff (-want, +got): %v", tc.name, diff)
			}

			if diff := cmp.Diff(tc.wantFoldersPolicy, tc.foldersServer.policy, protocmp.Transform()); diff != "" {
				t.Errorf("Process(%+v) got folder policy diff (-want, +got): %v", tc.name, diff)
			}

			if diff := cmp.Diff(tc.wantProjectsPolicy, tc.projectsServer.policy, protocmp.Transform()); diff != "" {
				t.Errorf("Process(%+v) got project policy diff (-want, +got): %v", tc.name, diff)
			}
		})
	}
}

func setupFakeClients(t *testing.T, ctx context.Context, s1, s2, s3 *fakeServer) (c1, c2, c3 IAMClient) {
	t.Helper()

	ss := []*fakeServer{s1, s2, s3}
	cs := make([]IAMClient, 3)
	for i, e := range ss {
		// Setup fake servers.
		addr, conn := testutil.FakeGRPCServer(t, func(s *grpc.Server) {
			// Use ProjectsServer since it has the same APIs we need.
			resourcemanagerpb.RegisterProjectsServer(s, e)
		})
		t.Cleanup(func() {
			conn.Close()
		})
		// Use ProjectsClient since it has the same APIs we need.
		fakeClient, err := resourcemanager.NewProjectsClient(ctx, option.WithGRPCConn(conn))
		if err != nil {
			t.Fatalf("creating client for fake at %q: %v", addr, err)
		}
		cs[i] = fakeClient
	}
	return cs[0], cs[1], cs[2]
}

type fakeServer struct {
	// Use ProjectsServer since it has the same APIs we need.
	resourcemanagerpb.UnimplementedProjectsServer

	policy          *iampb.Policy
	getIAMPolicyErr error
	setIAMPolicyErr error
}

func (s *fakeServer) GetIamPolicy(context.Context, *iampb.GetIamPolicyRequest) (*iampb.Policy, error) {
	if s.getIAMPolicyErr != nil {
		return nil, s.getIAMPolicyErr
	}
	return s.policy, s.getIAMPolicyErr
}

func (s *fakeServer) SetIamPolicy(c context.Context, r *iampb.SetIamPolicyRequest) (*iampb.Policy, error) {
	if s.setIAMPolicyErr != nil {
		return nil, s.setIAMPolicyErr
	}
	s.policy = r.Policy
	return s.policy, s.setIAMPolicyErr
}
