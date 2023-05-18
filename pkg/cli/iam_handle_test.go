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

	"cloud.google.com/go/iam/apiv1/iampb"
	"github.com/abcxyz/access-on-demand/pkg/handler"
	"github.com/abcxyz/access-on-demand/pkg/testutil"
	"github.com/abcxyz/pkg/logging"
	"github.com/google/go-cmp/cmp"
	"google.golang.org/genproto/googleapis/type/expr"
	"google.golang.org/protobuf/testing/protocmp"

	pkgtestutil "github.com/abcxyz/pkg/testutil"
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
    role: roles/accessapproval.approver
  - members:
    - user:test-org-userA@example.com
    - user:test-org-userB@example.com
    role: roles/cloudkms.cryptoOperator
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
		t.Cleanup(func() {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		})
	}

	now := time.Now().UTC()
	cases := []struct {
		name                    string
		args                    []string
		fileData                []byte
		organizationsServer     *testutil.FakeServer
		foldersServer           *testutil.FakeServer
		projectsServer          *testutil.FakeServer
		wantOrganizationsPolicy *iampb.Policy
		wantFoldersPolicy       *iampb.Policy
		wantProjectsPolicy      *iampb.Policy
		expOut                  string
		expErr                  string
	}{
		{
			name: "success",
			args: []string{"-path", filepath.Join(dir, "valid.yaml"), "-duration", "2h"},
			organizationsServer: &testutil.FakeServer{
				Policy: &iampb.Policy{},
			},
			foldersServer: &testutil.FakeServer{
				Policy: &iampb.Policy{},
			},
			projectsServer: &testutil.FakeServer{
				Policy: &iampb.Policy{},
			},
			expOut: "IAM request handled successfully",
			wantOrganizationsPolicy: &iampb.Policy{
				Bindings: []*iampb.Binding{
					{
						Members: []string{
							"user:test-org-userA@example.com",
							"user:test-org-userB@example.com",
						},
						Role: "roles/accessapproval.approver",
						Condition: &expr.Expr{
							Title:      handler.ConditionTitle,
							Expression: fmt.Sprintf("request.time < timestamp('%s')", now.Add(2*time.Hour).Format(time.RFC3339)),
						},
					},
					{
						Members: []string{
							"user:test-org-userA@example.com",
							"user:test-org-userB@example.com",
						},
						Role: "roles/cloudkms.cryptoOperator",
						Condition: &expr.Expr{
							Title:      handler.ConditionTitle,
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
							Title:      handler.ConditionTitle,
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
							Title:      handler.ConditionTitle,
							Expression: fmt.Sprintf("request.time < timestamp('%s')", now.Add(2*time.Hour).Format(time.RFC3339)),
						},
					},
				},
			},
		},
		{
			name:                "unexpected_args",
			args:                []string{"foo"},
			expErr:              `unexpected arguments: [foo]`,
			organizationsServer: &testutil.FakeServer{},
			foldersServer:       &testutil.FakeServer{},
			projectsServer:      &testutil.FakeServer{},
		},
		{
			name:                "missing_path",
			args:                []string{},
			expErr:              `path is required`,
			organizationsServer: &testutil.FakeServer{},
			foldersServer:       &testutil.FakeServer{},
			projectsServer:      &testutil.FakeServer{},
		},
		{
			name:                "missing_duration",
			args:                []string{"-path", filepath.Join(dir, "valid.yaml")},
			expErr:              `duration is required`,
			organizationsServer: &testutil.FakeServer{},
			foldersServer:       &testutil.FakeServer{},
			projectsServer:      &testutil.FakeServer{},
		},
		{
			name:                "invalid_duration",
			args:                []string{"-path", filepath.Join(dir, "valid.yaml"), "-duration", "-2h"},
			expErr:              "a positive duration is required",
			organizationsServer: &testutil.FakeServer{},
			foldersServer:       &testutil.FakeServer{},
			projectsServer:      &testutil.FakeServer{},
		},
		{
			name:                "invalid_yaml",
			args:                []string{"-path", filepath.Join(dir, "invalid.yaml"), "-duration", "2h"},
			expErr:              "failed to unmarshal yaml to IAMRequest",
			organizationsServer: &testutil.FakeServer{},
			foldersServer:       &testutil.FakeServer{},
			projectsServer:      &testutil.FakeServer{},
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := logging.WithLogger(context.Background(), logging.TestLogger(t))

			var cmd IAMHandleCommand
			cmd.handler = testSetupHandler(t, ctx, tc.organizationsServer, tc.foldersServer, tc.projectsServer)
			_, stdout, _ := cmd.Pipe()

			args := append([]string{}, tc.args...)

			err := cmd.Run(ctx, args)
			if diff := pkgtestutil.DiffErrString(err, tc.expErr); diff != "" {
				t.Errorf("Process(%+v) got error diff (-want, +got):\n%s", tc.name, diff)
			}
			if diff := cmp.Diff(strings.TrimSpace(tc.expOut), strings.TrimSpace(stdout.String())); diff != "" {
				t.Errorf("Process(%+v) got output diff (-want, +got):\n%s", tc.name, diff)
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

func testSetupHandler(t *testing.T, ctx context.Context, orgs, folders, projects *testutil.FakeServer) *handler.IAMHandler {
	t.Helper()

	fakeOrganizationsClient, fakeFoldersClient, fakeProjectsClient := testutil.SetupFakeClients(
		t,
		ctx,
		orgs,
		folders,
		projects,
	)
	h, err := handler.NewIAMHandler(
		ctx,
		fakeOrganizationsClient,
		fakeFoldersClient,
		fakeProjectsClient,
	)
	if err != nil {
		t.Fatalf("failed to create IAMHandler: %v", err)
	}
	return h
}
