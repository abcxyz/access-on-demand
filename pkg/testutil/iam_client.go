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

// testutil package provides utilities that are intended to enable easier
// and more concise writing of unit test code.
package testutil

import (
	"context"
	"testing"

	"cloud.google.com/go/iam/apiv1/iampb"
	"cloud.google.com/go/resourcemanager/apiv3/resourcemanagerpb"
	"github.com/abcxyz/access-on-demand/pkg/iam"
	"github.com/abcxyz/pkg/testutil"
	"google.golang.org/api/option"
	"google.golang.org/grpc"

	resourcemanager "cloud.google.com/go/resourcemanager/apiv3"
)

type FakeServer struct {
	// Use ProjectsServer since it has the same APIs we need.
	resourcemanagerpb.UnimplementedProjectsServer

	Policy          *iampb.Policy
	GetIAMPolicyErr error
	SetIAMPolicyErr error
}

func (s *FakeServer) GetIamPolicy(context.Context, *iampb.GetIamPolicyRequest) (*iampb.Policy, error) {
	if s.GetIAMPolicyErr != nil {
		return nil, s.GetIAMPolicyErr
	}
	return s.Policy, s.GetIAMPolicyErr
}

func (s *FakeServer) SetIamPolicy(c context.Context, r *iampb.SetIamPolicyRequest) (*iampb.Policy, error) {
	if s.SetIAMPolicyErr != nil {
		return nil, s.SetIAMPolicyErr
	}
	s.Policy = r.Policy
	return s.Policy, s.SetIAMPolicyErr
}

func SetupFakeClients(t *testing.T, ctx context.Context, s1, s2, s3 *FakeServer) (c1, c2, c3 iam.IAMClient) {
	t.Helper()

	ss := []*FakeServer{s1, s2, s3}
	cs := make([]iam.IAMClient, 3)
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
