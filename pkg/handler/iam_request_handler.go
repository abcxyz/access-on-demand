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
	"fmt"

	"github.com/abcxyz/access-on-demand/apis/v1alpha1"
	"google.golang.org/api/cloudresourcemanager/v3"
	"google.golang.org/protobuf/types/known/durationpb"
)

type IAMRRequestHandler struct {
	service *cloudresourcemanager.Service
}

// a AOD CLI will be responsible for parse/validate the iam yaml file and unmarshal it
// to IAMRequest, and then a CLI command to call this handler to execute the request.
func (h *IAMRRequestHandler) IAMRequestHandler(r *v1alpha1.IAMRequest, ttl *durationpb.Duration) error {
	for _, p := range r.ResourcePolicies {
		if err := h.handlePolicy(p, ttl); err != nil {
			return fmt.Errorf("failed to update IAM policy: %w", err)
		}
	}
	return nil
}

func (h *IAMRRequestHandler) handlePolicy(p *v1alpha1.ResourcePolicy, ttl *durationpb.Duration) error {
	switch r := p.Resource; r {
		case "organization":
			// Get current policy
			getIAMPolicyRequest := &cloudresourcemanager.GetIamPolicyRequest{}
			policy, _ := h.service.Organizations.GetIamPolicy(r, getIAMPolicyRequest).Do()
			// Update policy with what's in the request
			updatePolicy(policy, p.Bindings, ttl)
			// Set policy
			setIAMPolicyRequest := &cloudresourcemanager.SetIamPolicyRequest{}
			h.service.Organizations.SetIamPolicy(r, setIAMPolicyRequest)
		case "folder":
			// same as organization but with folders
		case "project":
			// same as organization but with projects
	}
	return nil
}

func updatePolicy(currentP *cloudresourcemanager.Policy, addP []*v1alpha1.Binding, ttl *durationpb.Duration) {
	// update current with addP
}
