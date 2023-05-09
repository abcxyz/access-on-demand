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
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"cloud.google.com/go/iam/apiv1/iampb"
	"cloud.google.com/go/resourcemanager/apiv3"
	"github.com/abcxyz/access-on-demand/apis/v1alpha1"
	"github.com/googleapis/gax-go/v2"
	"github.com/sethvargo/go-retry"
	"google.golang.org/genproto/googleapis/type/expr"
)

// Condition tile of IAM bindings added by AOD.
var conditionTitle = "AOD expiration"

// IAMHandler updates IAM policies of GCP organizations, folders, and projects
// based on the IAM request received.
type IAMHandler struct {
	organizationsClient *resourcemanager.OrganizationsClient
	foldersClient       *resourcemanager.FoldersClient
	projectsClient      *resourcemanager.ProjectsClient
}

// Internal iamClient interface that get and set IAM policies for GCP
// organizations, folders, and projects.
type iamClient interface {
	GetIamPolicy(context.Context, *iampb.GetIamPolicyRequest, ...gax.CallOption) (*iampb.Policy, error)
	SetIamPolicy(context.Context, *iampb.SetIamPolicyRequest, ...gax.CallOption) (*iampb.Policy, error)
}

// Option is the option to set up an IAMHandler.
type Option func(h *IAMHandler) (*IAMHandler, error)

// WithOrganizationsClient provides a organizations client to the handler.
func WithOrganizationsClient(client *resourcemanager.OrganizationsClient) Option {
	return func(p *IAMHandler) (*IAMHandler, error) {
		p.organizationsClient = client
		return p, nil
	}
}

// WithFoldersClient provides a folders client to the handler.
func WithFoldersClient(client *resourcemanager.FoldersClient) Option {
	return func(p *IAMHandler) (*IAMHandler, error) {
		p.foldersClient = client
		return p, nil
	}
}

// WithProjectsClient provides a projects client to the handler.
func WithProjectsClient(client *resourcemanager.ProjectsClient) Option {
	return func(p *IAMHandler) (*IAMHandler, error) {
		p.projectsClient = client
		return p, nil
	}
}

// NewIAMHandler creates a new IAMHandler with the given options.
func NewIAMHandler(ctx context.Context, opts ...Option) (*IAMHandler, error) {
	h := &IAMHandler{}
	for _, opt := range opts {
		var err error
		h, err = opt(h)
		if err != nil {
			return nil, fmt.Errorf("failed to apply client options: %w", err)
		}
	}

	if h.organizationsClient == nil {
		client, err := resourcemanager.NewOrganizationsClient(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to create the organizations client: %w", err)
		}
		h.organizationsClient = client
	}
	if h.foldersClient == nil {
		client, err := resourcemanager.NewFoldersClient(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to create the folders client: %w", err)
		}
		h.foldersClient = client
	}
	if h.projectsClient == nil {
		client, err := resourcemanager.NewProjectsClient(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to create the projects client: %w", err)
		}
		h.projectsClient = client
	}
	return h, nil
}

// Do adds additinal IAM bindings to current IAM policy.
func (h *IAMHandler) Do(ctx context.Context, r *v1alpha1.IAMRequestWrapper) (nps []*v1alpha1.IAMResponse, retErr error) {
	for _, p := range r.Request.ResourcePolicies {
		np, err := h.handlePolicy(ctx, p, r.Duration)
		if err != nil {
			retErr = errors.Join(
				retErr,
				fmt.Errorf("failed to handle policy update for resource %s: %w", p.Resource, err),
			)
		}
		if np != nil {
			nps = append(nps, np)
		}
	}
	return
}

func (h *IAMHandler) handlePolicy(
	ctx context.Context,
	p *v1alpha1.ResourcePolicy,
	ttl time.Duration) (*v1alpha1.IAMResponse, error) {

	var iamC iamClient
	switch strings.Split(p.Resource, "/")[0] {
	case "organizations":
		iamC = h.organizationsClient
	case "folders":
		iamC = h.foldersClient
	case "projects":
		iamC = h.projectsClient
	}

	var np *iampb.Policy
	b := retry.WithMaxRetries(5, retry.NewFibonacci(500*time.Millisecond))
	if err := retry.Do(ctx, b, func(ctx context.Context) error {
		// Get current IAM policy.
		cp, err := iamC.GetIamPolicy(
			ctx,
			&iampb.GetIamPolicyRequest{Resource: p.Resource})
		if err != nil {
			return fmt.Errorf("failed to get IAM policy: %w", err)
		}

		// Update the policy with new IAM binding additions.
		updatePolicy(cp, p.Bindings, ttl)

		// Set the new policy.
		setIamPolicyRequest := &iampb.SetIamPolicyRequest{
			Resource: p.Resource,
			Policy:   cp,
		}
		np, err = iamC.SetIamPolicy(ctx, setIamPolicyRequest)
		// Retry when set IAM policy fail.
		if err != nil {
			return retry.RetryableError(fmt.Errorf("failed to set IAM policy: %w, retrying", err))
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("failed to handle IAM request: %w", err)
	}

	return &v1alpha1.IAMResponse{Resource: p.Resource, Policy: np}, nil
}

// Remove expired bindings and add or update new bindings with expiration condition.
func updatePolicy(p *iampb.Policy, bs []*v1alpha1.Binding, ttl time.Duration) {

	// Clean up current policy.
	copy := make([]*iampb.Binding, 0, len(p.Bindings))
	for _, cb := range p.Bindings {
		// Only clean up AOD bindings.
		// TODO (#6): Remove expired bindings.
		if cb.Condition != nil && cb.Condition.Title == conditionTitle {
			// Exclude duplicative Members from current bindings.
			ms := make([]string, 0, len(cb.Members))
			for _, nb := range bs {
				if cb.Role == nb.Role {
					for _, m := range cb.Members {
						if !slices.Contains(nb.Members, m) {
							ms = append(ms, m)
						}
					}
				}
			}
			// Copy the bindings with de-dupped members.
			if len(ms) != 0 {
				cb.Members = ms
				copy = append(copy, cb)
			}
		} else {
			copy = append(copy, cb)
		}
	}
	p.Bindings = copy

	// Add new bindings with expiration condition.
	t := time.Now().Add(ttl).Format(time.RFC3339)
	for _, b := range bs {
		newBindings := &iampb.Binding{
			Condition: &expr.Expr{
				Title:      conditionTitle,
				Expression: fmt.Sprintf("request.time < timestamp('%s')", t),
			},
			Members: b.Members,
			Role:    b.Role,
		}
		p.Bindings = append(p.Bindings, newBindings)
	}
	return
}

// Cleanup handles the graceful shutdown of the resource manager clients.
func (h *IAMHandler) Cleanup() (retErr error) {
	if err := h.organizationsClient.Close(); err != nil {
		retErr = errors.Join(retErr, fmt.Errorf("failed to close organizations client: %w", err))
	}

	if err := h.foldersClient.Close(); err != nil {
		retErr = errors.Join(retErr, fmt.Errorf("failed to close folders client: %w", err))
	}

	if err := h.projectsClient.Close(); err != nil {
		retErr = errors.Join(retErr, fmt.Errorf("failed to close projects client: %w", err))
	}
	return
}
