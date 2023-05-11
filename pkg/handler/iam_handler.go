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
	"strings"
	"time"

	"cloud.google.com/go/iam/apiv1/iampb"
	"github.com/abcxyz/access-on-demand/apis/v1alpha1"
	"github.com/googleapis/gax-go/v2"
	"github.com/sethvargo/go-retry"
	"google.golang.org/genproto/googleapis/type/expr"
)

// ConditionTitle of IAM bindings added by AOD.
var ConditionTitle = "abcxyz-aod-expiry"

// IAMHandler updates IAM policies of GCP organizations, folders, and projects
// based on the IAM request received.
type IAMHandler struct {
	organizationsClient IAMClient
	foldersClient       IAMClient
	projectsClient      IAMClient
	// Optional retry backoff strategy, default is 5 attempts with fibonacci
	// backoff that starts at 500ms.
	retry retry.Backoff
}

// Internal IAMClient interface that get and set IAM policies for GCP
// organizations, folders, and projects.
type IAMClient interface {
	GetIamPolicy(context.Context, *iampb.GetIamPolicyRequest, ...gax.CallOption) (*iampb.Policy, error)
	SetIamPolicy(context.Context, *iampb.SetIamPolicyRequest, ...gax.CallOption) (*iampb.Policy, error)
}

// Option is the option to set up an IAMHandler.
type Option func(h *IAMHandler) (*IAMHandler, error)

// WithRetry provides retry strategy to the handler.
func WithRetry(b retry.Backoff) Option {
	return func(p *IAMHandler) (*IAMHandler, error) {
		p.retry = b
		return p, nil
	}
}

// NewIAMHandler creates a new IAMHandler with provided clients and options.
func NewIAMHandler(ctx context.Context, organizationsClient, foldersClient, projectsClient IAMClient, opts ...Option) (*IAMHandler, error) {
	h := &IAMHandler{}
	for _, opt := range opts {
		var err error
		h, err = opt(h)
		if err != nil {
			return nil, fmt.Errorf("failed to apply client options: %w", err)
		}
	}
	h.organizationsClient = organizationsClient
	h.foldersClient = foldersClient
	h.projectsClient = projectsClient

	if h.retry == nil {
		h.retry = retry.WithMaxRetries(5, retry.NewFibonacci(500*time.Millisecond))
	}
	return h, nil
}

// Do removes expired or duplicative IAM bindings added by AOD and adds requested IAM bindings to current IAM policy.
func (h *IAMHandler) Do(ctx context.Context, r *v1alpha1.IAMRequestWrapper) (nps []*v1alpha1.IAMResponse, retErr error) {
	for _, p := range r.ResourcePolicies {
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

func (h *IAMHandler) handlePolicy(ctx context.Context, p *v1alpha1.ResourcePolicy, ttl time.Duration) (*v1alpha1.IAMResponse, error) {
	var iamC IAMClient
	switch strings.Split(p.Resource, "/")[0] {
	case "organizations":
		iamC = h.organizationsClient
	case "folders":
		iamC = h.foldersClient
	case "projects":
		iamC = h.projectsClient
	default:
		return nil, fmt.Errorf("resource isn't one of [organizations, folders, projects]")
	}

	var np *iampb.Policy
	if err := retry.Do(ctx, h.retry, func(ctx context.Context) error {
		// Get current IAM policy.
		cp, err := iamC.GetIamPolicy(ctx, &iampb.GetIamPolicyRequest{Resource: p.Resource})
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
		// TODO(#8): Look for specific errors to retry.
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
	// Convert new bindings to a role to bindings map.
	bsMap := toBindingsMap(bs)
	// Clean up current policy bindings.
	var result []*iampb.Binding
	for _, cb := range p.Bindings {
		// Skip non-AOD bindings.
		if cb.Condition == nil || cb.Condition.Title != ConditionTitle {
			result = append(result, cb)
			continue
		}
		// TODO (#6): Remove expired bindings.
		// Exclude duplicative Members from current bindings.
		cb.Members = removeCommonValues(cb.Members, bsMap[cb.Role])
		if len(cb.Members) > 0 {
			result = append(result, cb)
		}
	}
	p.Bindings = result

	// Add new bindings with expiration condition.
	t := time.Now().UTC().Add(ttl).Format(time.RFC3339)
	for _, b := range bs {
		newBinding := &iampb.Binding{
			Condition: &expr.Expr{
				Title:      ConditionTitle,
				Expression: fmt.Sprintf("request.time < timestamp('%s')", t),
			},
			Members: b.Members,
			Role:    b.Role,
		}
		p.Bindings = append(p.Bindings, newBinding)
	}
}

func toBindingsMap(bs []*v1alpha1.Binding) map[string][]string {
	m := make(map[string][]string)
	for _, b := range bs {
		m[b.Role] = removeCommonValues(m[b.Role], b.Members)
		m[b.Role] = append(m[b.Role], b.Members...)
	}
	return m
}

// Returns a result list of strings in l1 that are not found in l2.
func removeCommonValues(l1, l2 []string) []string {
	var result []string
	set := make(map[string]struct{})
	for _, e := range l2 {
		set[e] = struct{}{}
	}
	for _, e := range l1 {
		if _, contains := set[e]; !contains {
			result = append(result, e)
		}
	}
	return result
}
