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
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"cloud.google.com/go/iam/apiv1/iampb"
	"github.com/abcxyz/access-on-demand/apis/v1alpha1"
	"github.com/abcxyz/pkg/logging"
	"github.com/googleapis/gax-go/v2"
	"github.com/sethvargo/go-retry"
	"google.golang.org/genproto/googleapis/type/expr"
)

var (
	// defaultConditionTitle of IAM bindings added by AOD.
	defaultConditionTitle = "abcxyz-aod-expiry"
	// expirationExpression of IAM binding condition added by AOD.
	expirationExpression = "request.time < timestamp('%s')"
	// expirationRegex matching expirationExpression.
	expirationRegex = regexp.MustCompile(`request.time < timestamp\('([^']+)'\)`)
)

// IAMHandler updates IAM policies of GCP organizations, folders, and projects
// based on the IAM request received.
type IAMHandler struct {
	organizationsClient IAMClient
	foldersClient       IAMClient
	projectsClient      IAMClient
	// Optional retry backoff strategy, default is 5 attempts with fibonacci
	// backoff that starts at 500ms.
	retry retry.Backoff
	// Optional description for IAM bindings expiration condition.
	conditionDescription string
}

// IAMClient is the interface to get and set IAM policies for GCP organizations,
// folders, and projects.
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

// WithConditionDescription provides a condition description for IAM bindings
// expiration condition.
func WithConditionDescription(title string) Option {
	return func(p *IAMHandler) (*IAMHandler, error) {
		p.conditionDescription = title
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
	expiry := r.StartTime.Add(r.Duration)
	for _, p := range r.ResourcePolicies {
		np, err := h.handlePolicy(ctx, p, expiry)
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

func (h *IAMHandler) handlePolicy(ctx context.Context, p *v1alpha1.ResourcePolicy, expiry time.Time) (*v1alpha1.IAMResponse, error) {
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
		getIAMPolicyRequest := &iampb.GetIamPolicyRequest{
			Resource: p.Resource,
			// Set required policy version to 3 to support conditional IAM bindings
			// in the requested policy.
			// Note that if the requested policy does not contain conditional IAM
			// bindings it will return the policy as is, which is version 1.
			// See details here: https://cloud.google.com/iam/docs/policies#specifying-version-get
			Options: &iampb.GetPolicyOptions{
				RequestedPolicyVersion: 3,
			},
		}
		cp, err := iamC.GetIamPolicy(ctx, getIAMPolicyRequest)
		if err != nil {
			return fmt.Errorf("failed to get IAM policy: %w", err)
		}

		// updatePolicy also does best effort cleanup which removes any expired AOD
		// bindings, however any errors encounterred during removal will be ignored
		// and policy update for the request will continue. Removal errors should be
		// handled separately such as in a global IAM cleanup.
		h.updatePolicy(ctx, cp, p.Bindings, expiry)

		// Set the new policy.
		setIAMPolicyRequest := &iampb.SetIamPolicyRequest{
			Resource: p.Resource,
			Policy:   cp,
		}
		np, err = iamC.SetIamPolicy(ctx, setIAMPolicyRequest)
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
func (h *IAMHandler) updatePolicy(ctx context.Context, p *iampb.Policy, bs []*v1alpha1.Binding, expiry time.Time) {
	logger := logging.FromContext(ctx)
	// Convert new bindings to a role to unique bindings map.
	bsMap := toBindingsMap(bs)
	// Clean up current policy bindings.
	var result []*iampb.Binding
	for _, cb := range p.Bindings {
		// Skip non-AOD bindings.
		if cb.Condition == nil || cb.Condition.Title != defaultConditionTitle {
			result = append(result, cb)
			continue
		}

		// Skip expired bindings.
		expired, err := expired(cb.Condition.Expression)
		if err != nil {
			// Continue policy update when there is error checking the AOD expiry.
			// Cleaning up expired AOD bindings here is best effort.
			// We rely on a separate process to clean up AOD bindings.
			logger.Warnw("failed to check expiry", "error", err)
		}
		if expired {
			continue
		}

		// Skip roles we are not interested in.
		if _, ok := bsMap[cb.Role]; !ok {
			result = append(result, cb)
			continue
		}
		var nm []string
		for _, m := range cb.Members {
			if _, ok := bsMap[cb.Role][m]; !ok {
				nm = append(nm, m)
			}
		}
		if len(nm) > 0 {
			cb.Members = nm
			result = append(result, cb)
		}
	}
	p.Bindings = result

	// Add new bindings with expiration condition.
	t := expiry.Format(time.RFC3339)
	for r, ms := range bsMap {
		newBinding := &iampb.Binding{
			Condition: &expr.Expr{
				Title:       defaultConditionTitle,
				Expression:  fmt.Sprintf(expirationExpression, t),
				Description: h.conditionDescription,
			},
			Role: r,
		}
		for m := range ms {
			newBinding.Members = append(newBinding.Members, m)
		}
		sort.Strings(newBinding.Members)
		p.Bindings = append(p.Bindings, newBinding)
	}

	// Set policy version to 3 to support conditional IAM bindings.
	// See details here: https://cloud.google.com/iam/docs/policies#specifying-version-set
	p.Version = 3
}

func toBindingsMap(bs []*v1alpha1.Binding) map[string]map[string]struct{} {
	result := make(map[string]map[string]struct{})
	for _, b := range bs {
		if result[b.Role] == nil {
			result[b.Role] = make(map[string]struct{})
		}
		for _, m := range b.Members {
			result[b.Role][m] = struct{}{}
		}
	}
	return result
}

func expired(exp string) (bool, error) {
	matches := expirationRegex.FindStringSubmatch(exp)
	if len(matches) < 2 {
		return false, fmt.Errorf("expression %q does not match format %q", exp, "request.time < timestamp('YYYY-MM-DDTHH:MM:SSZ')")
	}
	t, err := time.Parse(time.RFC3339, matches[1])
	if err != nil {
		return false, fmt.Errorf("failed to parse expiration %q: %w", exp, err)
	}
	return t.Before(time.Now()), nil
}
