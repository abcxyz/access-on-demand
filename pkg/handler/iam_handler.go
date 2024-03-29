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
	"github.com/googleapis/gax-go/v2"
	"github.com/sethvargo/go-retry"
	"google.golang.org/genproto/googleapis/type/expr"

	"github.com/abcxyz/access-on-demand/apis/v1alpha1"
	"github.com/abcxyz/pkg/logging"
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
	// Title for IAM bindings expiration condition, default is "abcxyz-aod-expiry".
	conditionTitle string
}

// IAMClient is the interface to get and set IAM policies for GCP organizations,
// folders, and projects.
type IAMClient interface {
	GetIamPolicy(context.Context, *iampb.GetIamPolicyRequest, ...gax.CallOption) (*iampb.Policy, error)
	SetIamPolicy(context.Context, *iampb.SetIamPolicyRequest, ...gax.CallOption) (*iampb.Policy, error)
}

// updatePolicy updates the given IAM policy.
type updatePolicy func(context.Context, *iampb.Policy, []*v1alpha1.Binding, time.Time) error

// Option is the option to set up an IAMHandler.
type Option func(h *IAMHandler) (*IAMHandler, error)

// WithRetry provides retry strategy to the handler.
func WithRetry(b retry.Backoff) Option {
	return func(p *IAMHandler) (*IAMHandler, error) {
		p.retry = b
		return p, nil
	}
}

// WithCustomConditionTitle provides a custom condition title for IAM bindings
// expiration condition.
func WithCustomConditionTitle(title string) Option {
	return func(p *IAMHandler) (*IAMHandler, error) {
		p.conditionTitle = title
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

	if h.conditionTitle == "" {
		h.conditionTitle = defaultConditionTitle
	}

	return h, nil
}

// Cleanup removes expired IAM bindings added by AOD from the IAM policies of the resources in the request.
func (h *IAMHandler) Cleanup(ctx context.Context, r *v1alpha1.IAMRequest) (nps []*v1alpha1.IAMResponse, retErr error) {
	for _, p := range r.ResourcePolicies {
		// time.Now() is a dummy parameter used to match the function signature.
		np, err := h.handlePolicy(ctx, p, time.Now(), h.cleanupBindings)
		if err != nil {
			retErr = errors.Join(
				retErr,
				fmt.Errorf("failed to handle policy cleanup for resource %s: %w", p.Resource, err),
			)
		}
		if np != nil {
			nps = append(nps, np)
		}
	}
	return
}

// Do removes expired or conflicting IAM bindings added by AOD and adds requested IAM bindings to current IAM policy.
func (h *IAMHandler) Do(ctx context.Context, r *v1alpha1.IAMRequestWrapper) (nps []*v1alpha1.IAMResponse, retErr error) {
	expiry := r.StartTime.Add(r.Duration)
	for _, p := range r.ResourcePolicies {
		np, err := h.handlePolicy(ctx, p, expiry, h.addBindings)
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

func (h *IAMHandler) handlePolicy(ctx context.Context, p *v1alpha1.ResourcePolicy, expiry time.Time, updateFunc updatePolicy) (*v1alpha1.IAMResponse, error) {
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
	var updateErr error
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
		// Retry when get IAM policy fail.
		if err != nil {
			return retry.RetryableError(fmt.Errorf("failed to get IAM policy: %w", err))
		}

		// Keep handling the request and report the errors at the end.
		if err := updateFunc(ctx, cp, p.Bindings, expiry); err != nil {
			updateErr = fmt.Errorf("errors when updating IAM policy: %w", err)
		}

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
		return nil, errors.Join(updateErr, fmt.Errorf("failed to handle IAM request: %w", err))
	}

	return &v1alpha1.IAMResponse{Resource: p.Resource, Policy: np}, updateErr
}

// addBindings adds new bindings with expiration condition and does best
// effort cleanup which removes any expired AOD bindings. It always return nil
// error, any errors encounterred during removal will be ignored and policy
// update for the request will continue. Removal errors should be handled
// separately such as in a global IAM cleanup.
func (h *IAMHandler) addBindings(ctx context.Context, p *iampb.Policy, bs []*v1alpha1.Binding, expiry time.Time) error {
	logger := logging.FromContext(ctx)

	// Cleanup policy, returned error is logged.
	if err := h.cleanupBindings(ctx, p, bs, expiry); err != nil {
		logger.WarnContext(ctx, "failed to check expiry", "error", err)
	}

	// Convert new bindings to a role to unique bindings map.
	bsMap := toBindingsMap(bs)

	// Add new bindings with expiration condition.
	t := expiry.Format(time.RFC3339)
	for r, ms := range bsMap {
		newBinding := &iampb.Binding{
			Condition: &expr.Expr{
				Title:      h.conditionTitle,
				Expression: fmt.Sprintf(expirationExpression, t),
			},
			Role: r,
		}
		for m := range ms {
			newBinding.Members = append(newBinding.GetMembers(), m)
		}
		sort.Strings(newBinding.GetMembers())
		p.Bindings = append(p.GetBindings(), newBinding)
	}

	// Set policy version to 3 to support conditional IAM bindings.
	// See details here: https://cloud.google.com/iam/docs/policies#specifying-version-set
	p.Version = 3

	return nil
}

// cleanupBindings does best effort cleanup which removes bs bindings and any
// expired AOD bindings from the policy.
func (h *IAMHandler) cleanupBindings(ctx context.Context, p *iampb.Policy, bs []*v1alpha1.Binding, _ time.Time) (retErr error) {
	// Convert new bindings to a role to unique bindings map.
	bsMap := toBindingsMap(bs)
	var keep []*iampb.Binding
	for _, b := range p.GetBindings() {
		// Keep non-AOD bindings.
		if b.GetCondition() == nil || b.GetCondition().GetTitle() != h.conditionTitle {
			keep = append(keep, b)
			continue
		}

		expired, err := expired(b.GetCondition().GetExpression())
		if err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("failed to check expiry: %w", err))
		}
		// Remove expired bindings.
		if expired {
			continue
		}

		// Keep roles that are not in the request.
		if _, ok := bsMap[b.GetRole()]; !ok {
			keep = append(keep, b)
			continue
		}

		// Keep members from the binding if it is not in the request.
		var nm []string
		for _, m := range b.GetMembers() {
			if _, ok := bsMap[b.GetRole()][m]; !ok {
				nm = append(nm, m)
			}
		}
		if len(nm) > 0 {
			b.Members = nm
			keep = append(keep, b)
		}
	}
	p.Bindings = keep

	return retErr
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
