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

package v1alpha1

// IAMRequest represents a request to update IAM policies.
type IAMRequest struct {
	// List of ResourcePolicy, each specifies the IAM principals/members to role
	// bindings to be added for a GCP resource IAM policy.
	ResourcePolicies []*ResourcePolicy `json:"policies,omitempty"`
}

// ResourcePolicy specifies the IAM principals/members to role bindings to be
// added for a GCP resource IAM policy.
type ResourcePolicy struct {
	// Resource represents one of GCP organization, folder, and project.
	Resource string `json:"resource,omitempty"`

	// Bindings contains a list of IAM principals/members to role bindings.
	Bindings []*Binding `json:"bindings,omitempty"`
}

// Binding associates IAM principals/members with a role.
type Binding struct {
	// Members is a list of IAM principals, check
	// https://cloud.google.com/resource-manager/reference/rest/Shared.Types/Binding
	// for acceptable values.
	Members []string `json:"members,omitempty"`

	// Role to be assigned to Members. For example, roles/viewer, roles/editor, or
	// roles/owner.
	Role string `json:"role,omitempty"`
}
