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

import resourcemanager "google.golang.org/api/cloudresourcemanager/v3"

// IamRequest represents a request to update IAM policies.
type IamRequest struct {
	// List of ResourcePolicy, each specifies the IAM policy to be added for a
	// GCP resource.
	ResourcePolicies []*ResourcePolicy `json:"policies,omitempty"`
}

// ResourcePolicy specifies the IAM policy to be added for a GCP resource.
type ResourcePolicy struct {
	// Resource represents one of GCP organization, folder, and project.
	Resource string `json:"resource,omitempty"`

	// Policy contains a list of IAM members to role bindings.
	Policy *resourcemanager.Policy `json:"policy,omitempty"`
}
