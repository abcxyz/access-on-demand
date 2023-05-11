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

import (
	"errors"
	"fmt"
	"net/mail"
	"strings"
)

// allowedResource defines the resource supported.
var allowedResource = map[string]struct{}{
	"organizations": {},
	"folders": {},
	"projects": {},
}

// ValidateIAMRequest checks if the ResourceMapping is valid.
func ValidateIAMRequest(r *IAMRequest) (retErr error) {
	for _, s := range r.ResourcePolicies {
		// Check if resource type is valid.
		if _, contains := allowedResource[strings.Split(s.Resource, "/")[0]]; !contains {
			retErr = errors.Join(retErr, fmt.Errorf("resource isn't one of [organizations, folders, projects]"))
		}
		// Check if IAM member is valid.
		for _, b := range s.Bindings {
			for _, m := range b.Members {
				// AOD only supports user level request.
				if !strings.HasPrefix(m, "user:") {
					retErr = errors.Join(retErr, fmt.Errorf("member %s is not of user type", m))
				}
				e := strings.Split(m, ":")[1]
				if _, err := mail.ParseAddress(e); err != nil {
					retErr = errors.Join(retErr, fmt.Errorf("email %s is not valid: %w", e, err))
				}
			}
		}
	}
	return
}
