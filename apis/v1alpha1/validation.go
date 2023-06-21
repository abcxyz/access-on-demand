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

var (
	defaultCLI              = "gcloud"
	invalidCommandOperators = []string{"&", "|", ">", ">>"}
)

// ValidateIAMRequest checks if the IAMRequest is valid.
func ValidateIAMRequest(r *IAMRequest) (retErr error) {
	for _, s := range r.ResourcePolicies {
		// Check if resource type is valid.
		resourceType := strings.Split(s.Resource, "/")[0]
		switch resourceType {
		case "organizations", "folders", "projects":
			// Ok.
		default:
			retErr = errors.Join(retErr, fmt.Errorf("resource %q isn't one of [organizations, folders, projects]", s.Resource))
		}

		// Check if IAM member is valid.
		for _, b := range s.Bindings {
			for _, m := range b.Members {
				parts := strings.SplitN(m, ":", 2)
				if len(parts) < 2 {
					retErr = errors.Join(retErr, fmt.Errorf(`member %q is not a valid format (expected "user:<email>")`, m))
					continue
				}

				// Check if prefix is "user".
				if got, want := parts[0], "user"; got != want {
					retErr = errors.Join(retErr, fmt.Errorf(`member %q is not of "user" type (got %q)`, m, got))
				}

				// Check if the email is a valid email.
				email := parts[1]
				if _, err := mail.ParseAddress(email); err != nil {
					retErr = errors.Join(retErr, fmt.Errorf("member %q does not appear to be a valid email address (got %q)", m, email))
				}
			}
		}
	}
	return
}

// ValidateCLIRequest checks if the CLIRequest is valid.
func ValidateCLIRequest(r *CLIRequest) (retErr error) {
	// Set default CLI
	if r.CLI == "" {
		r.CLI = defaultCLI
	}
	// TODO (#49): support other CLIs.
	if r.CLI != defaultCLI {
		retErr = errors.Join(retErr, fmt.Errorf("CLI %q is not supported", r.CLI))
	}

	// Check if the do commands are valid.
	for _, c := range r.Do {
		if err := checkCommand(c); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("command %q is not valid: %w", c, err))
		}
	}

	// Check if the cleanup commands are valid.
	for _, c := range r.Cleanup {
		if err := checkCommand(c); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("command %q is not valid: %w", c, err))
		}
	}
	return retErr
}

func checkCommand(c string) error {
	for _, o := range invalidCommandOperators {
		if strings.Contains(c, o) {
			return fmt.Errorf(`command contains invalid operators in %q`, invalidCommandOperators)
		}
	}
	return nil
}
