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

package cli

import (
	"context"
	"fmt"
	"io"

	"github.com/abcxyz/access-on-demand/pkg/handler"
	"gopkg.in/yaml.v3"

	resourcemanager "cloud.google.com/go/resourcemanager/apiv3"
)

// encodeYaml writes YAML encoding of v to w.
func encodeYaml(w io.Writer, v any) error {
	enc := yaml.NewEncoder(w)
	enc.SetIndent(2)
	if err := enc.Encode(v); err != nil {
		return fmt.Errorf("failed to encode to yaml: %w", err)
	}

	if err := enc.Close(); err != nil {
		return fmt.Errorf("failed to close yaml encoder: %w", err)
	}

	return nil
}

// printHeader prints the hearder to w.
func printHeader(w io.Writer, header string) {
	fmt.Fprintf(w, "------%s------\n", header)
}

func newIAMHandler(ctx context.Context, customConditionTitle string) (*handler.IAMHandler, error) {
	// Create resource manager clients.
	organizationsClient, err := resourcemanager.NewOrganizationsClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create organizations client: %w", err)
	}
	defer organizationsClient.Close()

	foldersClient, err := resourcemanager.NewFoldersClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create folders client: %w", err)
	}
	defer foldersClient.Close()

	projectsClient, err := resourcemanager.NewProjectsClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create projects client: %w", err)
	}
	defer projectsClient.Close()

	var opts []handler.Option
	if customConditionTitle != "" {
		opts = append(opts, handler.WithCustomConditionTitle(customConditionTitle))
	}

	// Create IAMHandler with the clients.
	h, err := handler.NewIAMHandler(
		ctx,
		organizationsClient,
		foldersClient,
		projectsClient,
		opts...,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create IAM handler: %w", err)
	}
	return h, nil
}
