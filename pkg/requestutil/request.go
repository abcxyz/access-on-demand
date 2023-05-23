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

// Package requestutil contains common requestutil functions to parse AOD request files.
package requestutil

import (
	"fmt"
	"io"
	"os"

	"github.com/abcxyz/access-on-demand/apis/v1alpha1"
	"gopkg.in/yaml.v3"
)

// ReadFromPath reads a YAML file at the given path and unmarshal it to
// IAMRequest.
func ReadFromPath(path string) (*v1alpha1.IAMRequest, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file at %q, %w", path, err)
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, 64*1_000))
	if err != nil {
		return nil, fmt.Errorf("failed to read file content at %q, %w", path, err)
	}

	var req v1alpha1.IAMRequest
	if err := yaml.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("failed to unmarshal yaml to %T: %w", req, err)
	}

	return &req, nil
}
