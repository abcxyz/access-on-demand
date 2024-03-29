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
	"bytes"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

// ReadRequestFromPath reads a YAML file at the given path and unmarshal it to
// the given req.
func ReadRequestFromPath(path string, req any) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to read file at %q, %w", path, err)
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, 64*1_000))
	if err != nil {
		return fmt.Errorf("failed to read file content at %q, %w", path, err)
	}

	if len(data) > 0 {
		dec := yaml.NewDecoder(bytes.NewReader(data))
		dec.KnownFields(true)
		if err := dec.Decode(req); err != nil {
			return fmt.Errorf("failed to unmarshal yaml to %T: %w", req, err)
		}
	}

	return nil
}
