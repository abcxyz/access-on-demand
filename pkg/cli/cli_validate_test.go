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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abcxyz/pkg/logging"
	"github.com/abcxyz/pkg/testutil"
	"github.com/google/go-cmp/cmp"
)

func TestCLIValidateCommand(t *testing.T) {
	t.Parallel()

	// Set up CLI request file.
	requestFileContentByName := map[string]string{
		"valid.yaml": `
cli: 'gcloud'
do:
  - 'do1'
  - 'do2'
cleanup:
  - 'cleanup1'
  - 'cleanup2'
`,
		"invalid-request.yaml": `
cli: 'cli_not_exist'
do:
  - 'do'
cleanup:
  - 'cleanup'
`,
		"invalid.yaml": `bananas`,
	}
	dir := t.TempDir()
	for name, content := range requestFileContentByName {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	cases := []struct {
		name   string
		args   []string
		expOut string
		expErr string
	}{
		{
			name:   "success",
			args:   []string{"-path", filepath.Join(dir, "valid.yaml")},
			expOut: `Successfully validated CLI request`,
		},
		{
			name:   "unexpected_args",
			args:   []string{"foo"},
			expErr: `unexpected arguments: ["foo"]`,
		},
		{
			name:   "missing_path",
			args:   []string{},
			expErr: `path is required`,
		},
		{
			name:   "invalid_yaml",
			args:   []string{"-path", filepath.Join(dir, "invalid.yaml")},
			expErr: "failed to read *v1alpha1.CLIRequest",
		},
		{
			name:   "invalid_request",
			args:   []string{"-path", filepath.Join(dir, "invalid-request.yaml")},
			expErr: "failed to validate *v1alpha1.CLIRequest",
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := logging.WithLogger(context.Background(), logging.TestLogger(t))

			var cmd CLIValidateCommand
			_, stdout, _ := cmd.Pipe()

			args := append([]string{}, tc.args...)

			err := cmd.Run(ctx, args)
			if diff := testutil.DiffErrString(err, tc.expErr); diff != "" {
				t.Errorf("Process(%+v) got error diff (-want, +got):\n%s", tc.name, diff)
			}
			if diff := cmp.Diff(strings.TrimSpace(tc.expOut), strings.TrimSpace(stdout.String())); diff != "" {
				t.Errorf("Process(%+v) got output diff (-want, +got):\n%s", tc.name, diff)
			}
		})
	}
}
