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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abcxyz/access-on-demand/apis/v1alpha1"
	"github.com/abcxyz/pkg/logging"
	"github.com/abcxyz/pkg/testutil"
	"github.com/google/go-cmp/cmp"
)

func TestToolDoCommand(t *testing.T) {
	t.Parallel()

	// Set up tool request file.
	requestFileContentByName := map[string]string{
		"valid.yaml": `
tool: 'gcloud'
do:
  - 'do1'
  - 'do2'
cleanup:
  - 'cleanup1'
  - 'cleanup2'
`,
		"invalid-request.yaml": `
tool: 'tool_not_exist'
do:
  - 'do'
cleanup:
  - 'cleanup'
`,
		"invalid.yaml": `bananas`,
	}

	validReq := &v1alpha1.ToolRequest{
		Tool:    "gcloud",
		Do:      []string{"do1", "do2"},
		Cleanup: []string{"cleanup1", "cleanup2"},
	}

	injectErr := fmt.Errorf("injected error")

	dir := t.TempDir()
	for name, content := range requestFileContentByName {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	cases := []struct {
		name        string
		args        []string
		testHandler *fakeToolHandler
		expOut      string
		expErr      string
		expReq      *v1alpha1.ToolRequest
	}{
		{
			name:        "success_do",
			args:        []string{"-path", filepath.Join(dir, "valid.yaml")},
			testHandler: &fakeToolHandler{},
			expOut:      `
------Successfully Completed Commands------
- gcloud do1
- gcloud do2`,
			expReq:      validReq,
		},
		{
			name:        "unexpected_args",
			args:        []string{"foo"},
			testHandler: &fakeToolHandler{},
			expErr:      `unexpected arguments: ["foo"]`,
		},
		{
			name:        "missing_path",
			args:        []string{},
			testHandler: &fakeToolHandler{},
			expErr:      `path is required`,
		},
		{
			name:        "invalid_yaml",
			args:        []string{"-path", filepath.Join(dir, "invalid.yaml")},
			testHandler: &fakeToolHandler{},
			expErr:      "failed to read *v1alpha1.ToolRequest",
		},
		{
			name:        "handler_do_failure",
			args:        []string{"-path", filepath.Join(dir, "valid.yaml")},
			testHandler: &fakeToolHandler{injectErr: injectErr},
			expErr:      injectErr.Error(),
			expReq:      validReq,
		},
		{
			name:        "invalid_request",
			args:        []string{"-path", filepath.Join(dir, "invalid-request.yaml")},
			testHandler: &fakeToolHandler{},
			expErr:      "failed to validate *v1alpha1.ToolRequest",
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := logging.WithLogger(context.Background(), logging.TestLogger(t))

			cmd := ToolDoCommand{
				ToolBaseCommand: ToolBaseCommand{
					testHandler: tc.testHandler,
				},
			}
			_, stdout, _ := cmd.Pipe()

			args := append([]string{}, tc.args...)

			err := cmd.Run(ctx, args)
			if diff := testutil.DiffErrString(err, tc.expErr); diff != "" {
				t.Errorf("Process(%+v) got error diff (-want, +got):\n%s", tc.name, diff)
			}
			if diff := cmp.Diff(strings.TrimSpace(tc.expOut), strings.TrimSpace(stdout.String())); diff != "" {
				t.Errorf("Process(%+v) got output diff (-want, +got):\n%s", tc.name, diff)
			}
			if diff := cmp.Diff(tc.expReq, tc.testHandler.gotReq); diff != "" {
				t.Errorf("Process(%+v) got request diff (-want, +got):\n%s", tc.name, diff)
			}
		})
	}
}

type fakeToolHandler struct {
	injectErr error
	gotReq    *v1alpha1.ToolRequest
}

func (h *fakeToolHandler) Do(ctx context.Context, req *v1alpha1.ToolRequest) error {
	h.gotReq = req
	return h.injectErr
}

func (h *fakeToolHandler) Cleanup(ctx context.Context, req *v1alpha1.ToolRequest) error {
	h.gotReq = req
	return h.injectErr
}
