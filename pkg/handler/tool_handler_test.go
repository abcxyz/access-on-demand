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
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/abcxyz/access-on-demand/apis/v1alpha1"
	"github.com/abcxyz/pkg/testutil"
)

func TestToolHandlerDo(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name               string
		request            *v1alpha1.ToolRequest
		stdout             *bytes.Buffer
		expHandleErrSubStr string
		expOutErr          string
		expOutResponse     string
	}{
		{
			name: "success",
			request: &v1alpha1.ToolRequest{
				Tool: "bash",
				Do: []string{
					`-c "echo test do1"`,
					`-c "echo test do2"`,
				},
			},
			stdout: bytes.NewBuffer(nil),
			expOutResponse: `
bash -c "echo test do1"
test do1

bash -c "echo test do2"
test do2
`,
		},
		{
			name: "success_nil_stdout",
			request: &v1alpha1.ToolRequest{
				Tool: "bash",
				Do: []string{
					`-c "echo test do1"`,
					`-c "echo test do2"`,
				},
			},
		},
		{
			name: "fail_to_parse_cmd",
			request: &v1alpha1.ToolRequest{
				Tool: "bash",
				Do: []string{
					`-c "echo test do1`,
				},
			},
			expHandleErrSubStr: "failed to parse cmd",
		},
		{
			name: "fail_to_run",
			request: &v1alpha1.ToolRequest{
				Tool: "echo",
				Do: []string{
					`test1 && test2`,
				},
			},
			stdout: bytes.NewBuffer(nil),
			expOutResponse: `
echo test1 && test2
test1`,
		},
		{
			name: "invalid_tool",
			request: &v1alpha1.ToolRequest{
				Tool: "invalid",
				Do: []string{
					"test do",
				},
			},
			stdout:             bytes.NewBuffer(nil),
			expOutResponse:     "invalid test do",
			expHandleErrSubStr: `failed to run command "invalid test do"`,
		},
		{
			name: "failed_to_execute_tool_command",
			request: &v1alpha1.ToolRequest{
				Tool: "ls",
				Do: []string{
					"dir_not_exist",
				},
			},
			stdout:             bytes.NewBuffer(nil),
			expOutResponse:     "ls dir_not_exist",
			expHandleErrSubStr: `failed to run command "ls dir_not_exist"`,
			expOutErr:          `No such file or directory`,
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			stderr := bytes.NewBuffer(nil)
			opts := []ToolHandlerOption{WithStderr(stderr)}
			if tc.stdout != nil {
				opts = append(opts, WithStdout(tc.stdout))
			}
			h := NewToolHandler(ctx, opts...)

			// Run test.
			gotErr := h.Do(ctx, tc.request)
			if diff := testutil.DiffErrString(gotErr, tc.expHandleErrSubStr); diff != "" {
				t.Errorf("Process(%+v) got unexpected error substring: %v", tc.name, diff)
			}
			if !strings.Contains(stderr.String(), tc.expOutErr) {
				t.Errorf("Process(%+v) error output got %q, want substring: %q", tc.name, stderr.String(), tc.expOutErr)
			}
			var gotOut string
			if tc.stdout != nil {
				gotOut = tc.stdout.String()
			}
			if strings.TrimSpace(tc.expOutResponse) != strings.TrimSpace(gotOut) {
				t.Errorf("Process(%+v) output response got %q, want %q)", tc.name, gotOut, tc.expOutResponse)
			}
		})
	}
}

func TestToolHandlerCleanup(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name               string
		request            *v1alpha1.ToolRequest
		stdout             *bytes.Buffer
		expHandleErrSubStr string
		expOutErr          string
		expOutResponse     string
	}{
		{
			name: "success",
			request: &v1alpha1.ToolRequest{
				Tool: "bash",
				Cleanup: []string{
					`-c "echo test cleanup1"`,
					`-c "echo test cleanup2"`,
				},
			},
			stdout: bytes.NewBuffer(nil),
			expOutResponse: `
bash -c "echo test cleanup1"
test cleanup1

bash -c "echo test cleanup2"
test cleanup2
`,
		},
		{
			name: "success_nil_stdout",
			request: &v1alpha1.ToolRequest{
				Tool: "bash",
				Cleanup: []string{
					`-c "echo test cleanup1"`,
					`-c "echo test cleanup2"`,
				},
			},
		},
		{
			name: "fail_to_parse_cmd",
			request: &v1alpha1.ToolRequest{
				Tool: "bash",
				Cleanup: []string{
					`-c "echo test do1`,
				},
			},
			expHandleErrSubStr: "failed to parse cmd",
		},
		{
			name: "fail_to_run",
			request: &v1alpha1.ToolRequest{
				Tool: "echo",
				Cleanup: []string{
					`test1 && test2`,
				},
			},
			stdout: bytes.NewBuffer(nil),
			expOutResponse: `
echo test1 && test2
test1`,
		},
		{
			name: "invalid_tool",
			request: &v1alpha1.ToolRequest{
				Tool: "invalid",
				Cleanup: []string{
					"test cleanup",
				},
			},
			stdout:             bytes.NewBuffer(nil),
			expOutResponse:     "invalid test cleanup",
			expHandleErrSubStr: `failed to run command "invalid test cleanup"`,
		},
		{
			name: "failed_to_execute_tool",
			request: &v1alpha1.ToolRequest{
				Tool: "ls",
				Cleanup: []string{
					"dir_not_exist",
				},
			},
			stdout:             bytes.NewBuffer(nil),
			expOutResponse:     "ls dir_not_exist",
			expHandleErrSubStr: `failed to run command "ls dir_not_exist"`,
			expOutErr:          `No such file or directory`,
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			stderr := bytes.NewBuffer(nil)
			opts := []ToolHandlerOption{WithStderr(stderr)}
			if tc.stdout != nil {
				opts = append(opts, WithStdout(tc.stdout))
			}
			h := NewToolHandler(ctx, opts...)

			// Run test.
			gotErr := h.Cleanup(ctx, tc.request)
			if diff := testutil.DiffErrString(gotErr, tc.expHandleErrSubStr); diff != "" {
				t.Errorf("Process(%+v) got unexpected error substring: %v", tc.name, diff)
			}
			if !strings.Contains(stderr.String(), tc.expOutErr) {
				t.Errorf("Process(%+v) error output got %q, want substring: %q", tc.name, stderr.String(), tc.expOutErr)
			}
			var gotOut string
			if tc.stdout != nil {
				gotOut = tc.stdout.String()
			}
			if strings.TrimSpace(tc.expOutResponse) != strings.TrimSpace(gotOut) {
				t.Errorf("Process(%+v) output response got %q, want %q)", tc.name, gotOut, tc.expOutResponse)
			}
		})
	}
}
