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
	"github.com/google/go-cmp/cmp"
)

func TestToolHandlerDo(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name               string
		request            *v1alpha1.ToolRequest
		expHandleErrSubStr string
		expOutErr          string
		expOutResponse     string
	}{
		{
			name: "success",
			request: &v1alpha1.ToolRequest{
				Tool: "echo",
				Do: []string{
					"test do1",
					"test do2",
				},
			},
			expOutResponse: "test do1\ntest do2",
		},
		{
			name: "invalid_tool",
			request: &v1alpha1.ToolRequest{
				Tool: "invalid",
				Do: []string{
					"test do",
				},
			},
			expHandleErrSubStr: `failed to run command "test do"`,
		},
		{
			name: "failed_to_execute_tool_command",
			request: &v1alpha1.ToolRequest{
				Tool: "ls",
				Do: []string{
					"dir_not_exist",
				},
			},
			expHandleErrSubStr: `failed to run command "dir_not_exist"`,
			expOutErr:          `ls: cannot access 'dir_not_exist': No such file or directory`,
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			stderr := bytes.NewBuffer(nil)
			stdout := bytes.NewBuffer(nil)
			h := NewToolHandler(ctx, WithStderr(stderr), WithDebugMode(stdout))

			// Run test.
			gotErr := h.Do(ctx, tc.request)
			if diff := testutil.DiffErrString(gotErr, tc.expHandleErrSubStr); diff != "" {
				t.Errorf("Process(%+v) got unexpected error substring: %v", tc.name, diff)
			}
			if diff := cmp.Diff(strings.TrimSpace(tc.expOutErr), strings.TrimSpace(stderr.String())); diff != "" {
				t.Errorf("Process(%+v) got unexpected error output substring: %v", tc.name, diff)
			}
			if diff := cmp.Diff(strings.TrimSpace(tc.expOutResponse), strings.TrimSpace(stdout.String())); diff != "" {
				t.Errorf("Process(%+v) got output response diff (-want, +got): %v", tc.name, diff)
			}
		})
	}
}

func TestToolHandlerCleanup(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name               string
		request            *v1alpha1.ToolRequest
		expHandleErrSubStr string
		expOutErr          string
		expOutResponse     string
	}{
		{
			name: "success",
			request: &v1alpha1.ToolRequest{
				Tool: "echo",
				Cleanup: []string{
					"test do1",
					"test do2",
				},
			},
			expOutResponse: "test do1\ntest do2",
		},
		{
			name: "invalid_tool",
			request: &v1alpha1.ToolRequest{
				Tool: "invalid",
				Cleanup: []string{
					"test do",
				},
			},
			expHandleErrSubStr: `failed to run command "test do"`,
		},
		{
			name: "failed_to_execute_tool",
			request: &v1alpha1.ToolRequest{
				Tool: "ls",
				Cleanup: []string{
					"dir_not_exist",
				},
			},
			expHandleErrSubStr: `failed to run command "dir_not_exist"`,
			expOutErr:          `ls: cannot access 'dir_not_exist': No such file or directory`,
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			stderr := bytes.NewBuffer(nil)
			stdout := bytes.NewBuffer(nil)
			h := NewToolHandler(ctx, WithStderr(stderr), WithDebugMode(stdout))

			// Run test.
			gotErr := h.Cleanup(ctx, tc.request)
			if diff := testutil.DiffErrString(gotErr, tc.expHandleErrSubStr); diff != "" {
				t.Errorf("Process(%+v) got unexpected error substring: %v", tc.name, diff)
			}
			if diff := cmp.Diff(strings.TrimSpace(tc.expOutErr), strings.TrimSpace(stderr.String())); diff != "" {
				t.Errorf("Process(%+v) got unexpected error output substring: %v", tc.name, diff)
			}
			if diff := cmp.Diff(strings.TrimSpace(tc.expOutResponse), strings.TrimSpace(stdout.String())); diff != "" {
				t.Errorf("Process(%+v) got output response diff (-want, +got): %v", tc.name, diff)
			}
		})
	}
}