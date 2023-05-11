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

import "time"

// IAMRequestWrapper wraps the IAMRequest and adds additional fields such as
// duration.
type IAMRequestWrapper struct {
	// IAMRequest contains IAM binding information.
	*IAMRequest

	// Duration feild used as IAM binding condition to specify expiration.
	// This will not override role bindings with no conditions.
	Duration time.Duration
}
