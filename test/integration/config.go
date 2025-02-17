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

// Package integration tests the aod root command.
package integration

import (
	"context"
	"fmt"
	"time"

	"github.com/sethvargo/go-envconfig"
)

type config struct {
	ProjectID              string        `env:"INTEG_TEST_PROJECT_ID,required"`
	QueryRetryWaitDuration time.Duration `env:"INTEG_TEST_QUERY_RETRY_WAIT_DURATION,default=10s"`
	QueryRetryLimit        uint64        `env:"INTEG_TEST_QUERY_RETRY_COUNT,default=20"`
	ConditionTitle         string        `env:"INTEG_TEST_CONDITION_TITLE,required"`
	IAMUser                string        `env:"INTEG_TEST_IAM_USER,required"`
}

func newTestConfig(ctx context.Context) (*config, error) {
	var c config
	if err := envconfig.ProcessWith(ctx, &envconfig.Config{
		Target:   &c,
		Lookuper: envconfig.OsLookuper(),
	}); err != nil {
		return nil, fmt.Errorf("failed to process environment: %w", err)
	}

	return &c, nil
}
