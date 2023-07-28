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

package integration

import (
	"context"
	"fmt"
	"time"

	"github.com/sethvargo/go-envconfig"
)

// const conditionTitlePrefix = "ci-expiry"

// type config struct {
// 	ProjectId              string        `env:"INTEG_TEST_PROJECT_ID,default=access-on-demand-i-12af76"`
// 	// RunId                  string        `env:"INTEG_TEST_RUN_ID,required"`
// 	IAMExpirationStartTime string        `env:"INTEG_TEST_IAM_EXPIRATION_START_TIME,default=2023-08-17T04:58:38+00:00"`
// 	IAMExpirationDuration  string        `env:"INTEG_TEST_IAM_EXPIRATION_DURATION,default=2h"`
// 	QueryRetryWaitDuration time.Duration `env:"INTEG_TEST_QUERY_RETRY_WAIT_DURATION,default=10s"`
// 	QueryRetryLimit        uint64        `env:"INTEG_TEST_QUERY_RETRY_COUNT,default=20"`
// 	ConditionTitle         string        `env:"INTEG_TEST_CONDITION_TITLE,default=test"`
// 	WorkingDir             string        `env:"INTEG_TEST_WORKING_DIR,default=/Users/suhongq/IdeaProjects/access-on-demand/test/data"`
// }

type config struct {
	ProjectId                 string        `env:"INTEG_TEST_PROJECT_ID,required"`
	IAMExpirationStartTime    string        `env:"INTEG_TEST_IAM_EXPIRATION_START_TIME,required"`
	IAMExpirationDurationHour string        `env:"INTEG_TEST_IAM_EXPIRATION_DURATION_HOUR,required"`
	QueryRetryWaitDuration    time.Duration `env:"INTEG_TEST_QUERY_RETRY_WAIT_DURATION,default=10s"`
	QueryRetryLimit           uint64        `env:"INTEG_TEST_QUERY_RETRY_COUNT,default=20"`
	ConditionTitle            string        `env:"INTEG_TEST_CONDITION_TITLE,required"`
	WorkingDir                string        `env:"INTEG_TEST_WORKING_DIR,required"`
	IAMExpiration             string        `env:"INTEG_TEST_IAM_EXPIRATION,required"`
}

func newTestConfig(ctx context.Context) (*config, error) {
	var c config
	if err := envconfig.ProcessWith(ctx, &c, envconfig.OsLookuper()); err != nil {
		return nil, fmt.Errorf("failed to process environment: %w", err)
	}

	// st, err := c.printStartTime()
	// if err != nil {
	// 	return nil, err
	// }

	// c.IAMExpirationStartTime = st

	// c.ConditionTitle = fmt.Sprintf("%s-%s", conditionTitlePrefix, c.RunId[len(c.RunId)-7:])

	return &c, nil
}

// func (c *config)printStartTime() (string, error) {
// 	t, err := time.Parse(time.RFC3339, c.IAMExpirationStartTime)
// 	if err != nil {
// 		return "", fmt.Errorf("failed to parse IAMExpirationStartTime %w", err)
// 	}
// 	return t.Format(time.RFC3339), nil
// }
