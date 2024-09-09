// Copyright 2024 WorkOS, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package authz

import (
	"fmt"
	"time"

	"github.com/pkg/errors"
)

const PrimarySortKey = "typeId"

type ObjectTypeListParamParser struct{}

func (parser ObjectTypeListParamParser) GetDefaultSortBy() string {
	return "typeId"
}

func (parser ObjectTypeListParamParser) GetSupportedSortBys() []string {
	return []string{"createdAt", "typeId"}
}

func (parser ObjectTypeListParamParser) ParseValue(val string, sortBy string) (interface{}, error) {
	switch sortBy {
	//nolint:goconst
	case "createdAt":
		value, err := time.Parse(time.RFC3339, val)
		if err != nil || value.Equal(time.Time{}) {
			return nil, fmt.Errorf("must be a valid time in the format %s", time.RFC3339)
		}

		return &value, nil
	case "typeId":
		if val == "" {
			return nil, errors.New("must not be empty")
		}

		return val, nil
	default:
		return nil, errors.New(fmt.Sprintf("must match type of selected sortBy attribute %s", sortBy))
	}
}
