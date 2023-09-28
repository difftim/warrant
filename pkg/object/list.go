// Copyright 2023 Forerunner Labs, Inc.
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

package object

import (
	"fmt"
	"time"
)

var supportedSortBys = []string{"createdAt", "objectType", "objectId"}

type ObjectListParamParser struct{}

func (parser ObjectListParamParser) GetDefaultSortBy() string {
	return "objectId"
}

func (parser ObjectListParamParser) GetSupportedSortBys() []string {
	return supportedSortBys
}

func (parser ObjectListParamParser) ParseValue(val string, sortBy string) (interface{}, error) {
	switch sortBy {
	case "createdAt":
		afterValue, err := time.Parse(time.RFC3339, val)
		if err != nil || afterValue.Equal(time.Time{}) {
			return nil, fmt.Errorf("must be a valid time in the format %s", time.RFC3339)
		}

		return &afterValue, nil
	case "objectType", "objectId":
		if val == "" {
			return nil, fmt.Errorf("must not be empty")
		}

		return val, nil
	default:
		return nil, fmt.Errorf("must match type of selected sortBy attribute %s", sortBy)
	}
}

func IsObjectSortBy(sortBy string) bool {
	for _, supportedSortBy := range supportedSortBys {
		if sortBy == supportedSortBy {
			return true
		}
	}

	return false
}