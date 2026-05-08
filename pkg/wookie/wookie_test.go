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

package wookie_test

import (
	"context"
	"testing"

	"github.com/warrant-dev/warrant/pkg/wookie"
)

func TestBasicSerialization(t *testing.T) {
	t.Parallel()
	ctx := wookie.WithLatest(context.Background())
	if !wookie.ContainsLatest(ctx) {
		t.Fatalf("expected ctx to contain 'latest' wookie")
	}

	ctx = context.Background()
	if wookie.ContainsLatest(ctx) {
		t.Fatalf("expected ctx to not contain 'latest' wookie")
	}
}

func TestOrgIDFilterValuesIncludesIndividualForPersonalOrgWhenEnabled(t *testing.T) {
	t.Parallel()
	ctx := wookie.WithIndividualOrgFallback(context.Background())

	orgIDs := wookie.OrgIDFilterValues(ctx, "personal_123")

	expected := []string{"personal_123", "individual", "*"}
	if len(orgIDs) != len(expected) {
		t.Fatalf("expected %d org ids, got %d: %v", len(expected), len(orgIDs), orgIDs)
	}
	for i, expectedOrgID := range expected {
		if orgIDs[i] != expectedOrgID {
			t.Fatalf("expected org id %d to be %q, got %q", i, expectedOrgID, orgIDs[i])
		}
	}
}
