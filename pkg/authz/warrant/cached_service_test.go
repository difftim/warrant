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

import "testing"

func spec(relation, subjectType, subjectId, subjectRelation string) WarrantSpec {
	return WarrantSpec{
		ObjectType: "report",
		ObjectId:   "r1",
		Relation:   relation,
		Subject: &SubjectSpec{
			ObjectType: subjectType,
			ObjectId:   subjectId,
			Relation:   subjectRelation,
		},
	}
}

func TestFilterBucketRelation(t *testing.T) {
	bucket := []WarrantSpec{
		spec("viewer", "user", "1", ""),
		spec("editor", "user", "1", ""),
		spec("viewer", "user", "2", ""),
	}
	got := filterBucket(bucket, FilterParams{Relation: "viewer"}, 0)
	if len(got) != 2 {
		t.Fatalf("expected 2 viewer warrants, got %d", len(got))
	}
	for _, w := range got {
		if w.Relation != "viewer" {
			t.Fatalf("unexpected relation %s", w.Relation)
		}
	}
}

func TestFilterBucketSubjectExactAndWildcard(t *testing.T) {
	bucket := []WarrantSpec{
		spec("viewer", "user", "1", ""),
		spec("viewer", "user", "*", ""), // wildcard subject must always match a subjectId filter
		spec("viewer", "user", "2", ""),
	}
	got := filterBucket(bucket, FilterParams{
		Relation:    "viewer",
		SubjectType: "user",
		SubjectId:   "1",
	}, 0)
	// expects user:1 and user:* (subject_id IN (?, '*'))
	if len(got) != 2 {
		t.Fatalf("expected 2 (exact + wildcard), got %d", len(got))
	}
}

func TestFilterBucketSubjectType(t *testing.T) {
	bucket := []WarrantSpec{
		spec("member", "user", "1", ""),
		spec("member", "role", "admin", ""),
	}
	got := filterBucket(bucket, FilterParams{Relation: "member", SubjectType: "role"}, 0)
	if len(got) != 1 || got[0].Subject.ObjectType != "role" {
		t.Fatalf("expected only role subject, got %+v", got)
	}
}

func TestFilterBucketSubjectRelation(t *testing.T) {
	bucket := []WarrantSpec{
		spec("member", "role", "admin", ""),
		spec("member", "role", "admin", "member"),
	}
	got := filterBucket(bucket, FilterParams{Relation: "member", SubjectRelation: "member"}, 0)
	if len(got) != 1 || got[0].Subject.Relation != "member" {
		t.Fatalf("expected only subjectRelation=member, got %+v", got)
	}
}

func TestFilterBucketNoFilterReturnsAll(t *testing.T) {
	bucket := []WarrantSpec{
		spec("viewer", "user", "1", ""),
		spec("editor", "user", "2", ""),
	}
	got := filterBucket(bucket, FilterParams{}, 0)
	if len(got) != 2 {
		t.Fatalf("expected all 2, got %d", len(got))
	}
}

func TestFilterBucketLimit(t *testing.T) {
	bucket := []WarrantSpec{
		spec("viewer", "user", "1", ""),
		spec("viewer", "user", "2", ""),
		spec("viewer", "user", "3", ""),
	}
	got := filterBucket(bucket, FilterParams{Relation: "viewer"}, 2)
	if len(got) != 2 {
		t.Fatalf("expected limit 2, got %d", len(got))
	}
}

func TestBucketVersionKeyOrgIndependent(t *testing.T) {
	// 版本号桶以 (objectType,objectId) 为键，与 org 无关：
	// 一次写应能失效该桶的所有 org 变体。
	k1 := bucketVersionKey("warrant:", "report", "r1")
	k2 := bucketVersionKey("warrant:", "report", "r1")
	if k1 != k2 {
		t.Fatalf("version key must be stable for same (objectType,objectId)")
	}
	if bucketVersionKey("warrant:", "report", "r1") == bucketVersionKey("warrant:", "report", "r2") {
		t.Fatalf("different objects must have different version keys")
	}
}

func TestBucketDataKeyVariesByDimensions(t *testing.T) {
	base := bucketDataKey("warrant:", 1, 1, "report", "r1", "orgA")
	if base == bucketDataKey("warrant:", 2, 1, "report", "r1", "orgA") {
		t.Fatalf("data key must change with epoch")
	}
	if base == bucketDataKey("warrant:", 1, 2, "report", "r1", "orgA") {
		t.Fatalf("data key must change with version")
	}
	if base == bucketDataKey("warrant:", 1, 1, "report", "r1", "orgB") {
		t.Fatalf("data key must change with org scope")
	}
	if base == bucketDataKey("warrant:", 1, 1, "report", "r2", "orgA") {
		t.Fatalf("data key must change with objectId")
	}
}

func TestSubjectVersionKeyDimensions(t *testing.T) {
	// subject 桶版本号以 (objectType,subjectType,subjectId) 为键，与 org 无关。
	k1 := subjectVersionKey("warrant:", "report", "user", "u1")
	k2 := subjectVersionKey("warrant:", "report", "user", "u1")
	if k1 != k2 {
		t.Fatalf("version key must be stable for same (objectType,subjectType,subjectId)")
	}
	base := k1
	if base == subjectVersionKey("warrant:", "doc", "user", "u1") {
		t.Fatalf("different objectType must have different version keys")
	}
	if base == subjectVersionKey("warrant:", "report", "group", "u1") {
		t.Fatalf("different subjectType must have different version keys")
	}
	if base == subjectVersionKey("warrant:", "report", "user", "u2") {
		t.Fatalf("different subjectId must have different version keys")
	}
}

func TestSubjectDataKeyVariesByDimensions(t *testing.T) {
	base := subjectDataKey("warrant:", 1, 1, "report", "user", "u1", "orgA")
	if base == subjectDataKey("warrant:", 2, 1, "report", "user", "u1", "orgA") {
		t.Fatalf("data key must change with epoch")
	}
	if base == subjectDataKey("warrant:", 1, 2, "report", "user", "u1", "orgA") {
		t.Fatalf("data key must change with version")
	}
	if base == subjectDataKey("warrant:", 1, 1, "doc", "user", "u1", "orgA") {
		t.Fatalf("data key must change with objectType")
	}
	if base == subjectDataKey("warrant:", 1, 1, "report", "user", "u2", "orgA") {
		t.Fatalf("data key must change with subjectId")
	}
	if base == subjectDataKey("warrant:", 1, 1, "report", "user", "u1", "orgB") {
		t.Fatalf("data key must change with org scope")
	}
	// object 桶与 subject 桶的 key 空间不得重叠。
	if bucketDataKey("warrant:", 1, 1, "report", "r1", "orgA") == subjectDataKey("warrant:", 1, 1, "report", "r1", "orgA", "") {
		t.Fatalf("object/subject bucket key spaces must not collide")
	}
}
