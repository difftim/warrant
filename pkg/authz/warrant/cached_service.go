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
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/warrant-dev/warrant/pkg/cache"
	"github.com/warrant-dev/warrant/pkg/service"
	"github.com/warrant-dev/warrant/pkg/stats"
	"github.com/warrant-dev/warrant/pkg/wookie"
)

const (
	// maxBucketSize 是单个 (objectType,objectId) 桶缓存的最大行数。
	maxBucketSize = 100000
)

// CachedService 在 WarrantService 之上提供读缓存与写失效。
//   - 读：仅当 context 被标记为 read-through（Check 路径）且满足缓存条件时，
//     以 (objectType,objectId) 为桶缓存"原始行集合"，relation/subject 在内存过滤。
//   - 写：Create/Delete 在底层事务提交成功后，同步对受影响桶 INCR 版本号失效。
type CachedService struct {
	*WarrantService
	cache *cache.Cache
}

func NewCachedService(svc *WarrantService, c *cache.Cache) *CachedService {
	return &CachedService{
		WarrantService: svc,
		cache:          c,
	}
}

// Routes 覆盖底层 WarrantService 的同名方法，确保 HTTP 写/读 handler 绑定到
// CachedService 自身（而非被方法提升绑定到未装饰的底层 service），从而让
// Create/Delete 经过缓存失效、List 经过读缓存。
func (s *CachedService) Routes() ([]service.Route, error) {
	return warrantRoutes(s)
}

// epochKey 是全局 warrant 版本号 key。仅在无法枚举受影响桶的罕见写
// （通配符 object 的 warrant、object 删除级联）时 +1，触发全量失效。
func (s *CachedService) epochKey() string {
	return s.cache.Prefix() + "wepoch"
}

// InvalidateAll 触发 warrant 缓存全量失效（供 object 删除级联等无法枚举桶的场景调用）。
func (s *CachedService) InvalidateAll(ctx context.Context) {
	if s.cache.Enabled() {
		ek := s.epochKey()
		log.Ctx(ctx).Info().Str("epochKey", ek).Msg("cache: warrant invalidateAll (epoch bump)")
		_ = s.cache.Incr(ctx, ek)
	}
}

func (s *CachedService) Create(ctx context.Context, spec CreateWarrantSpec) (*WarrantSpec, *wookie.Token, error) {
	res, token, err := s.WarrantService.Create(ctx, spec)
	if err == nil {
		s.invalidateBucket(ctx, spec.ObjectType, spec.ObjectId)
	}
	return res, token, err
}

func (s *CachedService) Delete(ctx context.Context, spec DeleteWarrantSpec) (*wookie.Token, error) {
	token, err := s.WarrantService.Delete(ctx, spec)
	if err == nil {
		s.invalidateBucket(ctx, spec.ObjectType, spec.ObjectId)
	}
	return token, err
}

// invalidateBucket 在写提交后同步失效。对通配符 object 的 warrant，因其会出现在该
// type 下所有 object 的桶中（List 的 object_id IN (oid,'*') 合并），无法精确枚举，
// 退化为全量失效。
func (s *CachedService) invalidateBucket(ctx context.Context, objectType, objectId string) {
	if !s.cache.Enabled() {
		return
	}
	if objectId == Wildcard || objectId == "" {
		ek := s.epochKey()
		log.Ctx(ctx).Info().
			Str("objectType", objectType).Str("objectId", objectId).
			Str("epochKey", ek).
			Msg("cache: warrant write -> wildcard/empty objectId, invalidate all (epoch bump)")
		_ = s.cache.Incr(ctx, ek)
		return
	}
	vk := bucketVersionKey(s.cache.Prefix(), objectType, objectId)
	log.Ctx(ctx).Info().
		Str("objectType", objectType).Str("objectId", objectId).
		Str("versionKey", vk).
		Msg("cache: warrant write -> invalidate bucket (version bump)")
	_ = s.cache.Incr(ctx, vk)
}

func (s *CachedService) List(ctx context.Context, filterParams FilterParams, listParams service.ListParams) ([]WarrantSpec, *service.Cursor, *service.Cursor, error) {
	if !s.cacheable(ctx, filterParams, listParams) {
		log.Ctx(ctx).Debug().
			Str("objectType", filterParams.ObjectType).Str("objectId", filterParams.ObjectId).
			Msg("cache: warrant List bypass (not cacheable)")
		return s.WarrantService.List(ctx, filterParams, listParams)
	}

	objectType := filterParams.ObjectType
	objectId := filterParams.ObjectId
	orgKey, hasOrg := orgScopeKey(ctx, filterParams)
	if !hasOrg {
		log.Ctx(ctx).Debug().
			Str("objectType", objectType).Str("objectId", objectId).
			Msg("cache: warrant List bypass (no org scope)")
		return s.WarrantService.List(ctx, filterParams, listParams)
	}

	counters, ok := s.cache.GetCounters(ctx, s.epochKey(), bucketVersionKey(s.cache.Prefix(), objectType, objectId))
	if !ok {
		log.Ctx(ctx).Debug().
			Str("objectType", objectType).Str("objectId", objectId).
			Msg("cache: warrant List bypass (counters unavailable, falling back to DB)")
		return s.WarrantService.List(ctx, filterParams, listParams)
	}
	epoch, version := counters[0], counters[1]
	dataKey := bucketDataKey(s.cache.Prefix(), epoch, version, objectType, objectId, orgKey)

	var bucket []WarrantSpec
	hit := false
	if vals, ok := s.cache.GetBytes(ctx, dataKey); ok && len(vals) == 1 && vals[0] != nil {
		if err := json.Unmarshal(vals[0], &bucket); err == nil {
			hit = true
		} else {
			log.Ctx(ctx).Warn().Err(err).Str("dataKey", dataKey).Msg("cache: corrupt warrant bucket, refetching")
		}
	}

	if !hit {
		rows, err := s.fetchBucket(ctx, objectType, objectId, filterParams.OrgId)
		if err != nil {
			return nil, nil, nil, err
		}
		bucket = rows
		if b, marshalErr := json.Marshal(bucket); marshalErr == nil {
			s.cache.SetBytes(ctx, dataKey, b)
		}
		stats.IncrCacheMiss(ctx)
		log.Ctx(ctx).Debug().
			Str("objectType", objectType).Str("objectId", objectId).Str("orgKey", orgKey).
			Int64("epoch", epoch).Int64("version", version).Str("dataKey", dataKey).
			Int("rows", len(bucket)).Msg("cache: warrant bucket MISS (refilled from DB)")
	} else {
		stats.IncrCacheHit(ctx)
		log.Ctx(ctx).Debug().
			Str("objectType", objectType).Str("objectId", objectId).Str("orgKey", orgKey).
			Int64("epoch", epoch).Int64("version", version).Str("dataKey", dataKey).
			Int("rows", len(bucket)).Msg("cache: warrant bucket HIT")
	}

	return filterBucket(bucket, filterParams, listParams.Limit), nil, nil, nil
}

// cacheable 判定本次 List 是否可走缓存。
func (s *CachedService) cacheable(ctx context.Context, filterParams FilterParams, listParams service.ListParams) bool {
	if !s.cache.Enabled() {
		return false
	}
	// 仅 Check 路径标记 read-through；管理类查询绕过以保留游标语义并读最新值。
	if !cache.IsReadThrough(ctx) {
		return false
	}
	// 'latest' 强一致请求直查 writer，旁路缓存。
	if wookie.ContainsLatest(ctx) {
		return false
	}
	// 分页游标语义不进缓存。
	if listParams.NextCursor != nil || listParams.PrevCursor != nil {
		return false
	}
	// 桶以 (objectType,objectId) 为键；通配符/空 objectId 的查询语义为跨对象，旁路。
	if filterParams.ObjectType == "" || filterParams.ObjectId == "" || filterParams.ObjectId == Wildcard {
		return false
	}
	return true
}

// fetchBucket 用原始 ctx 拉取 (objectType,objectId) 桶的全部行（含 object_id='*' 合并、
// 按 ctx 的 org 范围过滤），不带 relation/subject 过滤，以便在 Check 的多种查询形态间复用。
func (s *CachedService) fetchBucket(ctx context.Context, objectType, objectId, orgId string) ([]WarrantSpec, error) {
	listParams := service.DefaultListParams(WarrantListParamParser{})
	listParams.WithLimit(maxBucketSize)
	specs, _, _, err := s.WarrantService.List(ctx, FilterParams{
		ObjectType: objectType,
		ObjectId:   objectId,
		OrgId:      orgId,
	}, listParams)
	if err != nil {
		return nil, err
	}
	return specs, nil
}

// filterBucket 在内存中复刻 repository.List 的 relation/subject 过滤语义。
// object 维度已由桶范围（object_id IN (objectId,'*')）保证；org 维度已由 fetchBucket 的
// ctx org 范围保证，因此这里只过滤 relation 与 subject。
func filterBucket(bucket []WarrantSpec, fp FilterParams, limit int) []WarrantSpec {
	result := make([]WarrantSpec, 0, len(bucket))
	for _, w := range bucket {
		if fp.Relation != "" && w.Relation != fp.Relation {
			continue
		}
		if w.Subject == nil {
			if fp.SubjectType != "" || fp.SubjectId != "" || fp.SubjectRelation != "" {
				continue
			}
		} else {
			if fp.SubjectType != "" && w.Subject.ObjectType != fp.SubjectType {
				continue
			}
			// subject_id IN (?, '*')
			if fp.SubjectId != "" && w.Subject.ObjectId != fp.SubjectId && w.Subject.ObjectId != Wildcard {
				continue
			}
			if fp.SubjectRelation != "" && w.Subject.Relation != fp.SubjectRelation {
				continue
			}
		}
		result = append(result, w)
		if limit > 0 && len(result) >= limit {
			break
		}
	}
	return result
}

// orgScopeKey 计算 org 维度的缓存 key 片段，与 repository.List 的 org 过滤一致。
// 返回 ok=false 表示无法安全确定 org 范围，应旁路缓存。
func orgScopeKey(ctx context.Context, fp FilterParams) (string, bool) {
	orgId, _ := ctx.Value(wookie.OrgIdKey).(string)
	if orgId == "" {
		orgId = fp.OrgId
	}
	orgIDs := wookie.OrgIDFilterValues(ctx, orgId)
	if len(orgIDs) == 0 {
		return "", false
	}
	sort.Strings(orgIDs)
	return strings.Join(orgIDs, "|"), true
}

// key 一律使用明文拼接（不做 hash），便于在 Redis 中直接按对象类型/对象ID 排查问题。
// 注意：objectType/objectId 约定为标识符，正常不含冒号；orgKey 由 org 列表用 '|' 连接。

func bucketVersionKey(prefix, objectType, objectId string) string {
	return fmt.Sprintf("%swv:%s:%s", prefix, objectType, objectId)
}

func bucketDataKey(prefix string, epoch, version int64, objectType, objectId, orgKey string) string {
	return fmt.Sprintf("%swd:%d:%d:%s:%s:%s", prefix, epoch, version, objectType, objectId, orgKey)
}
