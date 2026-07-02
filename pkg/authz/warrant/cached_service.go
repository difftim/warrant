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
//   - 读：仅当 context 被标记为 read-through（Check / Query 路径）且满足缓存条件时走缓存，
//     按 filter 形态分两种桶，均缓存"原始行集合"、其余条件在内存过滤：
//     1) object 桶 (objectType,objectId)：Check 路径的正查；relation/subject 内存过滤。
//     2) subject 桶 (objectType,subjectType,subjectId)：Query 路径的列举/反查
//     （"某 subject 在某类型上有哪些授权"，无 objectId）；relation 内存过滤。
//   - 写：Create/Delete 在底层事务提交成功后，同步对受影响的两个维度桶 INCR 版本号失效。
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
		s.invalidateForWarrant(ctx, spec.ObjectType, spec.ObjectId, spec.Subject)
	}
	return res, token, err
}

func (s *CachedService) Delete(ctx context.Context, spec DeleteWarrantSpec) (*wookie.Token, error) {
	token, err := s.WarrantService.Delete(ctx, spec)
	if err == nil {
		s.invalidateForWarrant(ctx, spec.ObjectType, spec.ObjectId, spec.Subject)
	}
	return token, err
}

// invalidateForWarrant 在写提交后同步失效受影响的两个维度桶：
//   - object 桶 (objectType,objectId)；
//   - subject 桶 (objectType,subjectType,subjectId)。
//
// 对通配符/空 objectId 的 warrant，因其会出现在该 type 下所有 object 的桶中
//（List 的 object_id IN (oid,'*') 合并），无法精确枚举，退化为全量失效（epoch），
// epoch 在两种 data key 前缀中，天然同时覆盖两个维度。通配符 subject 同理。
func (s *CachedService) invalidateForWarrant(ctx context.Context, objectType, objectId string, subject *SubjectSpec) {
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
		Msg("cache: warrant write -> invalidate object bucket (version bump)")
	_ = s.cache.Incr(ctx, vk)

	// subject 维度失效。Delete 的 subject 理论上可为 nil（HasAnyValue 校验后仍是指针），
	// 此时无法定位 subject 桶，保守退化为全量失效。
	switch {
	case subject == nil || subject.ObjectType == "" || subject.ObjectId == "" || subject.ObjectId == Wildcard:
		ek := s.epochKey()
		log.Ctx(ctx).Info().
			Str("objectType", objectType).Str("objectId", objectId).
			Str("epochKey", ek).
			Msg("cache: warrant write -> wildcard/unknown subject, invalidate all (epoch bump)")
		_ = s.cache.Incr(ctx, ek)
	default:
		svk := subjectVersionKey(s.cache.Prefix(), objectType, subject.ObjectType, subject.ObjectId)
		log.Ctx(ctx).Info().
			Str("objectType", objectType).
			Str("subjectType", subject.ObjectType).Str("subjectId", subject.ObjectId).
			Str("versionKey", svk).
			Msg("cache: warrant write -> invalidate subject bucket (version bump)")
		_ = s.cache.Incr(ctx, svk)
	}
}

func (s *CachedService) List(ctx context.Context, filterParams FilterParams, listParams service.ListParams) ([]WarrantSpec, *service.Cursor, *service.Cursor, error) {
	if !s.readCacheEligible(ctx, listParams) || filterParams.ObjectType == "" {
		log.Ctx(ctx).Debug().
			Str("objectType", filterParams.ObjectType).Str("objectId", filterParams.ObjectId).
			Msg("cache: warrant List bypass (not cacheable)")
		return s.WarrantService.List(ctx, filterParams, listParams)
	}

	switch {
	// object 桶：具体 (objectType,objectId) 的正查（Check 路径）。
	case filterParams.ObjectId != "" && filterParams.ObjectId != Wildcard:
		return s.listViaObjectBucket(ctx, filterParams, listParams)
	// subject 桶：无 objectId、具体 (subjectType,subjectId) 的列举/反查（Query 路径主干）。
	case filterParams.ObjectId == "" && filterParams.SubjectType != "" &&
		filterParams.SubjectId != "" && filterParams.SubjectId != Wildcard:
		return s.listViaSubjectBucket(ctx, filterParams, listParams)
	default:
		log.Ctx(ctx).Debug().
			Str("objectType", filterParams.ObjectType).Str("objectId", filterParams.ObjectId).
			Str("subjectType", filterParams.SubjectType).Str("subjectId", filterParams.SubjectId).
			Msg("cache: warrant List bypass (filter shape not bucketable)")
		return s.WarrantService.List(ctx, filterParams, listParams)
	}
}

// readCacheEligible 判定本次读是否具备走缓存的前提（与 filter 形态无关的公共条件）。
func (s *CachedService) readCacheEligible(ctx context.Context, listParams service.ListParams) bool {
	if !s.cache.Enabled() {
		return false
	}
	// 仅 Check / Query 路径标记 read-through；管理类查询绕过以保留游标语义并读最新值。
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
	return true
}

// listViaObjectBucket 以 (objectType,objectId) 为桶读缓存，relation/subject 在内存过滤。
func (s *CachedService) listViaObjectBucket(ctx context.Context, filterParams FilterParams, listParams service.ListParams) ([]WarrantSpec, *service.Cursor, *service.Cursor, error) {
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

	bucket, hit := s.loadBucket(ctx, dataKey)
	if !hit {
		rows, err := s.fetchBucket(ctx, FilterParams{
			ObjectType: objectType,
			ObjectId:   objectId,
			OrgId:      filterParams.OrgId,
		})
		if err != nil {
			return nil, nil, nil, err
		}
		bucket = rows
		s.storeBucket(ctx, dataKey, bucket)
		stats.IncrCacheMiss(ctx)
		log.Ctx(ctx).Debug().
			Str("objectType", objectType).Str("objectId", objectId).Str("orgKey", orgKey).
			Int64("epoch", epoch).Int64("version", version).Str("dataKey", dataKey).
			Int("rows", len(bucket)).Msg("cache: warrant object bucket MISS (refilled from DB)")
	} else {
		stats.IncrCacheHit(ctx)
		log.Ctx(ctx).Debug().
			Str("objectType", objectType).Str("objectId", objectId).Str("orgKey", orgKey).
			Int64("epoch", epoch).Int64("version", version).Str("dataKey", dataKey).
			Int("rows", len(bucket)).Msg("cache: warrant object bucket HIT")
	}

	return filterBucket(bucket, filterParams, listParams.Limit), nil, nil, nil
}

// listViaSubjectBucket 以 (objectType,subjectType,subjectId) 为桶读缓存，
// relation（及 subjectRelation）在内存过滤。桶内容与 repository 语义一致：
// subject_id IN (subjectId,'*')，即包含通配符 subject 行。
func (s *CachedService) listViaSubjectBucket(ctx context.Context, filterParams FilterParams, listParams service.ListParams) ([]WarrantSpec, *service.Cursor, *service.Cursor, error) {
	objectType := filterParams.ObjectType
	subjectType := filterParams.SubjectType
	subjectId := filterParams.SubjectId
	orgKey, hasOrg := orgScopeKey(ctx, filterParams)
	if !hasOrg {
		log.Ctx(ctx).Debug().
			Str("objectType", objectType).Str("subjectType", subjectType).Str("subjectId", subjectId).
			Msg("cache: warrant List bypass (no org scope)")
		return s.WarrantService.List(ctx, filterParams, listParams)
	}

	counters, ok := s.cache.GetCounters(ctx, s.epochKey(), subjectVersionKey(s.cache.Prefix(), objectType, subjectType, subjectId))
	if !ok {
		log.Ctx(ctx).Debug().
			Str("objectType", objectType).Str("subjectType", subjectType).Str("subjectId", subjectId).
			Msg("cache: warrant List bypass (counters unavailable, falling back to DB)")
		return s.WarrantService.List(ctx, filterParams, listParams)
	}
	epoch, version := counters[0], counters[1]
	dataKey := subjectDataKey(s.cache.Prefix(), epoch, version, objectType, subjectType, subjectId, orgKey)

	bucket, hit := s.loadBucket(ctx, dataKey)
	if !hit {
		rows, err := s.fetchBucket(ctx, FilterParams{
			ObjectType:  objectType,
			SubjectType: subjectType,
			SubjectId:   subjectId,
			OrgId:       filterParams.OrgId,
		})
		if err != nil {
			return nil, nil, nil, err
		}
		bucket = rows
		s.storeBucket(ctx, dataKey, bucket)
		stats.IncrCacheMiss(ctx)
		log.Ctx(ctx).Debug().
			Str("objectType", objectType).Str("subjectType", subjectType).Str("subjectId", subjectId).Str("orgKey", orgKey).
			Int64("epoch", epoch).Int64("version", version).Str("dataKey", dataKey).
			Int("rows", len(bucket)).Msg("cache: warrant subject bucket MISS (refilled from DB)")
	} else {
		stats.IncrCacheHit(ctx)
		log.Ctx(ctx).Debug().
			Str("objectType", objectType).Str("subjectType", subjectType).Str("subjectId", subjectId).Str("orgKey", orgKey).
			Int64("epoch", epoch).Int64("version", version).Str("dataKey", dataKey).
			Int("rows", len(bucket)).Msg("cache: warrant subject bucket HIT")
	}

	return filterBucket(bucket, filterParams, listParams.Limit), nil, nil, nil
}

// loadBucket 读取并反序列化一个桶 data key；损坏数据按未命中处理并重新回填。
func (s *CachedService) loadBucket(ctx context.Context, dataKey string) ([]WarrantSpec, bool) {
	vals, ok := s.cache.GetBytes(ctx, dataKey)
	if !ok || len(vals) != 1 || vals[0] == nil {
		return nil, false
	}
	var bucket []WarrantSpec
	if err := json.Unmarshal(vals[0], &bucket); err != nil {
		log.Ctx(ctx).Warn().Err(err).Str("dataKey", dataKey).Msg("cache: corrupt warrant bucket, refetching")
		return nil, false
	}
	return bucket, true
}

// storeBucket 序列化并回填一个桶 data key（带 DataTTL 兜底）。
func (s *CachedService) storeBucket(ctx context.Context, dataKey string, bucket []WarrantSpec) {
	if b, err := json.Marshal(bucket); err == nil {
		s.cache.SetBytes(ctx, dataKey, b)
	}
}

// fetchBucket 用原始 ctx 按桶维度 filter 拉取全部行（object 桶含 object_id='*' 合并、
// subject 桶含 subject_id='*' 合并、按 ctx 的 org 范围过滤），不带 relation 等细粒度过滤，
// 以便同一个桶在多种查询形态间复用。
func (s *CachedService) fetchBucket(ctx context.Context, bucketFilter FilterParams) ([]WarrantSpec, error) {
	listParams := service.DefaultListParams(WarrantListParamParser{})
	listParams.WithLimit(maxBucketSize)
	specs, _, _, err := s.WarrantService.List(ctx, bucketFilter, listParams)
	if err != nil {
		return nil, err
	}
	return specs, nil
}

// filterBucket 在内存中复刻 repository.List 的 relation/subject 过滤语义。
// 桶自身的维度（object 桶：object_id IN (objectId,'*')；subject 桶：objectType +
// subject_id IN (subjectId,'*')）已由 fetchBucket 的桶范围保证；org 维度已由其
// ctx org 范围保证。这里过滤剩余条件：relation 与 subject（对 subject 桶，
// subject 条件与桶范围一致，天然全部通过）。
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

// subject 桶：sv = 版本计数器，sd = 数据。维度为 (objectType, subjectType, subjectId)，
// 服务"某 subject 在某类型上有哪些授权"的列举/反查（Query 主干）。
func subjectVersionKey(prefix, objectType, subjectType, subjectId string) string {
	return fmt.Sprintf("%ssv:%s:%s:%s", prefix, objectType, subjectType, subjectId)
}

func subjectDataKey(prefix string, epoch, version int64, objectType, subjectType, subjectId, orgKey string) string {
	return fmt.Sprintf("%ssd:%d:%d:%s:%s:%s:%s", prefix, epoch, version, objectType, subjectType, subjectId, orgKey)
}
