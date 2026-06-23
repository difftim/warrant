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

	"github.com/rs/zerolog/log"
	"github.com/warrant-dev/warrant/pkg/cache"
	"github.com/warrant-dev/warrant/pkg/service"
	"github.com/warrant-dev/warrant/pkg/stats"
	"github.com/warrant-dev/warrant/pkg/wookie"
)


// CachedService 在 ObjectTypeService 之上缓存 GetByTypeId（Check 路径高频调用），
// 并在写操作提交后失效。object_type 无 org 维度，缓存值全局共享。
type CachedService struct {
	*ObjectTypeService
	cache *cache.Cache
}

func NewCachedService(svc *ObjectTypeService, c *cache.Cache) *CachedService {
	return &CachedService{
		ObjectTypeService: svc,
		cache:             c,
	}
}

// Routes 覆盖底层 ObjectTypeService 的同名方法，确保 HTTP handler 绑定到
// CachedService 自身，使写操作经过缓存失效、GetByTypeId 经过读缓存。
func (s *CachedService) Routes() ([]service.Route, error) {
	return objectTypeRoutes(s)
}

// epochKey 是 object_type 定义的全局版本号 key。任何 object_type 写操作都会 +1，
// 使旧版本缓存项变为孤儿（object_type 变更极少，全量失效完全可接受）。
func (s *CachedService) epochKey() string {
	return s.cache.Prefix() + "oteepoch"
}

func (s *CachedService) GetByTypeId(ctx context.Context, typeId string) (*ObjectTypeSpec, error) {
	if !s.cache.Enabled() || !cache.IsReadThrough(ctx) || wookie.ContainsLatest(ctx) {
		log.Ctx(ctx).Debug().Str("typeId", typeId).Msg("cache: object_type GetByTypeId bypass (disabled/not-read-through/latest)")
		return s.ObjectTypeService.GetByTypeId(ctx, typeId)
	}

	counters, ok := s.cache.GetCounters(ctx, s.epochKey())
	if !ok {
		log.Ctx(ctx).Debug().Str("typeId", typeId).Msg("cache: object_type GetByTypeId bypass (counter unavailable, falling back to DB)")
		return s.ObjectTypeService.GetByTypeId(ctx, typeId)
	}
	dataKey := fmt.Sprintf("%sotd:%d:%s", s.cache.Prefix(), counters[0], typeId)

	if vals, ok := s.cache.GetBytes(ctx, dataKey); ok && len(vals) == 1 && vals[0] != nil {
		var spec ObjectTypeSpec
		if err := json.Unmarshal(vals[0], &spec); err == nil {
			stats.IncrCacheHit(ctx)
			log.Ctx(ctx).Debug().Str("typeId", typeId).Int64("epoch", counters[0]).Str("dataKey", dataKey).Msg("cache: object_type HIT")
			return &spec, nil
		}
		log.Ctx(ctx).Warn().Str("dataKey", dataKey).Msg("cache: corrupt object_type entry, refetching")
	}

	spec, err := s.ObjectTypeService.GetByTypeId(ctx, typeId)
	if err != nil {
		return nil, err
	}
	if b, marshalErr := json.Marshal(spec); marshalErr == nil {
		s.cache.SetBytes(ctx, dataKey, b)
	}
	stats.IncrCacheMiss(ctx)
	log.Ctx(ctx).Debug().Str("typeId", typeId).Int64("epoch", counters[0]).Str("dataKey", dataKey).Msg("cache: object_type MISS (refilled from DB)")
	return spec, nil
}

func (s *CachedService) Create(ctx context.Context, spec CreateObjectTypeSpec) (*ObjectTypeSpec, *wookie.Token, error) {
	res, token, err := s.ObjectTypeService.Create(ctx, spec)
	if err == nil {
		s.invalidate(ctx)
	}
	return res, token, err
}

func (s *CachedService) UpdateByTypeId(ctx context.Context, typeId string, spec UpdateObjectTypeSpec) (*ObjectTypeSpec, *wookie.Token, error) {
	res, token, err := s.ObjectTypeService.UpdateByTypeId(ctx, typeId, spec)
	if err == nil {
		s.invalidate(ctx)
	}
	return res, token, err
}

func (s *CachedService) DeleteByTypeId(ctx context.Context, typeId string) (*wookie.Token, error) {
	token, err := s.ObjectTypeService.DeleteByTypeId(ctx, typeId)
	if err == nil {
		s.invalidate(ctx)
	}
	return token, err
}

func (s *CachedService) invalidate(ctx context.Context) {
	if s.cache.Enabled() {
		ek := s.epochKey()
		log.Ctx(ctx).Info().Str("epochKey", ek).Msg("cache: object_type write -> invalidate all (epoch bump)")
		_ = s.cache.Incr(ctx, ek)
	}
}
