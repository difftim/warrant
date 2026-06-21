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

package object

import (
	"context"

	"github.com/warrant-dev/warrant/pkg/service"
	"github.com/warrant-dev/warrant/pkg/wookie"
)

// WarrantInvalidator 抽象 warrant 缓存的全量失效能力。删除 object 会级联软删除
// 以该 object 为 object 或 subject 的所有 warrant（DeleteWarrantsMatchingObject /
// DeleteWarrantsMatchingSubject），其中按 subject 删除会影响无法枚举的桶，故退化为全量失效。
type WarrantInvalidator interface {
	InvalidateAll(ctx context.Context)
}

// CachedService 包装 object.Service，仅在删除 object 后触发 warrant 缓存失效。
type CachedService struct {
	*ObjectService
	invalidator WarrantInvalidator
}

func NewCachedService(svc *ObjectService, invalidator WarrantInvalidator) *CachedService {
	return &CachedService{
		ObjectService: svc,
		invalidator:   invalidator,
	}
}

// Routes 覆盖底层 ObjectService 的同名方法，确保删除 object 的 HTTP handler
// 绑定到 CachedService 自身，从而触发 warrant 缓存的级联失效。
func (s *CachedService) Routes() ([]service.Route, error) {
	return objectRoutes(s)
}

func (s *CachedService) DeleteByObjectTypeAndId(ctx context.Context, objectType string, objectId string) (*wookie.Token, error) {
	token, err := s.ObjectService.DeleteByObjectTypeAndId(ctx, objectType, objectId)
	if err == nil && s.invalidator != nil {
		s.invalidator.InvalidateAll(ctx)
	}
	return token, err
}
