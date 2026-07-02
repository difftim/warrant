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
	"net/http"
	"time"

	"github.com/rs/zerolog/log"
	objecttype "github.com/warrant-dev/warrant/pkg/authz/objecttype"
	authz "github.com/warrant-dev/warrant/pkg/authz/warrant"
	"github.com/warrant-dev/warrant/pkg/cache"
	"github.com/warrant-dev/warrant/pkg/service"
	"github.com/warrant-dev/warrant/pkg/wookie"
)

// syncMarkerTTL 是 syncUserRelationsOnQuery 去重护栏的窗口：同一 (org,user) 在该窗口内
// 只会触发一次"懒同步"写（及一次缓存失效），避免每次查询都打掉该 org 的 warrant 缓存。
const syncMarkerTTL = 24 * time.Hour

// queryReadContext 构造 query 读路径的 context：与 Check 路径一致，标记 read-through，
// 使图遍历中的 warrant.List / objecttype.GetByTypeId 走各自装饰器的桶缓存
// （复用现有版本失效机制，不缓存 query 结果本身）。
// 'latest' 强一致请求保持直查 DB，不打标记。
func queryReadContext(r *http.Request) context.Context {
	ctx := wookie.WithIndividualOrgFallback(r.Context())
	if wookie.ContainsLatest(ctx) {
		return ctx
	}
	return cache.WithReadThrough(ctx)
}

func (svc QueryService) Routes() ([]service.Route, error) {
	return []service.Route{
		service.WarrantRoute{
			Pattern: "/v1/query",
			Method:  "GET",
			Handler: service.ChainMiddleware(
				service.NewRouteHandler(svc, queryV1),
				service.ListMiddleware[QueryListParamParser],
			),
		},
		service.WarrantRoute{
			Pattern: "/v2/query",
			Method:  "GET",
			Handler: service.ChainMiddleware(
				service.NewRouteHandler(svc, queryV2),
				service.ListMiddleware[QueryListParamParser],
			),
		},
	}, nil
}

func queryV1(svc QueryService, w http.ResponseWriter, r *http.Request) error {
	ctx := queryReadContext(r)
	queryParams := r.URL.Query()
	queryString := queryParams.Get("q")
	query, err := NewQueryFromString(queryString)
	if err != nil {
		return err
	}

	if queryParams.Has("context") {
		err = query.WithContext(queryParams.Get("context"))
		if err != nil {
			return service.NewInvalidParameterError("context", "invalid")
		}
	}

	listParams := service.GetListParamsFromContext[QueryListParamParser](r.Context())
	// create next cursor from lastId or afterId param
	if r.URL.Query().Has("lastId") {
		lastIdCursor, err := service.NewCursorFromBase64String(r.URL.Query().Get("lastId"), QueryListParamParser{}, listParams.SortBy)
		if err != nil {
			return service.NewInvalidParameterError("lastId", "invalid lastId")
		}

		listParams.WithNextCursor(lastIdCursor)
	} else if r.URL.Query().Has("afterId") {
		afterIdCursor, err := service.NewCursorFromBase64String(r.URL.Query().Get("afterId"), QueryListParamParser{}, listParams.SortBy)
		if err != nil {
			return service.NewInvalidParameterError("afterId", "invalid afterId")
		}

		listParams.WithNextCursor(afterIdCursor)
	}

	results, _, nextCursor, err := svc.Query(ctx, query, listParams)
	if err != nil {
		return err
	}

	var newLastId string
	if nextCursor != nil {
		base64EncodedNextCursor, err := nextCursor.ToBase64String()
		if err != nil {
			return err
		}
		newLastId = base64EncodedNextCursor
	}

	service.SendJSONResponse(w, QueryResponseV1{
		Results: results,
		LastId:  newLastId,
	})
	return nil
}

func queryV2(svc QueryService, w http.ResponseWriter, r *http.Request) error {
	ctx := queryReadContext(r)
	queryParams := r.URL.Query()
	queryString := queryParams.Get("q")
	query, err := NewQueryFromString(queryString)
	if err != nil {
		return err
	}

	syncUserRelationsOnQuery(ctx, svc, query)

	if queryParams.Has("context") {
		err = query.WithContext(queryParams.Get("context"))
		if err != nil {
			return service.NewInvalidParameterError("context", "invalid")
		}
	}

	listParams := service.GetListParamsFromContext[QueryListParamParser](r.Context())
	results, prevCursor, nextCursor, err := svc.Query(ctx, query, listParams)
	if err != nil {
		return err
	}

	service.SendJSONResponse(w, QueryResponseV2{
		Results:    results,
		PrevCursor: prevCursor,
		NextCursor: nextCursor,
	})
	return nil
}

func syncUserRelationsOnQuery(context context.Context, svc QueryService, query Query) {
	if query.SelectObjects == nil ||
		query.SelectObjects.WhereSubject == nil ||
		query.SelectObjects.WhereSubject.Type != objecttype.ObjectTypeUser ||
		query.SelectObjects.WhereSubject.Id == "" {
		return
	}
	userId := query.SelectObjects.WhereSubject.Id
	//orgId, imGroupIds, err := adaptor.GetUserIds(userId, true, true)
	//if err != nil {
	//	log.Error().Err(err).Msgf("syncUserRelationsOnQuery: cannot get user ids for user %s", userId)
	//	return
	//}
	orgId := context.Value(wookie.OrgIdKey).(string)
	log.Ctx(context).Info().Msgf("syncUserRelationsOnQuery,uid:%s, orgId:%s", userId, orgId)

	if orgId != "" {
		// 去重护栏：这条 org-member 关系是幂等的"懒同步"写。Create 是 upsert，即便关系已存在
		// 也会触发缓存失效（INCR wv:org:{orgId}），导致该 org 桶缓存被每次查询打掉。
		// 用一个短期 NX 标记把"同一 (org,user) 在窗口内的重复同步"挡掉，最多失效一次。
		// 缓存未启用/Redis 异常时 SetNXMarker 返回 true，自动退回原有"每次都写"行为，不丢正确性。
		marker := "warrant:synced:org:" + orgId + ":user:" + userId
		if svc.cache.SetNXMarker(context, marker, syncMarkerTTL) {
			_, _, err := svc.warrantSvc.Create(context, authz.CreateWarrantSpec{
				ObjectType: objecttype.ObjectTypeOrg,
				ObjectId:   orgId,
				Relation:   "member",
				Subject: &authz.SubjectSpec{
					ObjectType: objecttype.ObjectTypeUser,
					ObjectId:   userId,
				},
			})
			if err != nil {
				log.Ctx(context).Error().Err(err).Msgf("syncUserRelationsOnQuery: cannot create warrant  for user %s and  orgId %s", userId, orgId)
			}
		} else {
			log.Ctx(context).Debug().Msgf("syncUserRelationsOnQuery: skip (recently synced) user %s orgId %s", userId, orgId)
		}
	}
	//if imGroupIds != nil && len(imGroupIds) > 0 {
	//	for _, groupId := range imGroupIds {
	//		_, _, err = svc.warrantSvc.Create(context, authz.CreateWarrantSpec{
	//			ObjectType: objecttype.ObjectTypeImGroup,
	//			ObjectId:   groupId,
	//			Relation:   "member",
	//			Subject: &authz.SubjectSpec{
	//				ObjectType: objecttype.ObjectTypeUser,
	//				ObjectId:   userId,
	//			},
	//		})
	//		if err != nil {
	//			log.Error().Err(err).Msgf("syncUserRelationsOnQuery: cannot create warrant  for user %s and  imGroupId %s", userId, groupId)
	//		}
	//	}
	//}
}
