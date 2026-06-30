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
	"errors"
	"time"

	"github.com/rs/zerolog/log"
	objecttype "github.com/warrant-dev/warrant/pkg/authz/objecttype"
	"github.com/warrant-dev/warrant/pkg/messaging/event"
	"github.com/warrant-dev/warrant/pkg/object"
	"github.com/warrant-dev/warrant/pkg/service"
	"github.com/warrant-dev/warrant/pkg/wookie"
)

type Service interface {
	Create(ctx context.Context, spec CreateWarrantSpec) (*WarrantSpec, *wookie.Token, error)
	List(ctx context.Context, filterParams FilterParams, listParams service.ListParams) ([]WarrantSpec, *service.Cursor, *service.Cursor, error)
	Delete(ctx context.Context, spec DeleteWarrantSpec) (*wookie.Token, error)
	ListWarrantApps(ctx context.Context) ([]*WarrantApp, error)
}

type WarrantService struct {
	service.BaseService
	repository    WarrantRepository
	objectTypeSvc objecttype.Service
	objectSvc     object.Service
}

func NewService(env service.Env, repository WarrantRepository, objectTypeSvc objecttype.Service, objectSvc object.Service) *WarrantService {
	return &WarrantService{
		BaseService:   service.NewBaseService(env),
		repository:    repository,
		objectTypeSvc: objectTypeSvc,
		objectSvc:     objectSvc,
	}
}

func (svc WarrantService) Create(ctx context.Context, spec CreateWarrantSpec) (*WarrantSpec, *wookie.Token, error) {
	var createdWarrant Model
	err := svc.Env().DB().WithinTransaction(ctx, func(txCtx context.Context) error {
		// Check that objectType exists
		objectTypeDef, err := svc.objectTypeSvc.GetByTypeId(txCtx, spec.ObjectType)
		if err != nil {
			var recordNotFoundError *service.RecordNotFoundError
			if errors.As(err, &recordNotFoundError) {
				return service.NewInvalidParameterError("objectType", "the object type does not exist.")
			}

			return err
		}

		// Check that relation is valid for objectType
		if _, exists := objectTypeDef.Relations[spec.Relation]; !exists {
			return service.NewInvalidParameterError("relation", "the relation does not exist on the specified object type.")
		}

		// Unless objectId is wildcard, create referenced object if it does not already exist
		if spec.ObjectId != Wildcard {
			objectSpec, err := svc.objectSvc.GetByObjectTypeAndId(txCtx, spec.ObjectType, spec.ObjectId)
			if err != nil {
				var recordNotFoundError *service.RecordNotFoundError
				if !errors.As(err, &recordNotFoundError) {
					return err
				}
			}

			if objectSpec == nil {
				_, err = svc.objectSvc.Create(txCtx, object.CreateObjectSpec{
					ObjectType: spec.ObjectType,
					ObjectId:   spec.ObjectId,
				})
				if err != nil {
					var duplicateRecordError *service.DuplicateRecordError
					if !errors.As(err, &duplicateRecordError) {
						return err
					}
				}
			}
		}

		// Unless subject objectId is wildcard, create referenced subject if it does not already exist
		if spec.Subject.ObjectId != Wildcard {
			objectSpec, err := svc.objectSvc.GetByObjectTypeAndId(txCtx, spec.Subject.ObjectType, spec.Subject.ObjectId)
			if err != nil {
				var recordNotFoundError *service.RecordNotFoundError
				if !errors.As(err, &recordNotFoundError) {
					return err
				}
			}

			if objectSpec == nil {
				_, err = svc.objectSvc.Create(txCtx, object.CreateObjectSpec{
					ObjectType: spec.Subject.ObjectType,
					ObjectId:   spec.Subject.ObjectId,
				})
				if err != nil {
					var duplicateRecordError *service.DuplicateRecordError
					if !errors.As(err, &duplicateRecordError) {
						return err
					}
				}
			}
		}

		warrant, err := spec.ToWarrant()
		if err != nil {
			return err
		}

		createdWarrantId, err := svc.repository.Create(txCtx, warrant)
		if err != nil {
			return err
		}

		createdWarrant, err = svc.repository.GetByID(txCtx, createdWarrantId)
		if err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		return nil, nil, err
	}

	svc.asyncNotifyAuthzChange(ctx, spec.ObjectType, spec.ObjectId, spec.Subject.ObjectType, spec.Subject.ObjectId, spec.Relation, createdWarrant.GetOrgId(), event.EventTypeGrant)

	return createdWarrant.ToWarrantSpec(), nil, nil
}

func (svc WarrantService) List(ctx context.Context, filterParams FilterParams, listParams service.ListParams) ([]WarrantSpec, *service.Cursor, *service.Cursor, error) {
	warrantSpecs := make([]WarrantSpec, 0)
	warrants, prevCursor, nextCursor, err := svc.repository.List(ctx, filterParams, listParams)
	if err != nil {
		return warrantSpecs, prevCursor, nextCursor, err
	}

	for _, warrant := range warrants {
		warrantSpecs = append(warrantSpecs, *warrant.ToWarrantSpec())
	}

	return warrantSpecs, prevCursor, nextCursor, nil
}

func (svc WarrantService) Delete(ctx context.Context, spec DeleteWarrantSpec) (*wookie.Token, error) {
	err := svc.Env().DB().WithinTransaction(ctx, func(txCtx context.Context) error {
		warrantToDelete, err := spec.ToWarrant()
		if err != nil {
			return err
		}

		err = svc.repository.Delete(txCtx, warrantToDelete.GetObjectType(), warrantToDelete.GetObjectId(), warrantToDelete.GetRelation(), warrantToDelete.GetSubjectType(), warrantToDelete.GetSubjectId(), warrantToDelete.GetSubjectRelation(), warrantToDelete.GetPolicyHash())
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	// 发送授权撤销通知（异步，不阻塞主流程）
	// 复制 ctx 避免 HTTP 请求结束后 context 被取消
	subjectType := ""
	subjectId := ""
	if spec.Subject != nil {
		subjectType = spec.Subject.ObjectType
		subjectId = spec.Subject.ObjectId
	}
	svc.asyncNotifyAuthzChange(ctx, spec.ObjectType, spec.ObjectId, subjectType, subjectId, spec.Relation, ctx.Value(wookie.OrgIdKey).(string), event.EventTypeRevoke)
	//nolint:nilnil
	return nil, nil
}

func (svc WarrantService) ListWarrantApps(ctx context.Context) ([]*WarrantApp, error) {
	return svc.repository.ListWarrantApps(ctx)
}

func (svc WarrantService) asyncNotifyAuthzChange(ctx context.Context, objectType, objectId, subjectType, subjectId, relation, orgId, eventType string) {
	if objectType == "" || objectId == "" || objectId == Wildcard || subjectType == "" || subjectId == "" || subjectId == Wildcard || relation == "" || orgId == "" {
		log.Ctx(ctx).Error().Msg("invalid parameters in asyncNotifyAuthzChange")
		return
	}

	asyncCtx, cancel := copyContextForAsync(ctx)
	go func() {
		defer cancel()
		defer func() {
			if r := recover(); r != nil {
				log.Ctx(asyncCtx).Error().Msgf("panic in asyncNotifyAuthzChange: %v", r)
			}
		}()
		log.Ctx(asyncCtx).Info().Msgf("asyncNotifyAuthzChange start: objectType=%s, objectId=%s, subjectType=%s, subjectId=%s, relation=%s, orgId=%s, eventType=%s", objectType, objectId, subjectType, subjectId, relation, orgId, eventType)
		svc.notifyAuthzChange(asyncCtx, objectType, objectId, subjectType, subjectId, relation, orgId, eventType)
		log.Ctx(asyncCtx).Info().Msgf("asyncNotifyAuthzChange end: objectType=%s, objectId=%s, subjectType=%s, subjectId=%s, relation=%s, orgId=%s, eventType=%s", objectType, objectId, subjectType, subjectId, relation, orgId, eventType)
	}()
}

// copyContextForAsync 复制 ctx 中的所有值到新的 context，用于异步 goroutine
// 新的 context 不会被原始 HTTP 请求取消，但保留所有存储的值
// 添加 30 秒超时保护，防止 goroutine 泄漏
func copyContextForAsync(ctx context.Context) (context.Context, context.CancelFunc) {
	newCtx := context.WithoutCancel(ctx)
	return context.WithTimeout(newCtx, 30*time.Second)
}

// notifyAuthzChange 发送授权变更通知
// 特殊处理：如果 workspaceApp 给 policyGroup 授权变更，需要展开 policyGroup 下所有 user member 逐个发通知
func (svc WarrantService) notifyAuthzChange(ctx context.Context, objectType, objectId, subjectType, subjectId, relation, orgId, eventType string) {
	log.Info().
		Msgf("notifyAuthzChange: %v", map[string]string{
			"objectType":  objectType,
			"relation":    relation,
			"subjectType": subjectType,
			"subjectId":   subjectId,
			"orgId":       orgId,
			"eventType":   eventType,
		})
	// 只处理 workspaceApp 的 member 授权变更
	if !event.ShouldNotify(objectType, relation) {
		log.Info().
			Str("objectType", objectType).
			Str("relation", relation).
			Msg("skip notify authz change")
		return
	}

	// 只处理支持的 subjectType
	if !event.IsSupportedSubjectType(subjectType) {
		log.Info().
			Str("subjectType", subjectType).
			Msg("skip notify authz change")
		return
	}

	// 黑名单（denied）语义与有效权限相反：新增 denied = 撤销权限，删除 denied = 恢复权限，
	// 因此向下游发送通知时需要反转事件类型。
	if relation == objecttype.RelationDenied {
		eventType = event.InvertEventType(eventType)
	}

	// 特殊处理：workspaceApp -> policyGroup 授权变更
	if subjectType == objecttype.ObjectTypePolicyGroup || objectType == objecttype.ObjectTypePolicyGroup {
		svc.notifyPolicyGroupMembers(ctx, objectType, objectId, subjectType, subjectId, relation, orgId, eventType)
		return
	}

	// 普通情况：直接发送通知
	// 对于 user 类型，直接发送
	// 对于 org 类型，也直接发送（由下游消费者处理）
	evt := event.NewAuthzChangeEvent(eventType, objectType, objectId, subjectType, subjectId, relation, orgId)
	if err := event.PublishAuthzChangeEvent(ctx, evt); err != nil {
		log.Ctx(ctx).Error().Err(err).
			Msgf("failed to publish authz change event")
	}
}

// notifyPolicyGroupMembers 展开 policyGroup 下的所有 user member，逐个发送通知
func (svc WarrantService) notifyPolicyGroupMembers(ctx context.Context, objectType, objectId, subjectType, subjectId, relation, orgId, eventType string) {
	if subjectType != objecttype.ObjectTypePolicyGroup && objectType != objecttype.ObjectTypePolicyGroup {
		log.Ctx(ctx).Info().
			Str("subjectType", subjectType).
			Str("objectType", objectType).
			Msg("skip notify policyGroup members because subjectType or objectType is not policyGroup")
		return
	}

	updateAppForPolicyGroup := objectType == objecttype.ObjectTypeWorkspaceApp && subjectType == objecttype.ObjectTypePolicyGroup
	updateUserForPolicyGroup := objectType == objecttype.ObjectTypePolicyGroup && subjectType == objecttype.ObjectTypeUser

	if !updateAppForPolicyGroup && !updateUserForPolicyGroup {
		log.Ctx(ctx).Info().
			Str("subjectType", subjectType).
			Str("objectType", objectType).
			Msg("skip notify policyGroup members because updateAppForPolicyGroup and updateUserForPolicyGroup are false")
		return
	}

	var filterParams FilterParams
	if updateAppForPolicyGroup {
		filterParams = FilterParams{
			ObjectType:  objecttype.ObjectTypePolicyGroup,
			ObjectId:    subjectId,
			Relation:    event.RelationMember,
			SubjectType: objecttype.ObjectTypeUser,
		}
	} else if updateUserForPolicyGroup {
		filterParams = FilterParams{
			ObjectType:  objecttype.ObjectTypeWorkspaceApp,
			Relation:    event.RelationMember,
			SubjectType: objecttype.ObjectTypePolicyGroup,
			SubjectId:   objectId,
		}
	}

	listParams := service.ListParams{
		Limit:     1000, // 一次最多查 1000 个
		SortBy:    "createdAt",
		SortOrder: service.SortOrderDesc,
	}

	warrants, _, _, err := svc.repository.List(ctx, filterParams, listParams)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).
			Str("filterParams", filterParams.String()).
			Msg("failed to list policyGroup members for notification")
		return
	}
	if len(warrants) == 0 {
		log.Ctx(ctx).Info().
			Str("filterParams", filterParams.String()).
			Msg("no policyGroup members found for notification")
		return
	}

	if updateAppForPolicyGroup {
		for _, warrant := range warrants {
			userId := warrant.GetSubjectId()
			evt := event.NewAuthzChangeEvent(eventType, objectType, objectId, objecttype.ObjectTypeUser, userId, relation, orgId)
			if err := event.PublishAuthzChangeEvent(ctx, evt); err != nil {
				log.Ctx(ctx).Error().Err(err).
					Msg("failed to publish authz change event for policyGroup app member")
			}
		}
	} else if updateUserForPolicyGroup {
		for _, warrant := range warrants {
			appId := warrant.GetObjectId()
			evt := event.NewAuthzChangeEvent(eventType, objecttype.ObjectTypeWorkspaceApp, appId, objecttype.ObjectTypeUser, subjectId, relation, orgId)
			if err := event.PublishAuthzChangeEvent(ctx, evt); err != nil {
				log.Error().Err(err).
					Msg("failed to publish authz change event for policyGroup user member")
			}
		}
	}
}
