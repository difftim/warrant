package event

import (
	"context"
	"encoding/json"
	"time"

	"github.com/rs/zerolog/log"
	authz "github.com/warrant-dev/warrant/pkg/authz/objecttype"
	"github.com/warrant-dev/warrant/pkg/messaging/kafka"
)

const (
	// 事件类型
	EventTypeGrant  = "grant"  // 授权
	EventTypeRevoke = "revoke" // 撤销授权

	// 关系类型
	RelationMember = "member"
)

// AuthzChangeEvent 授权变更事件消息结构
type AuthzChangeEvent struct {
	EventType   string `json:"eventType"`   // grant / revoke
	ObjectType  string `json:"objectType"`  // 授权对象类型 (workspaceApp)
	ObjectId    string `json:"objectId"`    // 授权对象ID (app id)
	SubjectType string `json:"subjectType"` // 被授权主体类型 (user)
	SubjectId   string `json:"subjectId"`   // 被授权主体ID (user id)
	Relation    string `json:"relation"`    // 关系 (member)
	OrgId       string `json:"orgId"`       // 组织ID
	Timestamp   int64  `json:"timestamp"`   // 事件发生时间戳(毫秒)
}

// NewAuthzChangeEvent 创建授权变更事件
func NewAuthzChangeEvent(eventType, objectType, objectId, subjectType, subjectId, relation, orgId string) *AuthzChangeEvent {
	return &AuthzChangeEvent{
		EventType:   eventType,
		ObjectType:  objectType,
		ObjectId:    objectId,
		SubjectType: subjectType,
		SubjectId:   subjectId,
		Relation:    relation,
		OrgId:       orgId,
		Timestamp:   time.Now().UnixMilli(),
	}
}

// ToJSON 序列化为 JSON
func (e *AuthzChangeEvent) ToJSON() ([]byte, error) {
	return json.Marshal(e)
}

// PublishAuthzChangeEvent 发布授权变更事件到 Kafka
func PublishAuthzChangeEvent(ctx context.Context, event *AuthzChangeEvent) error {
	if !kafka.IsEnabled() {
		log.Ctx(ctx).Info().Msg("kafka is disabled, skip publishing authz change event")
		return nil
	}

	data, err := event.ToJSON()
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to serialize authz change event")
		return err
	}

	msg := kafka.Message{
		Value: data,
	}

	if err := kafka.Publish(ctx, msg); err != nil {
		log.Ctx(ctx).Error().Err(err).
			Msgf("failed to publish authz change event to kafka: %s", string(data))
		return err
	}

	log.Ctx(ctx).Info().
		Msgf("published authz change event to kafka: %s", string(data))

	return nil
}

// ShouldNotify 判断是否需要发送通知
// 只处理 workspaceApp / policyGroup 相关的授权变更，relation 为 member 或 denied（黑名单）
func ShouldNotify(objectType, relation string) bool {
	if objectType != authz.ObjectTypeWorkspaceApp && objectType != authz.ObjectTypePolicyGroup {
		return false
	}
	if relation != RelationMember && relation != authz.RelationDenied {
		return false
	}
	return true
}

// InvertEventType 反转事件类型（grant <-> revoke）。
// 用于黑名单（denied）：新增 denied warrant 意味着撤销有效权限，删除则意味着恢复有效权限。
func InvertEventType(eventType string) string {
	switch eventType {
	case EventTypeGrant:
		return EventTypeRevoke
	case EventTypeRevoke:
		return EventTypeGrant
	default:
		return eventType
	}
}

// IsSupportedSubjectType 判断是否是支持的被授权主体类型
// 只支持 user / org / policyGroup
func IsSupportedSubjectType(subjectType string) bool {
	switch subjectType {
	case authz.ObjectTypeUser, authz.ObjectTypeOrg, authz.ObjectTypePolicyGroup, authz.ObjectTypePlatform:
		return true
	default:
		return false
	}
}
