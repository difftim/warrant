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
		log.Info().Msg("kafka is disabled, skip publishing authz change event")
		return nil
	}

	data, err := event.ToJSON()
	if err != nil {
		log.Error().Err(err).Msg("failed to serialize authz change event")
		return err
	}

	msg := kafka.Message{
		Value: data,
	}

	if err := kafka.Publish(ctx, msg); err != nil {
		log.Error().Err(err).
			Str("eventType", event.EventType).
			Str("objectType", event.ObjectType).
			Str("objectId", event.ObjectId).
			Str("subjectType", event.SubjectType).
			Str("subjectId", event.SubjectId).
			Msg("failed to publish authz change event to kafka")
		return err
	}

	log.Info().
		Str("eventType", event.EventType).
		Str("objectType", event.ObjectType).
		Str("objectId", event.ObjectId).
		Str("subjectType", event.SubjectType).
		Str("subjectId", event.SubjectId).
		Msg("published authz change event to kafka")

	return nil
}

// ShouldNotify 判断是否需要发送通知
// 只处理 workspaceApp 相关的授权变更，且 relation 必须是 member
func ShouldNotify(objectType, relation string) bool {
	if objectType != authz.ObjectTypeWorkspaceApp {
		return false
	}
	if relation != RelationMember {
		return false
	}
	return true
}

// IsSupportedSubjectType 判断是否是支持的被授权主体类型
// 只支持 user / org / policyGroup
func IsSupportedSubjectType(subjectType string) bool {
	switch subjectType {
	case authz.ObjectTypeUser, authz.ObjectTypeOrg, authz.ObjectTypePolicyGroup:
		return true
	default:
		return false
	}
}
