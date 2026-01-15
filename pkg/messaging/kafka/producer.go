package kafka

import (
	"context"
	"fmt"

	"github.com/rs/zerolog/log"
	"github.com/warrant-dev/warrant/pkg/config"
	"github.com/zeromicro/go-queue/kq"
)

// 全局 producer 实例
var defaultProducer *producer

type Message struct {
	Topic   string
	Key     []byte
	Value   []byte
	Headers map[string]string
}

type Producer interface {
	Publish(ctx context.Context, msg Message) error
	Close() error
}

type producer struct {
	defaultTopic string
	pusher       *kq.Pusher
}

// Init 初始化全局 Kafka Producer（服务启动时调用一次）
func Init(cfg *config.KafkaConfig) error {
	instance, err := NewProducer(cfg)
	if err != nil {
		return fmt.Errorf("kafka: could not initialize producer: %w", err)
	}
	defaultProducer = instance.(*producer)
	return nil
}

// Publish 使用全局 producer 发送消息
func Publish(ctx context.Context, msg Message) error {
	if defaultProducer == nil {
		return fmt.Errorf("kafka: producer not initialized, call Init() first")
	}
	return defaultProducer.Publish(ctx, msg)
}

// Close 关闭全局 producer
func Close() error {
	if defaultProducer == nil {
		return nil
	}
	return defaultProducer.Close()
}

// IsEnabled 检查 producer 是否已初始化
func IsEnabled() bool {
	return defaultProducer != nil
}

func NewProducer(cfg *config.KafkaConfig) (Producer, error) {
	if cfg == nil {
		return nil, fmt.Errorf("kafka: config is nil")
	}
	if !cfg.Enabled {
		return nil, fmt.Errorf("kafka: producer is disabled (kafka.enabled=false)")
	}
	if len(cfg.Brokers) == 0 {
		return nil, fmt.Errorf("kafka: brokers must be provided")
	}

	if cfg.Topic == "" {
		log.Warn().Msg("kafka: topic is not provided")
	}

	p := kq.NewPusher(cfg.Brokers, cfg.Topic)
	return &producer{
		defaultTopic: cfg.Topic,
		pusher:       p,
	}, nil
}

func (p *producer) Publish(ctx context.Context, msg Message) error {
	if p == nil || p.pusher == nil {
		return fmt.Errorf("kafka: producer not initialized")
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	topic := p.defaultTopic
	if topic == "" {
		topic = msg.Topic
	}
	if topic == "" {
		return fmt.Errorf("kafka: topic must be provided (kafka.topic or msg.Topic)")
	}

	// go-queue/kq 当前的 Push API 以 string 作为消息体
	return p.pusher.Push(string(msg.Value))
}

func (p *producer) Close() error {
	if p == nil || p.pusher == nil {
		return nil
	}
	p.pusher.Close()
	return nil
}
