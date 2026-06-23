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

// Package cache 提供一个基于 Redis 的通用缓存原语，供授权读路径使用。
//
// 一致性模型（重点）：
//   - 缓存值的 key 中嵌入"版本号"（epoch / bucket version）。
//   - 任何写操作只需对相关计数器执行 INCR，旧版本对应的 data key 立即变为
//     不可达的"孤儿"，从而：
//     1) 失效与写提交同步（写服务在事务提交后、返回前同步 INCR）；
//     2) 天然化解 cache-aside 回填竞态——慢读把旧值回填到旧版本 key 上，
//        但后续读使用新版本号，永远读不到这个孤儿，因此不会出现"撤销后仍读到旧授权"。
//   - 跨 Redis/DB 两套系统无法做到绝对原子，仅在"提交完成到 INCR 完成"这段
//     亚毫秒窗口内，对那些与本次写无因果关系的并发读可能短暂命中旧值；对已知
//     本次写结果的调用方（read-your-writes）严格一致。这是不依赖 2PC 时可达到
//     的最强实际保证。
//
// 任何 Redis 错误都不会影响业务正确性：调用方在缓存不可用时回退直查 DB。
package cache

import (
	"context"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"
)

type readThroughCtxKey struct{}

// WithReadThrough 标记该 context 上的读操作允许走缓存。
// 仅授权检查（Check）路径会设置此标记；管理类 List/Get（需要游标、事务内读最新值）
// 不设置，从而自动绕过缓存、直查 DB。
func WithReadThrough(ctx context.Context) context.Context {
	return context.WithValue(ctx, readThroughCtxKey{}, true)
}

// IsReadThrough 返回该 context 是否允许走缓存。
func IsReadThrough(ctx context.Context) bool {
	v, ok := ctx.Value(readThroughCtxKey{}).(bool)
	return ok && v
}

// Config 描述缓存的 Redis 连接与 TTL 配置。
// 字段带 mapstructure tag，供 LoadConfig 从独立配置文件（cache.yaml）反序列化。
type Config struct {
	Enabled      bool          `mapstructure:"enabled"`
	Address      string        `mapstructure:"address"`
	Username     string        `mapstructure:"username"`
	Password     string        `mapstructure:"password"`
	DB           int           `mapstructure:"db"`
	PoolSize     int           `mapstructure:"poolSize"`
	DialTimeout  time.Duration `mapstructure:"dialTimeout"`
	ReadTimeout  time.Duration `mapstructure:"readTimeout"`
	WriteTimeout time.Duration `mapstructure:"writeTimeout"`
	// DataTTL 是缓存数据 key 的兜底过期时间（仅用于淘汰孤儿，不承担一致性）。
	DataTTL time.Duration `mapstructure:"dataTtl"`
	// VersionTTL 是版本计数器 key 的过期时间，必须远大于 DataTTL，
	// 以避免版本号过期后被复用、与仍在 TTL 内的旧 data key 撞号。
	VersionTTL time.Duration `mapstructure:"versionTtl"`
	// KeyPrefix 是所有缓存 key 的统一业务前缀（共享 Redis 命名空间隔离 / ACL / 运维清理）。
	KeyPrefix string `mapstructure:"keyPrefix"`
}

// Cache 是对 Redis 的轻量封装，所有方法在未启用或底层报错时安全降级。
type Cache struct {
	rdb        *redis.Client
	enabled    bool
	dataTTL    time.Duration
	versionTTL time.Duration
	keyPrefix  string
}

// New 根据配置建立 Redis 连接。enabled=false 时返回一个永远降级的 Cache。
func New(cfg Config) (*Cache, error) {
	if !cfg.Enabled {
		return &Cache{enabled: false}, nil
	}

	dataTTL := cfg.DataTTL
	if dataTTL <= 0 {
		dataTTL = 10 * time.Minute
	}
	versionTTL := cfg.VersionTTL
	if versionTTL <= 0 {
		versionTTL = 24 * time.Hour
	}
	keyPrefix := cfg.KeyPrefix
	if keyPrefix == "" {
		keyPrefix = DefaultKeyPrefix
	}

	rdb := redis.NewClient(&redis.Options{
		Addr:         cfg.Address,
		Username:     cfg.Username,
		Password:     cfg.Password,
		DB:           cfg.DB,
		PoolSize:     cfg.PoolSize,
		DialTimeout:  cfg.DialTimeout,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, err
	}

	return &Cache{
		rdb:        rdb,
		enabled:    true,
		dataTTL:    dataTTL,
		versionTTL: versionTTL,
		keyPrefix:  keyPrefix,
	}, nil
}

// Enabled 返回缓存是否可用。
func (c *Cache) Enabled() bool {
	return c != nil && c.enabled
}

// Prefix 返回缓存 key 的统一业务前缀。即使在降级（未启用）实例上也返回默认前缀，
// 便于调用方在构造 key 时无条件使用。
func (c *Cache) Prefix() string {
	if c == nil || c.keyPrefix == "" {
		return DefaultKeyPrefix
	}
	return c.keyPrefix
}

// GetCounters 一次性读取多个版本计数器（epoch / bucket version）。
// 不存在的 key 记为 0。任何错误返回 ok=false，调用方据此回退直查 DB。
func (c *Cache) GetCounters(ctx context.Context, keys ...string) (values []int64, ok bool) {
	if !c.Enabled() || len(keys) == 0 {
		return nil, false
	}

	res, err := c.rdb.MGet(ctx, keys...).Result()
	if err != nil {
		log.Ctx(ctx).Warn().Err(err).Strs("keys", keys).Msg("cache: GetCounters MGet failed, falling back to DB")
		return nil, false
	}

	values = make([]int64, len(res))
	for i, v := range res {
		values[i] = toInt64(v)
	}
	log.Ctx(ctx).Debug().Strs("keys", keys).Ints64("values", values).Msg("cache: GetCounters ok")
	return values, true
}

// GetBytes 批量读取多个 data key，返回与 keys 等长的结果；未命中项为 nil。
// 任何错误返回 ok=false。
func (c *Cache) GetBytes(ctx context.Context, keys ...string) (values [][]byte, ok bool) {
	if !c.Enabled() || len(keys) == 0 {
		return nil, false
	}

	res, err := c.rdb.MGet(ctx, keys...).Result()
	if err != nil {
		log.Ctx(ctx).Warn().Err(err).Strs("keys", keys).Msg("cache: GetBytes MGet failed, falling back to DB")
		return nil, false
	}

	values = make([][]byte, len(res))
	hits := 0
	for i, v := range res {
		switch val := v.(type) {
		case string:
			values[i] = []byte(val)
			hits++
		case []byte:
			values[i] = val
			hits++
		default:
			values[i] = nil
		}
	}
	log.Ctx(ctx).Debug().Strs("keys", keys).Int("hits", hits).Int("total", len(keys)).Msg("cache: GetBytes ok")
	return values, true
}

// SetBytes 写入一个 data key，带 DataTTL 兜底过期。错误仅记录不阻断。
func (c *Cache) SetBytes(ctx context.Context, key string, val []byte) {
	if !c.Enabled() {
		return
	}
	if err := c.rdb.Set(ctx, key, val, c.dataTTL).Err(); err != nil {
		log.Ctx(ctx).Warn().Err(err).Str("key", key).Int("bytes", len(val)).Msg("cache: SetBytes failed")
		return
	}
	log.Ctx(ctx).Debug().Str("key", key).Int("bytes", len(val)).Dur("ttl", c.dataTTL).Msg("cache: SetBytes ok (bucket refilled)")
}

// Incr 对版本计数器 +1 并刷新其 TTL。这是失效的唯一手段：旧版本 data key 随之变为孤儿。
// 错误会被记录；调用方（写路径）应在缓存失效失败时依赖 DataTTL 兜底收敛。
func (c *Cache) Incr(ctx context.Context, key string) error {
	if !c.Enabled() {
		return nil
	}
	pipe := c.rdb.TxPipeline()
	incr := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, c.versionTTL)
	if _, err := pipe.Exec(ctx); err != nil {
		log.Ctx(ctx).Error().Err(err).Str("key", key).Msg("cache: Incr failed, cache may briefly serve stale until DataTTL")
		return err
	}
	log.Ctx(ctx).Info().Str("key", key).Int64("newVersion", incr.Val()).Msg("cache: invalidate ok (counter incremented)")
	return nil
}

func toInt64(v interface{}) int64 {
	switch val := v.(type) {
	case nil:
		return 0
	case int64:
		return val
	case string:
		n, err := strconv.ParseInt(val, 10, 64)
		if err != nil {
			return 0
		}
		return n
	default:
		return 0
	}
}
