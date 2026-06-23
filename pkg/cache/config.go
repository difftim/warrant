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

package cache

import (
	"os"
	"time"

	"github.com/spf13/viper"
)

const (
	// DefaultConfigFile 是缓存模块独立配置文件的默认路径（相对工作目录）。
	DefaultConfigFile = "cache.yaml"
	// DefaultKeyPrefix 是所有缓存 key 的默认业务前缀。
	DefaultKeyPrefix = "warrant:"
	// ConfigPathEnv 可覆盖配置文件路径。
	ConfigPathEnv = "WARRANT_CACHE_CONFIG"
)

// LoadConfig 从缓存模块的独立配置文件加载配置（与主 warrant.yaml 解耦）。
//
// 行为约定：
//   - path 为空时取环境变量 WARRANT_CACHE_CONFIG，仍为空则用默认 ./cache.yaml。
//   - 文件不存在时返回 Enabled=false 的默认配置且不报错，保证未提供该文件的
//     部署行为不变（缓存默认关闭）。
//   - 文件存在但解析失败时返回错误，由调用方决定是否终止启动。
func LoadConfig(path string) (Config, error) {
	if path == "" {
		path = os.Getenv(ConfigPathEnv)
	}
	if path == "" {
		path = DefaultConfigFile
	}

	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return Config{Enabled: false, KeyPrefix: DefaultKeyPrefix}, nil
		}
		return Config{}, err
	}

	v := viper.New() // 独立 viper 实例，与主配置的全局 viper 互不干扰
	v.SetConfigFile(path)
	v.SetConfigType("yaml")
	v.SetDefault("enabled", false)
	v.SetDefault("db", 0)
	v.SetDefault("poolSize", 50)
	v.SetDefault("dialTimeout", 5*time.Second)
	v.SetDefault("readTimeout", 1*time.Second)
	v.SetDefault("writeTimeout", 1*time.Second)
	v.SetDefault("dataTtl", 10*time.Minute)
	v.SetDefault("versionTtl", 24*time.Hour)
	v.SetDefault("keyPrefix", DefaultKeyPrefix)

	if err := v.ReadInConfig(); err != nil {
		return Config{}, err
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}
