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

package main

import (
	"context"
	"fmt"
	"net/http"
	"time"

	grpcClients "github.com/warrant-dev/warrant/pkg/grpc/client"

	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	check "github.com/warrant-dev/warrant/pkg/authz/check"
	objecttype "github.com/warrant-dev/warrant/pkg/authz/objecttype"
	query "github.com/warrant-dev/warrant/pkg/authz/query"
	warrant "github.com/warrant-dev/warrant/pkg/authz/warrant"
	"github.com/warrant-dev/warrant/pkg/cache"
	"github.com/warrant-dev/warrant/pkg/config"
	"github.com/warrant-dev/warrant/pkg/database"
	kafkaproducer "github.com/warrant-dev/warrant/pkg/messaging/kafka"
	object "github.com/warrant-dev/warrant/pkg/object"
	feature "github.com/warrant-dev/warrant/pkg/object/feature"
	permission "github.com/warrant-dev/warrant/pkg/object/permission"
	pricingtier "github.com/warrant-dev/warrant/pkg/object/pricingtier"
	role "github.com/warrant-dev/warrant/pkg/object/role"
	tenant "github.com/warrant-dev/warrant/pkg/object/tenant"
	user "github.com/warrant-dev/warrant/pkg/object/user"
	"github.com/warrant-dev/warrant/pkg/service"
)

const (
	MySQLDatastoreMigrationVersion    = 000006
	PostgresDatastoreMigrationVersion = 000007
	SQLiteDatastoreMigrationVersion   = 000006
)

type ServiceEnv struct {
	Datastore database.Database
}

func (env *ServiceEnv) DB() database.Database {
	return env.Datastore
}

func (env *ServiceEnv) InitDB(cfg config.Config) error {
	ctx, cancelFunc := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelFunc()

	if cfg.GetDatastore().GetMySQL().Hostname != "" || cfg.GetDatastore().GetMySQL().DSN != "" {
		db := database.NewMySQL(*cfg.GetDatastore().GetMySQL())
		err := db.Connect(ctx)
		if err != nil {
			return err
		}

		if cfg.GetAutoMigrate() {
			err = db.Migrate(ctx, MySQLDatastoreMigrationVersion)
			if err != nil {
				return err
			}
		}

		env.Datastore = db
		return nil
	}

	if cfg.GetDatastore().GetPostgres().Hostname != "" || cfg.GetDatastore().GetPostgres().DSN != "" {
		db := database.NewPostgres(*cfg.GetDatastore().GetPostgres())
		err := db.Connect(ctx)
		if err != nil {
			return err
		}

		if cfg.GetAutoMigrate() {
			err = db.Migrate(ctx, PostgresDatastoreMigrationVersion)
			if err != nil {
				return err
			}
		}

		env.Datastore = db
		return nil
	}

	if cfg.GetDatastore().GetSQLite().Database != "" {
		db := database.NewSQLite(*cfg.GetDatastore().GetSQLite())
		err := db.Connect(ctx)
		if err != nil {
			return err
		}

		if cfg.GetAutoMigrate() {
			err = db.Migrate(ctx, SQLiteDatastoreMigrationVersion)
			if err != nil {
				return err
			}
		}

		env.Datastore = db
		return nil
	}

	return errors.New("invalid database configuration provided")
}

func NewServiceEnv() *ServiceEnv {
	return &ServiceEnv{
		Datastore: nil,
	}
}

func main() {
	cfg := config.NewConfig()
	svcEnv := NewServiceEnv()
	err := svcEnv.InitDB(cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("init: could not initialize and connect to the configured datastore. Shutting down.")
	}

	// init kafka producer (optional)
	if kafkaCfg := cfg.GetKafka(); kafkaCfg != nil && kafkaCfg.Enabled {
		if err := kafkaproducer.Init(kafkaCfg); err != nil {
			log.Fatal().Err(err).Msg("init: could not initialize kafka producer. Shutting down.")
		}
		log.Info().Msg("init: kafka producer initialized")
	} else {
		log.Info().Msg("init: kafka producer disabled")
	}

	// init grpc clients
	grpcClients.Start(cfg)

	// init authz read cache (optional, off by default).
	// 缓存配置统一放在主配置 warrant.yaml 的 cache 段。
	var cacheCfg cache.Config
	if c := cfg.Cache; c != nil {
		cacheCfg = cache.Config{
			Enabled:      c.Enabled,
			Address:      c.Address,
			Cluster:      c.Cluster,
			Username:     c.Username,
			Password:     c.Password,
			DB:           c.DB,
			PoolSize:     c.PoolSize,
			DialTimeout:  c.DialTimeout,
			ReadTimeout:  c.ReadTimeout,
			WriteTimeout: c.WriteTimeout,
			DataTTL:      c.DataTTL,
			VersionTTL:   c.VersionTTL,
			KeyPrefix:    c.KeyPrefix,
		}
	}
	authzCache, err := cache.New(cacheCfg)
	if err != nil {
		log.Fatal().Err(err).Msg("init: could not initialize authz cache. Shutting down.")
	}
	if authzCache.Enabled() {
		log.Info().Msg("init: authz read cache enabled")
	} else {
		log.Info().Msg("init: authz read cache disabled")
	}

	// Init object type repo and service (wrapped with read cache + write invalidation)
	objectTypeRepository, err := objecttype.NewRepository(svcEnv.DB())
	if err != nil {
		log.Fatal().Err(err).Msg("init: could not initialize ObjectTypeRepository")
	}
	objectTypeSvc := objecttype.NewCachedService(objecttype.NewService(svcEnv, objectTypeRepository), authzCache)

	// Init object repo and service
	objectRepository, err := object.NewRepository(svcEnv.DB())
	if err != nil {
		log.Fatal().Err(err).Msg("init: could not initialize ObjectRepository")
	}
	objectSvc := object.NewService(svcEnv, objectRepository)

	// Init warrant repo and service (wrapped with read cache + write invalidation)
	warrantRepository, err := warrant.NewRepository(svcEnv.DB())
	if err != nil {
		log.Fatal().Err(err).Msg("init: could not initialize WarrantRepository")
	}
	warrantSvc := warrant.NewCachedService(warrant.NewService(svcEnv, warrantRepository, objectTypeSvc, objectSvc), authzCache)

	// Wrap object service so that object deletes (which cascade-delete warrants)
	// invalidate the warrant cache.
	cachedObjectSvc := object.NewCachedService(objectSvc, warrantSvc)

	// Init check service
	checkSvc := check.NewService(svcEnv, warrantSvc, objectTypeSvc, cfg.Check, nil)

	// Init query service
	querySvc := query.NewService(svcEnv, objectTypeSvc, warrantSvc, cachedObjectSvc, authzCache)

	// Init feature service
	featureSvc := feature.NewService(svcEnv, cachedObjectSvc)

	// Init permission service
	permissionSvc := permission.NewService(svcEnv, cachedObjectSvc)

	// Init pricing tier service
	pricingTierSvc := pricingtier.NewService(svcEnv, cachedObjectSvc)

	// Init role service
	roleSvc := role.NewService(svcEnv, cachedObjectSvc)

	// Init tenant service
	tenantSvc := tenant.NewService(svcEnv, cachedObjectSvc)

	// Init user service
	userSvc := user.NewService(svcEnv, cachedObjectSvc)

	svcs := []service.Service{
		checkSvc,
		featureSvc,
		cachedObjectSvc,
		objectTypeSvc,
		permissionSvc,
		pricingTierSvc,
		querySvc,
		roleSvc,
		tenantSvc,
		userSvc,
		warrantSvc,
	}

	routes := make([]service.Route, 0)
	for _, svc := range svcs {
		svcRoutes, err := svc.Routes()
		if err != nil {
			log.Fatal().Err(err).Msg("init: could not setup routes for service")
		}

		routes = append(routes, svcRoutes...)
	}

	router, err := service.NewRouter(cfg, "", routes, service.ApiKeyAuthMiddleware, []service.Middleware{}, []service.Middleware{})
	if err != nil {
		log.Fatal().Err(err).Msg("init: could not initialize service router")
	}

	log.Info().Msgf("init: listening on port %d", cfg.GetPort())
	shutdownErr := http.ListenAndServe(fmt.Sprintf(":%d", cfg.GetPort()), router)
	log.Fatal().Err(shutdownErr).Msg("shutdown")
}
