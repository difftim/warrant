package authz

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

type cacheEntry struct {
	spec      *ObjectTypeSpec
	expiresAt time.Time
}

type objectTypeCache struct {
	mu      sync.RWMutex
	entries map[string]*cacheEntry
	ttl     time.Duration
}

func newObjectTypeCache(ttl time.Duration) *objectTypeCache {
	return &objectTypeCache{
		entries: make(map[string]*cacheEntry),
		ttl:     ttl,
	}
}

func cacheKey(orgId string, typeId string) string {
	return fmt.Sprintf("%s:%s", orgId, typeId)
}

func (c *objectTypeCache) Get(orgId string, typeId string) (*ObjectTypeSpec, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[cacheKey(orgId, typeId)]
	if !ok || time.Now().After(entry.expiresAt) {
		return nil, false
	}

	return entry.spec, true
}

func (c *objectTypeCache) Set(orgId string, typeId string, spec *ObjectTypeSpec) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[cacheKey(orgId, typeId)] = &cacheEntry{
		spec:      spec,
		expiresAt: time.Now().Add(c.ttl),
	}
}

// InvalidateByTypeId removes all cache entries matching the given typeId across all orgs.
func (c *objectTypeCache) InvalidateByTypeId(typeId string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	suffix := ":" + typeId
	for key := range c.entries {
		if strings.HasSuffix(key, suffix) {
			delete(c.entries, key)
		}
	}
}

func (c *objectTypeCache) Flush() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	count := len(c.entries)
	c.entries = make(map[string]*cacheEntry)
	log.Info().Msgf("objecttype cache flushed, %d entries cleared", count)
	return count
}

func (c *objectTypeCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return len(c.entries)
}
