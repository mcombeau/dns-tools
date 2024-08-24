package dns

import (
	"time"
)

type CachedServer struct {
	Server    Server
	ExpiresAt time.Time
}

func (resolver *Resolver) cacheNameserver(server Server, ttl time.Duration) {
	resolver.cacheMutex.Lock()
	defer resolver.cacheMutex.Unlock()

	resolver.NameServerCache[server.Fqdn] = CachedServer{
		Server:    server,
		ExpiresAt: time.Now().Add(ttl),
	}
}

func (resolver *Resolver) getCachedNameServer(fqdn string) (server Server, success bool) {
	resolver.cacheMutex.RLock()

	cached, found := resolver.NameServerCache[fqdn]
	if found && !time.Now().After(cached.ExpiresAt) {
		resolver.cacheMutex.RUnlock()
		return cached.Server, true
	}

	// Cache miss or expired: upgrade to a write lock
	resolver.cacheMutex.RUnlock()
	resolver.cacheMutex.Lock()
	defer resolver.cacheMutex.Unlock()

	// Double-check the cache in case another goroutine updated it after we released the read lock
	cached, found = resolver.NameServerCache[fqdn]
	if found && !time.Now().After(cached.ExpiresAt) {
		return cached.Server, true
	}

	// Cache miss or expired: remove from cache and return false
	delete(resolver.NameServerCache, fqdn)
	return Server{}, false
}
