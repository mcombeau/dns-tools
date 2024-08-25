package dns

import (
	"time"
)

// Name server caching

type CachedServer struct {
	Server    Server
	ExpiresAt time.Time
}

func (resolver *Resolver) cacheNameserver(server Server, ttl time.Duration) {
	resolver.CacheMutex.Lock()
	defer resolver.CacheMutex.Unlock()

	resolver.NameServerCache[server.Fqdn] = CachedServer{
		Server:    server,
		ExpiresAt: time.Now().Add(ttl),
	}
}

func (resolver *Resolver) getCachedNameServer(fqdn string) (server Server, success bool) {
	resolver.CacheMutex.RLock()

	cached, found := resolver.NameServerCache[fqdn]
	if found && !time.Now().After(cached.ExpiresAt) {
		resolver.CacheMutex.RUnlock()
		return cached.Server, true
	}

	// Cache miss or expired: upgrade to a write lock
	resolver.CacheMutex.RUnlock()
	resolver.CacheMutex.Lock()
	defer resolver.CacheMutex.Unlock()

	// Double-check the cache in case another goroutine updated it after we released the read lock
	cached, found = resolver.NameServerCache[fqdn]
	if found && !time.Now().After(cached.ExpiresAt) {
		return cached.Server, true
	}

	// Cache miss or expired: remove from cache and return false
	delete(resolver.NameServerCache, fqdn)
	return Server{}, false
}

// Answer caching

type CachedAnswer struct {
	Answers []CachedResourceRecord
}

type CachedResourceRecord struct {
	Record    ResourceRecord
	ExpiresAt time.Time
}

func (resolver *Resolver) cacheAnswerRecord(fqdn string, answer ResourceRecord) {
	resolver.CacheMutex.Lock()
	defer resolver.CacheMutex.Unlock()

	cachedRecord := CachedResourceRecord{
		Record:    answer,
		ExpiresAt: time.Now().Add(time.Duration(answer.TTL) * time.Second),
	}

	// Check if the answer is already cached
	if cached, found := resolver.AnswerCache[fqdn]; found {
		// Append the new answer to the existing slice
		cached.Answers = append(cached.Answers, cachedRecord)
		resolver.AnswerCache[fqdn] = cached
	} else {
		// Create a new cache entry
		resolver.AnswerCache[fqdn] = CachedAnswer{
			Answers: []CachedResourceRecord{cachedRecord},
		}
	}
}

// Retrieves all valid cached answer records for a given FQDN.
func (resolver *Resolver) getCachedAnswerRecords(fqdn string) (records []ResourceRecord, success bool) {
	resolver.CacheMutex.Lock()
	defer resolver.CacheMutex.Unlock()

	cached, found := resolver.AnswerCache[fqdn]
	if !found {
		return nil, false
	}

	var updatedRecords []CachedResourceRecord

	for _, cachedRecord := range cached.Answers {
		if time.Now().Before(cachedRecord.ExpiresAt) {
			updatedRecords = append(updatedRecords, cachedRecord)
			records = append(records, cachedRecord.Record)
		}
	}

	if len(updatedRecords) > 0 {
		// Update the cache with only valid records
		resolver.AnswerCache[fqdn] = CachedAnswer{Answers: updatedRecords}
		return records, true
	}

	// All records expired; remove the cache entry
	delete(resolver.AnswerCache, fqdn)
	return nil, false
}
