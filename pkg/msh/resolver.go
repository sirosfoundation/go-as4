package msh

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	// ErrEndpointNotFound is returned when no endpoint can be resolved
	ErrEndpointNotFound = errors.New("endpoint not found")
	// ErrInvalidPartyID is returned for invalid party identifiers
	ErrInvalidPartyID = errors.New("invalid party ID")
)

// EndpointResolver resolves party IDs to endpoint information
// This interface supports both static point-to-point configurations
// and dynamic discovery mechanisms (e.g., SMP/SML, OASIS BDXL)
type EndpointResolver interface {
	// ResolveEndpoint resolves a party ID to endpoint information
	ResolveEndpoint(ctx context.Context, partyID, service, action string) (*EndpointInfo, error)

	// CacheEndpoint caches endpoint information for faster lookups
	CacheEndpoint(partyID string, info *EndpointInfo) error

	// InvalidateCache removes cached endpoint information
	InvalidateCache(partyID string) error
}

// StaticEndpointResolver implements a simple static configuration resolver
// Suitable for point-to-point deployments with fixed endpoints
type StaticEndpointResolver struct {
	mu        sync.RWMutex
	endpoints map[string]*EndpointInfo
}

// NewStaticEndpointResolver creates a new static resolver
func NewStaticEndpointResolver() *StaticEndpointResolver {
	return &StaticEndpointResolver{
		endpoints: make(map[string]*EndpointInfo),
	}
}

// RegisterEndpoint registers a static endpoint mapping
func (r *StaticEndpointResolver) RegisterEndpoint(partyID string, info *EndpointInfo) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.endpoints[partyID] = info
}

// ResolveEndpoint implements EndpointResolver
func (r *StaticEndpointResolver) ResolveEndpoint(ctx context.Context, partyID, service, action string) (*EndpointInfo, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	info, ok := r.endpoints[partyID]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrEndpointNotFound, partyID)
	}

	return info, nil
}

// CacheEndpoint implements EndpointResolver (for static resolver, this is the same as RegisterEndpoint)
func (r *StaticEndpointResolver) CacheEndpoint(partyID string, info *EndpointInfo) error {
	r.RegisterEndpoint(partyID, info)
	return nil
}

// InvalidateCache implements EndpointResolver
func (r *StaticEndpointResolver) InvalidateCache(partyID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.endpoints, partyID)
	return nil
}

// DynamicEndpointResolver implements dynamic endpoint discovery
// Suitable for four-corner model deployments using SMP/SML or BDXL
type DynamicEndpointResolver struct {
	mu         sync.RWMutex
	cache      map[string]*cachedEndpoint
	lookupFunc EndpointLookupFunc
	cacheTTL   int64 // seconds
}

// cachedEndpoint wraps endpoint info with cache expiry
type cachedEndpoint struct {
	Info      *EndpointInfo
	ExpiresAt int64 // Unix timestamp
}

// EndpointLookupFunc is a function that performs actual endpoint lookup
// This can be customized to query SMP, SML, BDXL, or other directory services
type EndpointLookupFunc func(ctx context.Context, partyID, service, action string) (*EndpointInfo, error)

// NewDynamicEndpointResolver creates a resolver with dynamic lookup capability
func NewDynamicEndpointResolver(lookupFunc EndpointLookupFunc, cacheTTLSeconds int64) *DynamicEndpointResolver {
	return &DynamicEndpointResolver{
		cache:      make(map[string]*cachedEndpoint),
		lookupFunc: lookupFunc,
		cacheTTL:   cacheTTLSeconds,
	}
}

// ResolveEndpoint implements EndpointResolver with caching
func (r *DynamicEndpointResolver) ResolveEndpoint(ctx context.Context, partyID, service, action string) (*EndpointInfo, error) {
	// Check cache first
	cacheKey := fmt.Sprintf("%s:%s:%s", partyID, service, action)

	r.mu.RLock()
	cached, ok := r.cache[cacheKey]
	r.mu.RUnlock()

	if ok && cached.ExpiresAt > currentTimestamp() {
		return cached.Info, nil
	}

	// Cache miss or expired - perform lookup
	if r.lookupFunc == nil {
		return nil, fmt.Errorf("%w: no lookup function configured", ErrEndpointNotFound)
	}

	info, err := r.lookupFunc(ctx, partyID, service, action)
	if err != nil {
		return nil, err
	}

	// Cache the result
	r.CacheEndpoint(cacheKey, info)

	return info, nil
}

// CacheEndpoint implements EndpointResolver
func (r *DynamicEndpointResolver) CacheEndpoint(key string, info *EndpointInfo) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.cache[key] = &cachedEndpoint{
		Info:      info,
		ExpiresAt: currentTimestamp() + r.cacheTTL,
	}

	return nil
}

// InvalidateCache implements EndpointResolver
func (r *DynamicEndpointResolver) InvalidateCache(key string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.cache, key)
	return nil
}

// currentTimestamp returns the current Unix timestamp
func currentTimestamp() int64 {
	return time.Now().Unix()
}

// MultiResolverEndpointResolver tries multiple resolvers in order
// Useful for hybrid configurations (check static first, then dynamic)
type MultiResolverEndpointResolver struct {
	resolvers []EndpointResolver
}

// NewMultiResolver creates a resolver that tries multiple resolvers in order
func NewMultiResolver(resolvers ...EndpointResolver) *MultiResolverEndpointResolver {
	return &MultiResolverEndpointResolver{
		resolvers: resolvers,
	}
}

// ResolveEndpoint implements EndpointResolver by trying each resolver in order
func (r *MultiResolverEndpointResolver) ResolveEndpoint(ctx context.Context, partyID, service, action string) (*EndpointInfo, error) {
	for _, resolver := range r.resolvers {
		info, err := resolver.ResolveEndpoint(ctx, partyID, service, action)
		if err == nil {
			return info, nil
		}
		// Continue to next resolver if this one failed
	}

	return nil, fmt.Errorf("%w: %s (tried %d resolvers)", ErrEndpointNotFound, partyID, len(r.resolvers))
}

// CacheEndpoint implements EndpointResolver by caching in the first resolver
func (r *MultiResolverEndpointResolver) CacheEndpoint(partyID string, info *EndpointInfo) error {
	if len(r.resolvers) == 0 {
		return errors.New("no resolvers configured")
	}
	return r.resolvers[0].CacheEndpoint(partyID, info)
}

// InvalidateCache implements EndpointResolver by invalidating in all resolvers
func (r *MultiResolverEndpointResolver) InvalidateCache(partyID string) error {
	for _, resolver := range r.resolvers {
		resolver.InvalidateCache(partyID)
	}
	return nil
}
