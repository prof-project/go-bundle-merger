package bundlemerger

import (
	"sync"
	"time"

	relay_grpc "github.com/bloXroute-Labs/relay-grpc"
)

type EnrichedPayload struct {
	UUID              string
	Payload           *relay_grpc.ExecutionPayloadAndBlobsBundle
	ReceivedAt        time.Time
	MarkedForDeletion bool
}

type EnrichedPayloadPool struct {
	payloads        map[string]*EnrichedPayload
	mu              sync.RWMutex
	cleanupInterval time.Duration
}

func NewEnrichedPayloadPool(cleanupInterval time.Duration) *EnrichedPayloadPool {
	pool := &EnrichedPayloadPool{
		payloads:        make(map[string]*EnrichedPayload),
		cleanupInterval: cleanupInterval,
	}
	go pool.startCleanupJob()
	return pool
}

func (p *EnrichedPayloadPool) Add(payload *EnrichedPayload) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.payloads[payload.UUID] = payload
}

func (p *EnrichedPayloadPool) Get(uuid string) (*EnrichedPayload, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	payload, exists := p.payloads[uuid]
	if !exists || payload.MarkedForDeletion {
		return nil, false
	}
	return payload, true
}

func (p *EnrichedPayloadPool) MarkForDeletion(uuid string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if payload, exists := p.payloads[uuid]; exists {
		payload.MarkedForDeletion = true
	}
}

func (p *EnrichedPayloadPool) startCleanupJob() {
	ticker := time.NewTicker(p.cleanupInterval)
	defer ticker.Stop()
	for range ticker.C {
		p.cleanup()
	}
}

func (p *EnrichedPayloadPool) cleanup() {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	for hash, payload := range p.payloads {
		if payload.MarkedForDeletion || now.Sub(payload.ReceivedAt) > p.cleanupInterval {
			delete(p.payloads, hash)
		}
	}
}
