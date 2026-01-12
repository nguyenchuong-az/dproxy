/*
File: upstream_pool.go
Version: 1.1.0
Description: Manages TCP and DoQ connection pools for upstream exchanges.
             FIXED: "Check-then-Act" race condition in DoQ dialing that allowed session count to burst beyond limits.
             OPTIMIZED: Added dialing slot reservation to enforce strict concurrency limits.
*/

package main

import (
	"context"
	"fmt"
	"hash/maphash"
	"sync"
	"time"
	"crypto/tls"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

const (
	maxDoQSessions  = 8   // Allow up to 8 concurrent QUIC sessions per upstream
	tcpIdlePoolSize = 512 // Max idle TCP connections to hold per upstream
	poolShardCount  = 256 // Number of shards for connection pools
)

// Global seed for maphash to ensure consistent hashing per process run
var poolHasherSeed = maphash.MakeSeed()

// --- Sharded TCP/DoT Connection Pool ---

type tcpPoolShard struct {
	sync.Mutex
	conns map[string][]*dns.Conn
}

type TCPConnPool struct {
	shards [poolShardCount]*tcpPoolShard
}

var tcpPool = newTCPConnPool()

func newTCPConnPool() *TCPConnPool {
	p := &TCPConnPool{}
	for i := 0; i < poolShardCount; i++ {
		p.shards[i] = &tcpPoolShard{
			conns: make(map[string][]*dns.Conn),
		}
	}
	return p
}

func (p *TCPConnPool) getShard(key string) *tcpPoolShard {
	var h maphash.Hash
	h.SetSeed(poolHasherSeed)
	h.WriteString(key)
	return p.shards[h.Sum64()&(poolShardCount-1)]
}

func (p *TCPConnPool) Get(key string) *dns.Conn {
	shard := p.getShard(key)
	shard.Lock()
	defer shard.Unlock()

	list := shard.conns[key]
	if len(list) > 0 {
		// LIFO (Stack) to keep hot connections hot
		conn := list[len(list)-1]
		shard.conns[key] = list[:len(list)-1]
		return conn
	}
	return nil
}

func (p *TCPConnPool) Put(key string, conn *dns.Conn) {
	shard := p.getShard(key)
	shard.Lock()
	defer shard.Unlock()

	if len(shard.conns[key]) >= tcpIdlePoolSize {
		conn.Close()
		return
	}
	shard.conns[key] = append(shard.conns[key], conn)
}

// --- Sharded DoQ Connection Pool ---

type doqPoolShard struct {
	sync.RWMutex
	sessions map[string][]*doqSession
	dialing  map[string]int // Track in-flight dials to prevent race condition bursting
	nextIdx  map[string]int
}

type DoQPool struct {
	shards [poolShardCount]*doqPoolShard
}

type doqSession struct {
	conn     quic.Connection
	lastUsed time.Time
	mu       sync.Mutex
}

var doqPool = newDoQPool()

func newDoQPool() *DoQPool {
	p := &DoQPool{}
	for i := 0; i < poolShardCount; i++ {
		p.shards[i] = &doqPoolShard{
			sessions: make(map[string][]*doqSession),
			dialing:  make(map[string]int),
			nextIdx:  make(map[string]int),
		}
	}
	return p
}

func (p *DoQPool) getShard(key string) *doqPoolShard {
	var h maphash.Hash
	h.SetSeed(poolHasherSeed)
	h.WriteString(key)
	return p.shards[h.Sum64()&(poolShardCount-1)]
}

func (p *DoQPool) Get(ctx context.Context, addr string, tlsConf *tls.Config) (quic.Connection, error) {
	poolKey := fmt.Sprintf("%s|%s", addr, tlsConf.ServerName)
	shard := p.getShard(poolKey)

	shard.Lock()
	// Clean closed sessions
	sessions := shard.sessions[poolKey]
	validSessions := make([]*doqSession, 0, len(sessions))
	for _, s := range sessions {
		select {
		case <-s.conn.Context().Done():
			// Closed
		default:
			validSessions = append(validSessions, s)
		}
	}
	shard.sessions[poolKey] = validSessions
	
	currentCount := len(validSessions)
	pendingDials := shard.dialing[poolKey]

	// RACE FIX: Check count AND pending dials. If under limit, reserve a slot.
	if currentCount+pendingDials < maxDoQSessions {
		shard.dialing[poolKey]++
		shard.Unlock()

		// Perform slow Dial without holding the lock
		conn, err := quic.DialAddr(ctx, addr, tlsConf, &quic.Config{
			KeepAlivePeriod:    30 * time.Second,
			MaxIdleTimeout:     60 * time.Second,
			MaxIncomingStreams: 1000,
		})

		shard.Lock()
		shard.dialing[poolKey]-- // Release reservation

		if err != nil {
			// If dial failed, we just return error. 
			// But we check if another thread succeeded while we were dialing?
			// No, simply fail this request or fallback to existing sessions below.
			if len(shard.sessions[poolKey]) > 0 {
				// Fallback to existing sessions if available despite dial error
				idx := shard.nextIdx[poolKey] % len(shard.sessions[poolKey])
				shard.nextIdx[poolKey]++
				s := shard.sessions[poolKey][idx]
				s.lastUsed = time.Now()
				shard.Unlock()
				return s.conn, nil
			}
			shard.Unlock()
			return nil, err
		}

		newSess := &doqSession{conn: conn, lastUsed: time.Now()}
		shard.sessions[poolKey] = append(shard.sessions[poolKey], newSess)
		shard.Unlock()
		return conn, nil
	}

	// Limit reached, perform Round-Robin on existing sessions
	if len(validSessions) == 0 {
		// Should rarely happen unless max sessions is 0 or all failed simultaneously
		shard.Unlock()
		return nil, fmt.Errorf("no DoQ sessions available and max limit %d reached (pending: %d)", maxDoQSessions, pendingDials)
	}

	idx := shard.nextIdx[poolKey] % len(validSessions)
	shard.nextIdx[poolKey]++
	sess := validSessions[idx]
	sess.lastUsed = time.Now()
	shard.Unlock()

	return sess.conn, nil
}

func (p *DoQPool) cleanup(ctx context.Context) {
	LogInfo("[DOQ] Starting DoQ connection pool maintenance")
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			count := 0
			for _, shard := range p.shards {
				shard.Lock()
				for _, sessions := range shard.sessions {
					for _, sess := range sessions {
						sess.conn.CloseWithError(0, "shutdown")
						count++
					}
				}
				shard.sessions = make(map[string][]*doqSession)
				shard.Unlock()
			}
			LogInfo("[DOQ] Closed %d connections on shutdown", count)
			return
		case <-ticker.C:
			closedCount := 0
			for _, shard := range p.shards {
				shard.Lock()
				for addr, sessions := range shard.sessions {
					var active []*doqSession
					for _, sess := range sessions {
						sess.mu.Lock()
						if time.Since(sess.lastUsed) > 2*time.Minute {
							sess.conn.CloseWithError(0, "idle timeout")
							closedCount++
						} else {
							active = append(active, sess)
						}
						sess.mu.Unlock()
					}
					if len(active) == 0 {
						delete(shard.sessions, addr)
						delete(shard.nextIdx, addr)
						// Also clear dialing if it's somehow stuck (safety)
						delete(shard.dialing, addr) 
					} else {
						shard.sessions[addr] = active
					}
				}
				shard.Unlock()
			}
			if closedCount > 0 {
				LogDebug("[DOQ] Cleaned up %d idle DoQ connections", closedCount)
			}
		}
	}
}

