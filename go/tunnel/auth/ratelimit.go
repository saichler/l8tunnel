package auth

import (
	"net/netip"
	"sync"
	"time"
)

// IPLimiter is a token bucket per client IP.
type IPLimiter struct {
	mu        sync.Mutex
	rate      float64 // tokens added per second
	burst     float64
	buckets   map[netip.Addr]*bucket
	lastSweep time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

// NewIPLimiter allows each IP perSecond events on average, with bursts of
// up to burst.
func NewIPLimiter(perSecond float64, burst int) *IPLimiter {
	return &IPLimiter{rate: perSecond, burst: float64(burst), buckets: map[netip.Addr]*bucket{}, lastSweep: time.Now()}
}

// Allow takes one token for ip, reporting whether one was available.
func (l *IPLimiter) Allow(ip netip.Addr) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.refill(ip.Unmap(), time.Now())
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Exhausted reports whether ip has no tokens left, without taking one.
func (l *IPLimiter) Exhausted(ip netip.Addr) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.refill(ip.Unmap(), time.Now()).tokens < 1
}

func (l *IPLimiter) refill(ip netip.Addr, now time.Time) *bucket {
	if now.Sub(l.lastSweep) > time.Minute {
		l.sweep(now)
	}
	b := l.buckets[ip]
	if b == nil {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[ip] = b
		return b
	}
	b.tokens += now.Sub(b.last).Seconds() * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	return b
}

// sweep drops buckets that have refilled completely; they carry no state.
func (l *IPLimiter) sweep(now time.Time) {
	for ip, b := range l.buckets {
		if b.tokens+now.Sub(b.last).Seconds()*l.rate >= l.burst {
			delete(l.buckets, ip)
		}
	}
	l.lastSweep = now
}
