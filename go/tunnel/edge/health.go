package edge

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/saichler/l8tunnel/go/types/tun"
)

// loop runs the pool's health checks and DNS refreshes until it stops.
func (p *pool) loop() {
	every := time.Duration(p.fwd.HealthInterval) * time.Second
	if every <= 0 {
		every = defaultHealthEvery
	}
	check := time.NewTicker(every)
	dns := time.NewTicker(dnsRefresh)
	defer check.Stop()
	defer dns.Stop()
	p.checkAll()
	for {
		select {
		case <-p.done:
			return
		case <-check.C:
			p.checkAll()
		case <-dns.C:
			if p.fwd.TargetKind == tun.EdgeTargetKind_EDGE_TARGET_KIND_DNS {
				p.mu.Lock()
				p.members = p.resolveMembers(p.members)
				p.mu.Unlock()
			}
		}
	}
}

// checkAll checks every enabled member (none when checks are off: then
// only failed dials mark members down).
func (p *pool) checkAll() {
	switch p.fwd.HealthType {
	case tun.EdgeHealthType_EDGE_HEALTH_TYPE_UNSPECIFIED, tun.EdgeHealthType_EDGE_HEALTH_TYPE_NONE:
		for _, m := range p.snapshot() {
			if !m.healthy.Load() && time.Since(m.lastCheckTime()) > defaultHealthEvery {
				m.passed() // passive only: give a failed member another chance
			}
		}
		return
	}
	for _, m := range p.snapshot() {
		if m.disabled {
			continue
		}
		if err := p.check(m); err != nil {
			m.failed(err.Error())
		} else {
			m.passed()
		}
	}
}

func (m *member) lastCheckTime() time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastCheck
}

func (p *pool) check(m *member) error {
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	switch p.fwd.HealthType {
	case tun.EdgeHealthType_EDGE_HEALTH_TYPE_HTTP, tun.EdgeHealthType_EDGE_HEALTH_TYPE_HTTPS:
		scheme := "http"
		if p.fwd.HealthType == tun.EdgeHealthType_EDGE_HEALTH_TYPE_HTTPS {
			scheme = "https"
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+m.addr+p.fwd.HealthPath, nil)
		if err != nil {
			return err
		}
		client := &http.Client{Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: p.fwd.SkipVerify, ServerName: m.host},
		}}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		resp.Body.Close()
		if resp.StatusCode >= 500 {
			return fmt.Errorf("health check answered %d", resp.StatusCode)
		}
		return nil
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", m.addr)
	if err != nil {
		return err
	}
	return conn.Close()
}
