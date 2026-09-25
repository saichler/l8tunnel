// Package inspect is the agent's HTTP request inspector: it records the
// requests that reach HTTP tunnels (headers and the start of each body),
// serves a local web UI to browse them, and replays them to the local
// service.
package inspect

import (
	"net/http"
	"sync"
	"time"
)

// MaxBody is how much of each request and response body is kept.
const MaxBody = 64 << 10

// DefaultMaxEntries is how many requests are kept.
const DefaultMaxEntries = 200

// Entry is one recorded request and its response.
type Entry struct {
	ID       int64       `json:"id"`
	Time     time.Time   `json:"time"`
	Tunnel   string      `json:"tunnel"`
	Method   string      `json:"method"`
	URI      string      `json:"uri"`
	Host     string      `json:"host"`
	Proto    string      `json:"proto"`
	ReqHead  http.Header `json:"request_headers"`
	ReqBody  []byte      `json:"request_body,omitempty"`
	ReqSize  int64       `json:"request_size"`
	Status   int         `json:"status"`
	RespHead http.Header `json:"response_headers,omitempty"`
	RespBody []byte      `json:"response_body,omitempty"`
	RespSize int64       `json:"response_size"`
	Duration float64     `json:"duration_ms"`
	Error    string      `json:"error,omitempty"`
	Upgraded bool        `json:"upgraded,omitempty"`
	ReplayOf int64       `json:"replay_of,omitempty"`
}

// Summary is an Entry without headers and bodies, for lists.
type Summary struct {
	ID       int64     `json:"id"`
	Time     time.Time `json:"time"`
	Tunnel   string    `json:"tunnel"`
	Method   string    `json:"method"`
	URI      string    `json:"uri"`
	Status   int       `json:"status"`
	RespSize int64     `json:"response_size"`
	Duration float64   `json:"duration_ms"`
	Error    string    `json:"error,omitempty"`
	ReplayOf int64     `json:"replay_of,omitempty"`
}

func (e *Entry) summary() Summary {
	return Summary{ID: e.ID, Time: e.Time, Tunnel: e.Tunnel, Method: e.Method, URI: e.URI, Status: e.Status,
		RespSize: e.RespSize, Duration: e.Duration, Error: e.Error, ReplayOf: e.ReplayOf}
}

// Recorder keeps the last entries and notifies subscribers of new ones.
type Recorder struct {
	mu      sync.Mutex
	max     int
	nextID  int64
	entries []*Entry // oldest first
	subs    map[chan Summary]struct{}
}

// NewRecorder keeps up to max entries (DefaultMaxEntries when max <= 0).
func NewRecorder(max int) *Recorder {
	if max <= 0 {
		max = DefaultMaxEntries
	}
	return &Recorder{max: max, subs: map[chan Summary]struct{}{}}
}

// add stores a finished entry, assigning its ID.
func (r *Recorder) add(e *Entry) {
	r.mu.Lock()
	r.nextID++
	e.ID = r.nextID
	r.entries = append(r.entries, e)
	if len(r.entries) > r.max {
		r.entries = r.entries[len(r.entries)-r.max:]
	}
	subs := make([]chan Summary, 0, len(r.subs))
	for ch := range r.subs {
		subs = append(subs, ch)
	}
	r.mu.Unlock()
	for _, ch := range subs {
		select {
		case ch <- e.summary():
		default: // a slow viewer misses live updates, not requests
		}
	}
}

// List returns summaries, newest first.
func (r *Recorder) List() []Summary {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Summary, 0, len(r.entries))
	for i := len(r.entries) - 1; i >= 0; i-- {
		out = append(out, r.entries[i].summary())
	}
	return out
}

// Get returns an entry by ID, or nil.
func (r *Recorder) Get(id int64) *Entry {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.entries {
		if e.ID == id {
			return e
		}
	}
	return nil
}

func (r *Recorder) subscribe() chan Summary {
	ch := make(chan Summary, 64)
	r.mu.Lock()
	r.subs[ch] = struct{}{}
	r.mu.Unlock()
	return ch
}

func (r *Recorder) unsubscribe(ch chan Summary) {
	r.mu.Lock()
	delete(r.subs, ch)
	r.mu.Unlock()
}

// capture keeps the first MaxBody bytes written to it and counts all.
type capture struct {
	buf  []byte
	size int64
}

func (c *capture) Write(p []byte) (int, error) {
	if room := MaxBody - len(c.buf); room > 0 {
		if len(p) < room {
			room = len(p)
		}
		c.buf = append(c.buf, p[:room]...)
	}
	c.size += int64(len(p))
	return len(p), nil
}

func (c *capture) complete() bool {
	return c.size == int64(len(c.buf))
}
