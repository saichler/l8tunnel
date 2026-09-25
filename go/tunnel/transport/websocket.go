package transport

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// WebSocketPath is where the relay accepts agent sessions over WebSocket.
const WebSocketPath = "/l8tunnel/ws"

// Transports.
const (
	TransportTLS       = "tls" // raw TLS with the l8tunnel ALPN (default)
	TransportWebSocket = "wss" // WebSocket over TLS, for HTTP-only networks
)

// DialRelayWebSocket opens an agent session over wss://<server-name><path>
// through addr, for networks that only let HTTP(S) out. It returns a
// connection carrying the same byte stream as DialRelay.
func DialRelayWebSocket(ctx context.Context, addr string, cfg *tls.Config, opts DialOptions) (net.Conn, error) {
	raw, err := opts.dialTCP(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("dial relay %s: %w", addr, err)
	}
	wsCfg := cfg.Clone()
	wsCfg.NextProtos = []string{"http/1.1"}
	tconn := tls.Client(raw, wsCfg)
	if err := tconn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, fmt.Errorf("dial relay %s: %w", addr, err)
	}
	// ws://, not wss://: the TLS layer is already in place (it had to go
	// through the proxy dialer), and gorilla would add a second one.
	u := url.URL{Scheme: "ws", Host: cfg.ServerName, Path: WebSocketPath}
	tconn.SetDeadline(time.Now().Add(10 * time.Second))
	ws, resp, err := websocket.NewClient(tconn, &u, http.Header{}, 32<<10, 32<<10)
	if err != nil {
		tconn.Close()
		if resp != nil {
			return nil, fmt.Errorf("relay %s refused the WebSocket upgrade: %s", addr, resp.Status)
		}
		return nil, fmt.Errorf("relay %s: WebSocket upgrade: %w", addr, err)
	}
	tconn.SetDeadline(time.Time{})
	return NewWebSocketConn(ws), nil
}

// NewWebSocketConn presents a WebSocket as a byte stream: each Write is
// one binary message, and Read concatenates incoming messages. It
// supports one concurrent reader and one concurrent writer, which is how
// yamux uses a connection.
func NewWebSocketConn(ws *websocket.Conn) net.Conn {
	return &wsConn{ws: ws}
}

type wsConn struct {
	ws     *websocket.Conn
	reader io.Reader
	wmu    sync.Mutex
}

func (c *wsConn) Read(p []byte) (int, error) {
	for {
		if c.reader == nil {
			typ, r, err := c.ws.NextReader()
			if err != nil {
				if websocket.IsCloseError(err, websocket.CloseNormalClosure) {
					return 0, io.EOF
				}
				return 0, err
			}
			if typ != websocket.BinaryMessage {
				return 0, fmt.Errorf("unexpected WebSocket message type %d", typ)
			}
			c.reader = r
		}
		n, err := c.reader.Read(p)
		if err == io.EOF {
			c.reader = nil
			if n > 0 {
				return n, nil
			}
			continue
		}
		return n, err
	}
}

func (c *wsConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if err := c.ws.WriteMessage(websocket.BinaryMessage, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *wsConn) Close() error {
	c.wmu.Lock()
	c.ws.WriteControl(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second))
	c.wmu.Unlock()
	return c.ws.Close()
}

func (c *wsConn) LocalAddr() net.Addr  { return c.ws.LocalAddr() }
func (c *wsConn) RemoteAddr() net.Addr { return c.ws.RemoteAddr() }

func (c *wsConn) SetDeadline(t time.Time) error {
	if err := c.ws.SetReadDeadline(t); err != nil {
		return err
	}
	return c.ws.SetWriteDeadline(t)
}

func (c *wsConn) SetReadDeadline(t time.Time) error  { return c.ws.SetReadDeadline(t) }
func (c *wsConn) SetWriteDeadline(t time.Time) error { return c.ws.SetWriteDeadline(t) }
