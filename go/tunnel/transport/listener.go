package transport

import (
	"net"
	"sync"
)

// ConnListener is a net.Listener fed by Push: it hands connections that
// were accepted and routed elsewhere to an http.Server.
type ConnListener struct {
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
}

// NewConnListener returns an empty ConnListener.
func NewConnListener() *ConnListener {
	return &ConnListener{conns: make(chan net.Conn), done: make(chan struct{})}
}

// Push hands conn to the listener; it is closed if the listener is.
func (l *ConnListener) Push(conn net.Conn) {
	select {
	case l.conns <- conn:
	case <-l.done:
		conn.Close()
	}
}

// Accept implements net.Listener.
func (l *ConnListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conns:
		return conn, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

// Close implements net.Listener.
func (l *ConnListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

// Addr implements net.Listener.
func (l *ConnListener) Addr() net.Addr {
	return &net.TCPAddr{}
}
