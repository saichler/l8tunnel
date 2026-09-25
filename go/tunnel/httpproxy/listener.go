package httpproxy

import (
	"net"
	"sync"
)

// connListener feeds connections handed to ServeConn to http.Server.
type connListener struct {
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
}

func newConnListener() *connListener {
	return &connListener{conns: make(chan net.Conn), done: make(chan struct{})}
}

func (l *connListener) push(conn net.Conn) {
	select {
	case l.conns <- conn:
	case <-l.done:
		conn.Close()
	}
}

func (l *connListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conns:
		return conn, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *connListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *connListener) Addr() net.Addr {
	return &net.TCPAddr{}
}
