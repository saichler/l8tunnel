// Package pipe is the single bidirectional copy used by every tunnel type.
package pipe

import (
	"io"
	"sync"
)

// Conn is a connection that can be half-closed. *net.TCPConn, *tls.Conn
// and *transport.Stream all satisfy it.
type Conn interface {
	io.ReadWriteCloser
	CloseWrite() error
}

// Result reports how a Join ended.
type Result struct {
	AtoB int64 // bytes copied from a to b
	BtoA int64 // bytes copied from b to a
	Err  error // first copy error, nil when both sides ended with EOF
}

// Join copies a->b and b->a until both directions finish, then closes both
// connections. When one side sends EOF, the other side is half-closed so
// the peer sees EOF too. When a copy fails, both connections are closed at
// once so the other direction doesn't hang.
func Join(a, b Conn) Result {
	var (
		res  Result
		wg   sync.WaitGroup
		once sync.Once
	)
	fail := func(err error) {
		once.Do(func() {
			res.Err = err
			a.Close()
			b.Close()
		})
	}
	wg.Add(2)
	go func() {
		defer wg.Done()
		res.AtoB = copyHalf(b, a, fail)
	}()
	go func() {
		defer wg.Done()
		res.BtoA = copyHalf(a, b, fail)
	}()
	wg.Wait()
	a.Close()
	b.Close()
	return res
}

func copyHalf(dst, src Conn, fail func(error)) int64 {
	n, err := io.Copy(dst, src)
	if err != nil {
		fail(err)
		return n
	}
	if err := dst.CloseWrite(); err != nil {
		fail(err)
	}
	return n
}
