package inspect

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"net/http"
	"time"
)

// Conn is a half-closable connection (pipe.Conn).
type Conn interface {
	io.ReadWriteCloser
	CloseWrite() error
}

// ServeStream carries HTTP/1.1 between the relay (client) and the local
// service (target), recording each request. Bodies stream through; only
// their first MaxBody bytes are kept. A protocol upgrade (101, e.g.
// WebSockets) switches to a raw byte pipe for the rest of the connection.
// It returns when either side closes; both connections are closed.
func (r *Recorder) ServeStream(tunnel string, client, target Conn) {
	defer client.Close()
	defer target.Close()
	cr, tr := bufio.NewReader(client), bufio.NewReader(target)
	for {
		req, err := http.ReadRequest(cr)
		if err != nil {
			return // client closed or sent garbage
		}
		e, keepGoing, upgraded := r.exchange(tunnel, req, target, tr, client)
		r.add(e)
		if upgraded {
			rawPipe(client, cr, target, tr)
			return
		}
		if !keepGoing {
			return
		}
	}
}

// exchange forwards one request and its response(s).
func (r *Recorder) exchange(tunnel string, req *http.Request, target io.Writer, tr *bufio.Reader, client io.Writer) (e *Entry, keepGoing, upgraded bool) {
	start := time.Now()
	e = &Entry{Time: start, Tunnel: tunnel, Method: req.Method, URI: req.RequestURI, Host: req.Host,
		Proto: req.Proto, ReqHead: req.Header.Clone()}
	finish := func(err error) {
		e.Duration = float64(time.Since(start).Microseconds()) / 1000
		if err != nil && e.Error == "" {
			e.Error = err.Error()
		}
	}
	var reqBody capture
	if req.Body != nil {
		req.Body = struct {
			io.Reader
			io.Closer
		}{io.TeeReader(req.Body, &reqBody), req.Body}
	}
	// Request.Write sends Host from req.Host and re-frames the body.
	if err := req.Write(target); err != nil {
		finish(err)
		return e, false, false
	}
	e.ReqBody, e.ReqSize = reqBody.buf, reqBody.size

	for {
		resp, err := http.ReadResponse(tr, req)
		if err != nil {
			e.Status = http.StatusBadGateway
			finish(err)
			return e, false, false
		}
		e.Status, e.RespHead = resp.StatusCode, resp.Header.Clone()
		if resp.StatusCode == http.StatusSwitchingProtocols {
			err := resp.Write(client) // headers only: a 101 has no body
			e.Upgraded = true
			finish(err)
			return e, false, err == nil
		}
		if resp.StatusCode >= 100 && resp.StatusCode < 200 {
			// Informational (100 Continue, 103 Early Hints): pass on,
			// then read the final response.
			if err := resp.Write(client); err != nil {
				finish(err)
				return e, false, false
			}
			continue
		}
		var respBody capture
		resp.Body = struct {
			io.Reader
			io.Closer
		}{io.TeeReader(resp.Body, &respBody), resp.Body}
		err = resp.Write(client)
		e.RespBody, e.RespSize = respBody.buf, respBody.size
		finish(err)
		return e, err == nil && !req.Close && !resp.Close, false
	}
}

// rawPipe copies both ways after an upgrade, including bytes already
// buffered by the HTTP readers.
func rawPipe(client Conn, cr *bufio.Reader, target Conn, tr *bufio.Reader) {
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(target, cr)
		target.CloseWrite()
		done <- struct{}{}
	}()
	go func() {
		io.Copy(client, tr)
		client.CloseWrite()
		done <- struct{}{}
	}()
	<-done
	<-done
}

// Replay sends a recorded request to the local service again and records
// the result. The request body must have been captured in full.
func (r *Recorder) Replay(id int64, dial func(tunnel string) (net.Conn, error)) (*Entry, error) {
	orig := r.Get(id)
	if orig == nil {
		return nil, errors.New("no such request")
	}
	if orig.ReqSize != int64(len(orig.ReqBody)) {
		return nil, errors.New("the request body was larger than the inspector keeps; it can't be replayed")
	}
	if orig.Upgraded {
		return nil, errors.New("protocol upgrades (WebSockets) can't be replayed")
	}
	conn, err := dial(orig.Tunnel)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	req, err := http.NewRequest(orig.Method, "http://"+orig.Host+orig.URI, io.NopCloser(bytes.NewReader(orig.ReqBody)))
	if err != nil {
		return nil, err
	}
	req.Header = orig.ReqHead.Clone()
	req.Host = orig.Host
	req.ContentLength = orig.ReqSize
	req.RequestURI = orig.URI
	req.Close = true
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	e, _, _ := r.exchange(orig.Tunnel, req, conn, bufio.NewReader(conn), io.Discard)
	e.URI, e.ReplayOf = orig.URI, orig.ID
	r.add(e)
	return e, nil
}
