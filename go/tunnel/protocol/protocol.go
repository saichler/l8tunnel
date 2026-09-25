// Package protocol holds the constants, framing and error types shared by
// the relay and the agent.
package protocol

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/saichler/l8tunnel/go/types/l8tunnel"
)

const (
	// Version is the control-protocol version spoken by this build.
	Version uint32 = 1
	// ALPN is the TLS application protocol an agent must negotiate. The relay
	// uses it to tell agent control connections apart from public traffic.
	ALPN = "l8tunnel/1"
	// ConnectALPN is offered by "l8tunnel connect" (mode B). For a host
	// name with no active tunnel, the relay fails the handshake for these
	// clients instead of serving its HTTP error page.
	ConnectALPN = "l8tunnel-connect/1"
)

// RandomID returns a random hex string of 2*nbytes characters.
func RandomID(nbytes int) string {
	buf := make([]byte, nbytes)
	// crypto/rand.Read never returns an error on supported platforms and
	// panics internally if the system random source is unavailable.
	rand.Read(buf)
	return hex.EncodeToString(buf)
}

// RemoteError is an Error message received from the peer.
type RemoteError struct {
	Code    l8tunnel.ErrorCode
	Message string
}

func (e *RemoteError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// NewRemoteError converts an Error message into a Go error.
func NewRemoteError(msg *l8tunnel.Error) *RemoteError {
	return &RemoteError{Code: msg.GetCode(), Message: msg.GetMessage()}
}

// ErrorMessage builds a control message carrying an Error.
func ErrorMessage(code l8tunnel.ErrorCode, format string, args ...interface{}) *l8tunnel.ControlMessage {
	return &l8tunnel.ControlMessage{Body: &l8tunnel.ControlMessage_Error{
		Error: &l8tunnel.Error{Code: code, Message: fmt.Sprintf(format, args...)},
	}}
}
