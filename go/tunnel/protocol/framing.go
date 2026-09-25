package protocol

import (
	"encoding/binary"
	"fmt"
	"io"

	"google.golang.org/protobuf/proto"
)

// MaxMessageSize bounds a single framed message, so a misbehaving peer
// can't make us allocate arbitrary amounts of memory.
const MaxMessageSize = 1 << 20

// WriteMessage writes msg as a 4-byte big-endian length followed by its
// protobuf encoding.
func WriteMessage(w io.Writer, msg proto.Message) error {
	data, err := proto.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal %T: %w", msg, err)
	}
	if len(data) > MaxMessageSize {
		return fmt.Errorf("%T is %d bytes, max is %d", msg, len(data), MaxMessageSize)
	}
	frame := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(frame, uint32(len(data)))
	copy(frame[4:], data)
	if _, err := w.Write(frame); err != nil {
		return fmt.Errorf("write %T: %w", msg, err)
	}
	return nil
}

// ReadMessage reads one frame written by WriteMessage into msg.
func ReadMessage(r io.Reader, msg proto.Message) error {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size > MaxMessageSize {
		return fmt.Errorf("incoming frame is %d bytes, max is %d", size, MaxMessageSize)
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(r, data); err != nil {
		return fmt.Errorf("read %T body: %w", msg, err)
	}
	if err := proto.Unmarshal(data, msg); err != nil {
		return fmt.Errorf("unmarshal %T: %w", msg, err)
	}
	return nil
}
