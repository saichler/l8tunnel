package common

import (
	"errors"

	"github.com/saichler/l8types/go/ifs"
)

// Hooks are one service's callback behavior. Only TypeName, Check and SetID
// are required.
type Hooks struct {
	TypeName string
	// Check asserts the element's type.
	Check func(interface{}) bool
	// SetID generates the primary key on POST when it is empty.
	SetID func(interface{})
	// Validate runs before every write; an error rejects it. It may return
	// a replacement element (nil keeps the input).
	Validate func(elem interface{}, action ifs.Action, vnic ifs.IVNic) (interface{}, error)
	// Changed runs after every successful write, for example to push the
	// change to the relays.
	Changed func(elem interface{}, action ifs.Action, vnic ifs.IVNic)
}

type callback struct {
	h Hooks
}

// NewCallback builds an IServiceCallback from hooks. Changes replayed from
// another replica (notifications) skip both hooks: they were validated and
// published where they happened.
func NewCallback(h Hooks) ifs.IServiceCallback {
	if h.TypeName == "" || h.Check == nil || h.SetID == nil {
		panic("common.NewCallback: TypeName, Check and SetID are required")
	}
	return &callback{h: h}
}

func (c *callback) Before(elem interface{}, action ifs.Action, notification bool, vnic ifs.IVNic) (interface{}, bool, error) {
	if notification {
		return nil, true, nil
	}
	if !c.h.Check(elem) {
		return nil, false, errors.New("invalid " + c.h.TypeName + " type")
	}
	if action == ifs.POST {
		c.h.SetID(elem)
	}
	if c.h.Validate == nil {
		return nil, true, nil
	}
	replaced, err := c.h.Validate(elem, action, vnic)
	if err != nil {
		return nil, false, err
	}
	return replaced, true, nil
}

func (c *callback) After(elem interface{}, action ifs.Action, notification bool, vnic ifs.IVNic) (interface{}, bool, error) {
	if notification || c.h.Changed == nil || !c.h.Check(elem) {
		return nil, true, nil
	}
	c.h.Changed(elem, action, vnic)
	return nil, true, nil
}
