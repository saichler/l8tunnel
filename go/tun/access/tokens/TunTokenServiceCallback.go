package tokens

import (
	"errors"
	"fmt"
	"strings"
	"time"

	l8common "github.com/saichler/l8common/go/common"
	"github.com/saichler/l8tunnel/go/tun/common"
	"github.com/saichler/l8tunnel/go/tunnel/auth"
	"github.com/saichler/l8tunnel/go/types/tun"
	"github.com/saichler/l8types/go/ifs"
)

func newTunTokenServiceCallback() ifs.IServiceCallback {
	return common.NewCallback(common.Hooks{
		TypeName: "TunToken",
		Check:    func(e interface{}) bool { _, ok := e.(*tun.TunToken); return ok },
		SetID: func(e interface{}) {
			l8common.GenerateID(&e.(*tun.TunToken).TokenId)
		},
		Validate: validate,
		// Relays act on every token change (policy, revocation) at once.
		Changed: common.PushToRelays,
	})
}

func validate(e interface{}, action ifs.Action, vnic ifs.IVNic) (interface{}, error) {
	t := e.(*tun.TunToken)
	if action == ifs.PATCH {
		return nil, validatePatch(t, vnic)
	}
	if err := auth.ValidateTokenName(t.Name); err != nil {
		return nil, err
	}
	if err := validatePolicy(t.Policy); err != nil {
		return nil, err
	}
	if err := checkNameFree(t, vnic); err != nil {
		return nil, err
	}
	if action == ifs.POST {
		if !isBcrypt(t.SecretHash) {
			return nil, errors.New("create tokens through TunIssue, which returns the token once")
		}
		if t.CreatedAt == 0 {
			t.CreatedAt = time.Now().Unix()
		}
		return nil, nil
	}
	// PUT: the secret can't change. The UI never sees the hash (a deny
	// rule blanks it), so an empty hash means "keep the stored one".
	existing, err := Token(t.TokenId, vnic)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return nil, fmt.Errorf("token %s doesn't exist", t.TokenId)
	}
	switch t.SecretHash {
	case "":
		t.SecretHash = existing.SecretHash
	case existing.SecretHash:
	default:
		return nil, errors.New("a token's secret can't be changed; issue a new token instead")
	}
	if t.CreatedAt == 0 {
		t.CreatedAt, t.CreatedBy = existing.CreatedAt, existing.CreatedBy
	}
	return nil, nil
}

// validatePatch checks only the fields a PATCH sets.
func validatePatch(t *tun.TunToken, vnic ifs.IVNic) error {
	if t.Name != "" {
		if err := auth.ValidateTokenName(t.Name); err != nil {
			return err
		}
		if err := checkNameFree(t, vnic); err != nil {
			return err
		}
	}
	if t.Policy != nil {
		if err := validatePolicy(t.Policy); err != nil {
			return err
		}
	}
	if t.SecretHash != "" {
		existing, err := Token(t.TokenId, vnic)
		if err != nil {
			return err
		}
		if existing == nil || existing.SecretHash != t.SecretHash {
			return errors.New("a token's secret can't be changed; issue a new token instead")
		}
	}
	return nil
}

func validatePolicy(p *tun.TunTokenPolicy) error {
	policy, err := common.PolicyToAuth(p)
	if err != nil {
		return err
	}
	return policy.Validate()
}

func checkNameFree(t *tun.TunToken, vnic ifs.IVNic) error {
	all, err := Tokens(vnic)
	if err != nil {
		return err
	}
	for _, o := range all {
		if o.TokenId != t.TokenId && strings.EqualFold(o.Name, t.Name) {
			return fmt.Errorf("a token named %q already exists", o.Name)
		}
	}
	return nil
}

// isBcrypt reports whether s looks like a bcrypt hash.
func isBcrypt(s string) bool {
	return len(s) == 60 && (strings.HasPrefix(s, "$2a$") || strings.HasPrefix(s, "$2b$") || strings.HasPrefix(s, "$2y$"))
}
