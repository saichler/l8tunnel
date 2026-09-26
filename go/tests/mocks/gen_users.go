package mocks

import "fmt"

// usersArea is the Security API's users service (l8secure, area 73). A
// project provisions users only through it, as plain JSON.
const usersArea = byte(73)

// The demo users' passwords meet l8secure's policy (10+ characters, upper
// and lower case, a digit and a special character, no runs).
var demoPasswords = map[string]string{"operator": "Mq4#Vw8!Tz2", "viewer": "Rb5$Hn9%Pk3"}

// Phase 9: demo users for the operator and viewer roles.
func generateUsers(c *Client, s *MockDataStore, tag string) error {
	for _, u := range []struct{ id, name, role string }{
		{"operator" + tag, "Demo operator", "operator"},
		{"viewer" + tag, "Demo viewer", "viewer"},
	} {
		if err := postMap(c, usersArea, "users", map[string]interface{}{
			"userId": u.id, "fullName": u.name, "email": u.id + "@example.test",
			"accountStatus": "ACCOUNT_STATUS_ACTIVE",
			"password":      map[string]interface{}{"hash": demoPasswords[u.role]},
			"roles":         map[string]bool{u.role: true},
		}); err != nil {
			return fmt.Errorf("user %s: %w", u.id, err)
		}
		s.TunUserIDs = append(s.TunUserIDs, u.id+" / "+demoPasswords[u.role])
	}
	return nil
}
