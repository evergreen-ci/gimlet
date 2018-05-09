package auth

import (
	"fmt"
	"net/http"
	"sync"
)

type BasicUser struct {
	ID           string   `bson:"_id" json:"id" yaml:"id"`
	EmailAddress string   `bson:"email" json:"email" yaml:"email"`
	Key          string   `bson:"key" json:"key" yaml:"key"`
	AccessRoles  []string `bson:"roles" json:"roles" yaml:"roles"`
}

func (u *BasicUser) Username() string    { return u.ID }
func (u *BasicUser) Email() string       { return u.EmailAddress }
func (u *BasicUser) DisplayName() string { return fmt.Sprintf("%s <%s>", u.ID, u.EmailAddress) }
func (u *BasicUser) IsNil() bool         { return u == nil }
func (u *BasicUser) GetAPIKey() string   { return u.Key }
func (u *BasicUser) Roles() []string {
	out := make([]string, len(u.AccessRoles))
	copy(out, u.AccessRoles)
	return out
}

type basicAuthenticator struct {
	mu     sync.RWMutex
	users  map[string]User
	groups map[string]string
}

func NewBasicAuthenticator(users []User, groups map[string]string) Authenticator {
	if groups == nil {
		groups = map[string]string{}
	}

	a := &basicAuthenticator{
		groups: groups,
		users:  map[string]User{},
	}

	for _, u := range users {
		if u != nil && !u.IsNil() {
			a.users[u.Username()] = u
		}
	}

	return a
}

func (a *basicAuthenticator) CheckResourceAccess(u User, resource string) bool {
	if !a.CheckAuthenticated(u) {
		return false
	}

	return UserHasRole(u, resource)
}

func (a *basicAuthenticator) CheckGroupAccess(u User, group string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()

	ur, ok := a.users[u.Username()]

	if !ok {
		return false
	}

	if u.GetAPIKey() == ur.GetAPIKey() {
		return true
	}

	return false
}

func (a *basicAuthenticator) CheckAuthenticated(u User) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()

	ur, ok := a.users[u.Username()]

	if !ok {
		return false
	}

	return u.GetAPIKey() == ur.GetAPIKey()
}

// TODO: remove
func (a *basicAuthenticator) GetUserFromRequest(um UserManager, r *http.Request) (User, error) {
	return nil, nil
}
