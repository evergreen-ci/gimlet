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
	mu       sync.RWMutex
	users    map[string]User
	groups   map[string]string
	tokeName string
}

func NewBasicAuthenticator(users []User, groups map[string]string, tokenName string) Authenticator {
	if groups == nil {
		groups = map[string]string{}
	}

	a := &basicAuthenticator{
		groups:   groups,
		users:    map[string]User{},
		tokeName: tokenName,
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
func (a *basicAuthenticator) GetUserFromRequest(um UserManager, r *http.Request) (User, error) {
	return nil, nil
}

/*
func setRequestUser(r *http.Requst, u User) *http.Request { return r }

func (a *basicAuthenticator) GetUserFromRequest(um UserManager, r *http.Request) (User, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	token := ""
	var err error
	// Grab token auth from cookies
	for _, cookie := range r.Cookies() {
		if cookie.Name == a.tokenName {
			if token, err = url.QueryUnescape(cookie.Value); err == nil {
				break
			}
		}
	}

	// Grab API auth details from header
	var authDataAPIKey, authDataName string
	if len(r.Header["Api-Key"]) > 0 {
		authDataAPIKey = r.Header["Api-Key"][0]
	}
	if len(r.Header["Auth-Username"]) > 0 {
		authDataName = r.Header["Auth-Username"][0]
	}
	if len(authDataName) == 0 && len(r.Header["Api-User"]) > 0 {
		authDataName = r.Header["Api-User"][0]
	}

	if len(token) > 0 {
		ctx := r.Context()
		u, err := um.GetUserByToken(ctx, token)

		if err != nil {
			grip.Infof("Error getting user %s: %+v", authDataName, err)
		} else {
			// Get the user's full details from the DB or create them if they don't exists
			if err != nil {
				grip.Debug(message.WrapError(err, message.Fields{
					"message": "error looking up user",
					"user":    u.Username(),
				}))
			} else {
				r = setRequestUser(r, dbUser)
			}
		}
	} else if len(authDataAPIKey) > 0 {
		dbUser, err := user.FindOne(user.ById(authDataName))
		if dbUser != nil && err == nil {
			if dbUser.APIKey != authDataAPIKey {
				http.Error(rw, "Unauthorized - invalid API key", http.StatusUnauthorized)
				return
			}
			r = setRequestUser(r, dbUser)
		} else {
			grip.Errorln("Error getting user:", err)
		}
	}

}
*/
