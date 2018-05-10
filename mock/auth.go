package mock

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/evergreen-ci/gimlet/auth"
)

type User struct {
	ID           string
	Name         string
	EmailAddress string
	ReportNil    bool
	APIKey       string
	RoleNames    []string
}

func (u *User) DisplayName() string { return u.Name }
func (u *User) Email() string       { return u.EmailAddress }
func (u *User) Username() string    { return u.ID }
func (u *User) IsNil() bool         { return u.ReportNil }
func (u *User) GetAPIKey() string   { return u.APIKey }
func (u *User) Roles() []string     { return u.RoleNames }

type Authenticator struct {
	ResourceUserMapping     map[string]string
	GroupUserMapping        map[string]string
	CheckAuthenticatedState map[string]bool
	UserToken               string
}

func (a *Authenticator) CheckResourceAccess(u auth.User, resource string) bool {
	r, ok := a.ResourceUserMapping[u.Username()]
	if !ok {
		return false
	}

	return r == resource
}

func (a *Authenticator) CheckGroupAccess(u auth.User, group string) bool {
	g, ok := a.GroupUserMapping[u.Username()]
	if !ok {
		return false
	}

	return g == group
}
func (a *Authenticator) CheckAuthenticated(u auth.User) bool {
	return a.CheckAuthenticatedState[u.Username()]
}

func (a *Authenticator) GetUserFromRequest(um auth.UserManager, r *http.Request) (auth.User, error) {
	ctx := r.Context()

	u, err := um.GetUserByToken(ctx, a.UserToken)
	if err != nil {
		return nil, err
	}
	if u == nil {
		return nil, errors.New("user not defined")
	}
	return u, nil
}

type UserManager struct {
	TokenToUsers map[string]auth.User
}

func (m *UserManager) GetUserByToken(_ context.Context, token string) (auth.User, error) {
	if m.TokenToUsers == nil {
		return nil, errors.New("no users configured")
	}

	u, ok := m.TokenToUsers[token]
	if !ok {
		return nil, errors.New("user does not exist")
	}

	return u, nil
}

func (m *UserManager) CreateUserToken(username, password string) (string, error) {
	return strings.Join([]string{username, password}, "."), nil
}

func (m *UserManager) GetLoginHandler(url string) http.HandlerFunc    { return nil }
func (m *UserManager) GetLoginCallbackHandler() http.HandlerFunc      { return nil }
func (m *UserManager) IsRedirect() bool                               { return false }
func (m *UserManager) GetUserByID(id string) (auth.User, error)       { return nil, nil }
func (m *UserManager) GetOrCreateUser(u auth.User) (auth.User, error) { return u, nil }
