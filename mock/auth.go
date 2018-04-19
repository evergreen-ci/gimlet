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

type Provider struct {
	ReloadShouldFail  bool
	OpenShouldFail    bool
	CloseShouldFail   bool
	MockAuthenticator *Authenticator
	MockUserManager   *UserManager
}

func (p *Provider) Reload(_ context.Context) error {
	if p.ReloadShouldFail {
		return errors.New("reload failure")
	}

	return nil
}

func (p *Provider) Open(_ context.Context) error {
	if p.OpenShouldFail {
		return errors.New("open failure")

	}

	return nil
}

func (p *Provider) Close() error {
	if p.CloseShouldFail {
		return errors.New("close failure")
	}

	return nil
}

func (p *Provider) Authenticator() auth.Authenticator {
	if p.MockAuthenticator == nil {
		p.MockAuthenticator = &Authenticator{
			ResourceUserMapping:     make(map[string]string),
			GroupUserMapping:        make(map[string]string),
			CheckAuthenticatedState: make(map[string]bool),
		}

	}

	return p.MockAuthenticator
}

func (p *Provider) UserManager() auth.UserManager {
	if p.MockUserManager == nil {
		p.MockUserManager = &UserManager{}
	}

	return p.MockUserManager
}

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
	return um.GetUserByToken(a.UserToken)
}

type UserManager struct {
	TokenToUsers map[string]auth.User
}

func (m *UserManager) GetUserByToken(token string) (auth.User, error) {
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

func (m *UserManager) GetLoginHandler(url string) http.HandlerFunc { return nil }
func (m *UserManager) GetLoginCallbackHandler() http.HandlerFunc   { return nil }
func (m *UserManager) IsRedirect() bool                            { return false }
