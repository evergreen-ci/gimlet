package mock

import (
	"context"
	"errors"
	"net/http"
)

type User struct {
	Name         string
	EmailAddress string
	ReportNil    bool
	APIKey       string
	Roles        []string
}

func (u *User) DisplayName() string { return u.Name }
func (u *User) Email() string       { return u.EmailAddress }
func (u *User) IsNil() bool         { return u.ReportNil }
func (u *User) GetAPIKey() string   { return u.APIKey }
func (u *User) Roles() []string     { return u.Roles }

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

func (p *Provider) Authenticator() gimlet.Authenticator {
	if p.MockAuthenticator == nil {
		p.MockAuthenticator = &Authenticator{
			ResourceUserMapping:     make(map[string]string),
			GroupUserMapping:        make(map[string]string),
			CheckAuthenticatedState: make(map[string]bool),
		}

	}

	return p.MockAuthenticator
}

func (p *Provider) UserManager() gimlet.UserManager {
	if p.MockUserManager == nil {
		p.MockUserManager = &UserManager{}
	}

	return p.UserManager
}

type Authenticator struct {
	ResourceUserMapping     map[string]string
	GroupUserMapping        map[string]string
	CheckAuthenticatedState map[string]bool
}

func (a *Authenticator) CheckResourceAccess(u gimlet.User, resource string) bool {}
func (a *Authenticator) CheckGroupAccess(u gimlet.User, group string) bool       {}
func (a *Authenticator) CheckAuthenticated(u gimlet.User) bool                   {}
func (a *Authenticator) GetUserFromRequest(um gimlet.UserManager, r *http.Request) (gimlet.User, error) {
}

type UserManager struct{}

func (m *UserManager) GetUserByToken(token string) (gimlet.User, error)          {}
func (m *UserManager) CreateUserToken(username, password string) (string, error) {}
func (m *UserManager) GetLoginHandler(url string) http.HandlerFunc               {}
func (m *UserManager) GetLoginCallbackHandler() http.HandlerFunc                 {}
func (m *UserManager) IsRedirect() bool                                          {}
