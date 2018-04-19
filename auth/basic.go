package auth

import (
	"context"
	"fmt"

	"github.com/pkg/errors"
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

type BasicProvider struct {
	AuthService Authenticator
	UserService UserManager
	isOpen      bool
}

func (p *BasicProvider) Open(_ context.Context) error {
	p.isOpen = true
	if p.AuthService == nil || p.UserService == nil {
		return errors.New("auth provides is incomplete")
	}

	return nil
}

func (p *BasicProvider) Reload(_ context.Context) error {
	if !p.isOpen {
		return errors.New("must open auth service before reloading")
	}

	if p.AuthService == nil || p.UserService == nil {
		return errors.New("auth provides is incomplete")
	}

	return nil
}

func (p *BasicProvider) Close() error { p.isOpen = false; return nil }

func (p *BasicProvider) Authenticator() Authenticator {
	if !p.isOpen {
		return nil
	}

	return p.AuthService
}

func (p *BasicProvider) UserManager() UserManager {
	if !p.isOpen {
		return nil
	}

	return p.UserService
}
