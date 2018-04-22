package auth

import (
	"fmt"
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

type BasicAuthenticator struct {
}
