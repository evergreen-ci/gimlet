package gimlet

import (
	"github.com/mongodb/grip"
	"github.com/mongodb/grip/message"
)

// NewBasicUser constructs a simple user. The underlying type has
// serialization tags.
func NewBasicUser(id, name, email, password, key, accessToken, refreshToken string, roles []string, invalid bool, rm RoleManager) *BasicUser {
	return &BasicUser{
		ID:           id,
		Name:         name,
		EmailAddress: email,
		Password:     password,
		Key:          key,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		AccessRoles:  roles,
		Invalid:      invalid,
		roleManager:  rm,
	}
}

type BasicUser struct {
	ID           string   `bson:"_id" json:"id" yaml:"id"`
	Name         string   `bson:"name" json:"name" yaml:"name"`
	EmailAddress string   `bson:"email" json:"email" yaml:"email"`
	Password     string   `bson:"password" json:"password" yaml:"password"`
	Key          string   `bson:"key" json:"key" yaml:"key"`
	AccessToken  string   `bson:"access_token" json:"access_token" yaml:"access_token"`
	RefreshToken string   `bson:"refresh_token" json:"refresh_token" yaml:"refresh_token"`
	AccessRoles  []string `bson:"roles" json:"roles" yaml:"roles"`
	Invalid      bool     `bson:"invalid" json:"invalid" yaml:"invalid"`
	roleManager  RoleManager
}

func (u *BasicUser) Username() string        { return u.ID }
func (u *BasicUser) Email() string           { return u.EmailAddress }
func (u *BasicUser) DisplayName() string     { return u.Name }
func (u *BasicUser) GetAPIKey() string       { return u.Key }
func (u *BasicUser) GetAccessToken() string  { return u.AccessToken }
func (u *BasicUser) GetRefreshToken() string { return u.RefreshToken }
func (u *BasicUser) Roles() []string {
	out := make([]string, len(u.AccessRoles))
	copy(out, u.AccessRoles)
	return out
}
func (u *BasicUser) HasPermission(opts PermissionOpts) bool {
	roles, err := u.roleManager.GetRoles(u.Roles())
	if err != nil {
		grip.Error(message.WrapError(err, message.Fields{
			"message": "error getting roles",
		}))
		return false
	}
	return HasPermission(u.roleManager, opts, roles)
}

// userHasRole determines if the user has the defined role.
func userHasRole(u User, role string) bool {
	for _, r := range u.Roles() {
		if r == role {
			return true
		}
	}

	return false
}

func userInSlice(u User, users []string) bool {
	if len(users) == 0 {
		return false
	}

	id := u.Username()
	for _, u := range users {
		if id == u {
			return true
		}
	}

	return false
}
