package gimlet

// NewBasicUser constructs a simple user. The underlying type has
// serialization tags.
func NewBasicUser(opts *BasicUserOpts) User {
	return &basicUser{opts}
}

// MakeBasicUser constructs an empty basic user structure to ease
// serialization.
func MakeBasicUser() User { return &basicUser{} }

type basicUser struct {
	*BasicUserOpts
}

type BasicUserOpts struct {
	ID           string   `bson:"_id" json:"id" yaml:"id"`
	EmailAddress string   `bson:"email" json:"email" yaml:"email"`
	Name         string   `bson:"name" json:"name" yaml:"name"`
	Key          string   `bson:"key" json:"key" yaml:"key"`
	AccessRoles  []string `bson:"roles" json:"roles" yaml:"roles"`
	Password     string   `bson:"pass" json:"pass" yaml:"pass"`
}

func (u *basicUser) Username() string    { return u.ID }
func (u *basicUser) Email() string       { return u.EmailAddress }
func (u *basicUser) DisplayName() string { return u.Name }
func (u *basicUser) GetAPIKey() string   { return u.Key }
func (u *basicUser) Roles() []string {
	out := make([]string, len(u.AccessRoles))
	copy(out, u.AccessRoles)
	return out
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
