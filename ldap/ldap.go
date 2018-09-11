package ldap

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/evergreen-ci/gimlet"
	"github.com/pkg/errors"
	ldap "gopkg.in/ldap.v2"
)

// userService provides authentication and authorization of users against an LDAP service. It
// implements the gimlet.Authenticator interface.
type userService struct {
	CreationOpts
	conn *ldap.Conn
}

// CreationOpts are options to pass to the service constructor.
type CreationOpts struct {
	URL  string
	Port string
	Path string
}

// NewUserService constructs a userService. It requires a URL and Port to the LDAP
// server. It also requires a Path to user resources that can be passed to an LDAP query.
func NewUserService(opts CreationOpts) (gimlet.UserManager, error) {
	if err := opts.validate(); err != nil {
		return nil, err
	}
	u := &userService{}
	u.CreationOpts = CreationOpts{
		URL:  opts.URL,
		Port: opts.Port,
		Path: opts.Path,
	}
	return u, nil
}

func (opts CreationOpts) validate() error {
	if opts.URL == "" || opts.Port == "" || opts.Path == "" {
		return errors.Errorf("URL ('%s'), Port ('%s'), and Path ('%s') must be provided", opts.URL, opts.Port, opts.Path)
	}
	return nil
}

func (*userService) GetUserByToken(context.Context, string) (gimlet.User, error) {
	return nil, errors.New("not yet implemented")
}
func (*userService) CreateUserToken(string, string) (string, error) {
	return "", errors.New("not yet implemented")
}
func (*userService) GetLoginHandler(url string) http.HandlerFunc { return nil }
func (*userService) GetLoginCallbackHandler() http.HandlerFunc   { return nil }
func (*userService) IsRedirect() bool                            { return false }
func (*userService) GetUserByID(string) (gimlet.User, error) {
	return nil, errors.New("not yet implemented")
}
func (*userService) GetOrCreateUser(gimlet.User) (gimlet.User, error) {
	return nil, errors.New("not yet implemented")
}

// authenticate returns nil if the user and password are valid, an error otherwise.
func (u *userService) authenticate(user, password string) error {
	if err := u.connect(); err != nil {
		return errors.Wrap(err, "could not connect to LDAP server")
	}
	if err := u.login(user, password); err != nil {
		return errors.Wrap(err, "failed to validate user")
	}
	return nil
}

// authorize returns nil if the user is a member of the group, an error otherwise.
func (u *userService) authorize(user, group string) error {
	if err := u.connect(); err != nil {
		return errors.Wrap(err, "could not connect to LDAP server")
	}
	if err := u.isMemberOf(user, group); err != nil {
		return errors.Wrap(err, "failed to validate user")
	}
	return nil
}

func (u *userService) connect() error {
	tlsConfig := &tls.Config{ServerName: u.URL}
	var err error
	u.conn, err = ldap.DialTLS("tcp", fmt.Sprintf("%s:%s", u.URL, u.Port), tlsConfig)
	if err != nil {
		return errors.Wrapf(err, "problem connecting to ldap server %s:%s", u.URL, u.Port)
	}
	return nil
}

func (u *userService) login(user, password string) error {
	fullPath := fmt.Sprintf("uid=%s,%s", user, u.Path)
	return errors.Wrapf(u.conn.Bind(fullPath, password), "could not validate user '%s'", user)
}

func (u *userService) isMemberOf(user, group string) error {
	result, err := u.conn.Search(
		ldap.NewSearchRequest(
			u.Path,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			fmt.Sprintf("(uid=%s)", user),
			[]string{"ismemberof"},
			nil))
	if err != nil {
		return errors.Wrap(err, "problem searching ldap")
	}
	if len(result.Entries) == 0 {
		return errors.Errorf("no entry returned for user '%s'", user)
	}
	if len(result.Entries[0].Attributes) == 0 {
		return errors.Errorf("entry's attributes empty for user '%s'", user)
	}
	for i := range result.Entries[0].Attributes[0].Values {
		if result.Entries[0].Attributes[0].Values[i] == group {
			return nil
		}
	}
	return errors.Errorf("user '%s' is not a member of group '%s'", user, group)
}
