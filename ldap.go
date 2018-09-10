package gimlet

import (
	"crypto/tls"
	"fmt"

	"github.com/pkg/errors"
	ldap "gopkg.in/ldap.v2"
)

// LDAPAuthenticator provides authentication and authorization of users against an LDAP service.
type LDAPAuthenticator struct {
	url  string
	port string
	path string
	conn *ldap.Conn
}

// NewLDAPAuthenticator constructs an LDAPAuthenticator. It requires a url and port to the LDAP
// server. It also requires a path to user resources that can be passed to an LDAP query.
func NewLDAPAuthenticator(url, port, path string) (*LDAPAuthenticator, error) {
	if url == "" || port == "" || path == "" {
		return nil, errors.Errorf("url ('%s'), port ('%s'), and path ('%s') must be provided", url, port, path)
	}
	return &LDAPAuthenticator{
		url:  url,
		port: port,
		path: path,
	}, nil
}

// Authenticate returns nil if the user and password are valid, an error otherwise.
func (l *LDAPAuthenticator) Authenticate(user, password string) error {
	if err := l.connect(); err != nil {
		return errors.Wrap(err, "could not connect to LDAP server")
	}
	if err := l.login(user, password); err != nil {
		return errors.Wrap(err, "failed to validate user")
	}
	return nil
}

// Authorize returns nil if the user is a member of the group, an error otherwise.
func (l *LDAPAuthenticator) Authorize(user, group string) error {
	if err := l.connect(); err != nil {
		return errors.Wrap(err, "could not connect to LDAP server")
	}
	if err := l.isMemberOf(user, group); err != nil {
		return errors.Wrap(err, "failed to validate user")
	}
	return nil
}

func (l *LDAPAuthenticator) connect() error {
	tlsConfig := &tls.Config{ServerName: l.url}
	conn, err := ldap.DialTLS("tcp", fmt.Sprintf("%s:%s", l.url, l.port), tlsConfig)
	if err != nil {
		return errors.Wrapf(err, "problem connecting to ldap server %s:%s", l.url, l.port)
	}
	l.conn = conn
	return nil
}

func (l *LDAPAuthenticator) login(user, password string) error {
	fullPath := fmt.Sprintf("uid=%s,%s", user, l.path)
	return errors.Wrapf(l.conn.Bind(fullPath, password), "could not validate user '%s'", user)
}

func (l *LDAPAuthenticator) isMemberOf(user, group string) error {
	result, err := l.conn.Search(
		ldap.NewSearchRequest(
			l.path,
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
