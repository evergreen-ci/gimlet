package ldap

import (
	"context"
	"crypto/tls"
	"testing"
	"time"

	"github.com/evergreen-ci/gimlet"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/suite"
	ldap "gopkg.in/ldap.v2"
)

type LDAPSuite struct {
	um gimlet.UserManager
	suite.Suite
}

func TestLDAPSuite(t *testing.T) {
	suite.Run(t, new(LDAPSuite))
}

func (s *LDAPSuite) SetupTest() {
	var err error
	s.um, err = NewUserService(CreationOpts{
		URL:     "url",
		Port:    "port",
		Path:    "path",
		Group:   "10gen",
		Put:     mockPut,
		Get:     mockGet,
		connect: mockConnect,
	})
	s.Require().NotNil(s.um)
	s.Require().NoError(err)
}

func mockConnect(url, port string) (ldap.Client, error) {
	return &mockConn{}, nil
}

type mockConn struct{}

func (m *mockConn) Start()                               { return }
func (m *mockConn) StartTLS(config *tls.Config) error    { return nil }
func (m *mockConn) Close()                               { return }
func (m *mockConn) SetTimeout(time.Duration)             { return }
func (m *mockConn) Bind(username, password string) error { return nil }
func (m *mockConn) SimpleBind(simpleBindRequest *ldap.SimpleBindRequest) (*ldap.SimpleBindResult, error) {
	return nil, nil
}
func (m *mockConn) Add(addRequest *ldap.AddRequest) error             { return nil }
func (m *mockConn) Del(delRequest *ldap.DelRequest) error             { return nil }
func (m *mockConn) Modify(modifyRequest *ldap.ModifyRequest) error    { return nil }
func (m *mockConn) Compare(dn, attribute, value string) (bool, error) { return false, nil }
func (m *mockConn) PasswordModify(passwordModifyRequest *ldap.PasswordModifyRequest) (*ldap.PasswordModifyResult, error) {
	return nil, nil
}
func (m *mockConn) Search(searchRequest *ldap.SearchRequest) (*ldap.SearchResult, error) {
	return &ldap.SearchResult{
		Entries: []*ldap.Entry{
			&ldap.Entry{
				Attributes: []*ldap.EntryAttribute{
					&ldap.EntryAttribute{
						Values: []string{"10gen"},
					},
				},
			},
		},
	}, nil
}
func (m *mockConn) SearchWithPaging(searchRequest *ldap.SearchRequest, pagingSize uint32) (*ldap.SearchResult, error) {
	return nil, nil
}

type mockUser struct{ name string }

func (u *mockUser) DisplayName() string { return "" }
func (u *mockUser) Email() string       { return "" }
func (u *mockUser) Username() string    { return u.name }
func (u *mockUser) GetAPIKey() string   { return "" }
func (u *mockUser) Roles() []string     { return []string{} }

func mockPut(u gimlet.User) (string, error) {
	return u.Username(), nil
}

type getController int

const (
	getErr getController = iota
	getValidUser
	getExpiredUser
	getMissingUser
)

var getControl = getErr

func mockGet(token string) (gimlet.User, bool, error) {
	if getControl == getErr {
		return nil, false, errors.New("error getting user")
	}
	if getControl == getValidUser {
		return &mockUser{name: token}, true, nil
	}
	if getControl == getExpiredUser {
		return &mockUser{name: token}, false, nil
	}
	return nil, false, nil
}

func (s *LDAPSuite) TestLDAPConstructorRequiresNonEmptyArgs() {
	l, err := NewUserService(CreationOpts{
		URL:   "url",
		Port:  "port",
		Path:  "path",
		Group: "group",
		Put:   mockPut,
		Get:   mockGet,
	})
	s.NotNil(l)
	s.NoError(err)

	l, err = NewUserService(CreationOpts{
		URL:   "",
		Port:  "port",
		Path:  "path",
		Group: "group",
		Put:   mockPut,
		Get:   mockGet,
	})
	s.Nil(l)
	s.Error(err)

	l, err = NewUserService(CreationOpts{
		URL:   "url",
		Port:  "",
		Path:  "path",
		Group: "group",
		Put:   mockPut,
		Get:   mockGet,
	})
	s.Nil(l)
	s.Error(err)

	l, err = NewUserService(CreationOpts{
		URL:   "url",
		Port:  "port",
		Path:  "",
		Group: "group",
		Put:   mockPut,
		Get:   mockGet,
	})
	s.Nil(l)
	s.Error(err)

	l, err = NewUserService(CreationOpts{
		URL:   "url",
		Port:  "port",
		Path:  "path",
		Group: "",
		Put:   mockPut,
		Get:   mockGet,
	})
	s.Nil(l)
	s.Error(err)

	l, err = NewUserService(CreationOpts{
		URL:   "url",
		Port:  "port",
		Path:  "path",
		Group: "group",
		Put:   nil,
		Get:   mockGet,
	})
	s.Nil(l)
	s.Error(err)

	l, err = NewUserService(CreationOpts{
		URL:   "url",
		Port:  "port",
		Path:  "path",
		Group: "group",
		Put:   mockPut,
		Get:   nil,
	})
	s.Nil(l)
	s.Error(err)
}

func (s *LDAPSuite) TestGetUserByToken() {
	ctx := context.Background()

	getControl = getErr
	u, err := s.um.GetUserByToken(ctx, "erh")
	s.Error(err)
	s.Nil(u)

	getControl = getValidUser
	u, err = s.um.GetUserByToken(ctx, "erh")
	s.NoError(err)
	s.Equal("erh", u.Username())

	getControl = getExpiredUser
	u, err = s.um.GetUserByToken(ctx, "erh")
	s.NoError(err)
	s.Equal("erh", u.Username())

	getControl = getMissingUser
	u, err = s.um.GetUserByToken(ctx, "erh")
	s.Error(err)
	s.Nil(u)
}
