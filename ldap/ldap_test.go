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
	um         gimlet.UserManager
	badGroupUm gimlet.UserManager
	realConnUm gimlet.UserManager
	suite.Suite
}

func TestLDAPSuite(t *testing.T) {
	suite.Run(t, new(LDAPSuite))
}

func (s *LDAPSuite) SetupTest() {
	var err error
	mockPutUser = nil
	s.um, err = NewUserService(CreationOpts{
		URL:           "url",
		Port:          "port",
		Path:          "path",
		Group:         "10gen",
		PutCache:      mockPut,
		GetCache:      mockGet,
		connect:       mockConnect,
		GetUser:       mockGetUserByID,
		GetCreateUser: mockGetOrCreateUser,
	})
	s.Require().NotNil(s.um)
	s.Require().NoError(err)

	s.badGroupUm, err = NewUserService(CreationOpts{
		URL:           "url",
		Port:          "port",
		Path:          "path",
		Group:         "badgroup",
		PutCache:      mockPut,
		GetCache:      mockGet,
		connect:       mockConnect,
		GetUser:       mockGetUserByID,
		GetCreateUser: mockGetOrCreateUser,
	})
	s.Require().NotNil(s.badGroupUm)
	s.Require().NoError(err)

	s.realConnUm, err = NewUserService(CreationOpts{
		URL:           "url",
		Port:          "port",
		Path:          "path",
		Group:         "badgroup",
		PutCache:      mockPut,
		GetCache:      mockGet,
		GetUser:       mockGetUserByID,
		GetCreateUser: mockGetOrCreateUser,
	})
	s.Require().NotNil(s.badGroupUm)
	s.Require().NoError(err)
}

func mockConnect(url, port string) (ldap.Client, error) {
	return &mockConn{}, nil
}

type mockConn struct{}

func (m *mockConn) Start()                            { return }
func (m *mockConn) StartTLS(config *tls.Config) error { return nil }
func (m *mockConn) Close()                            { return }
func (m *mockConn) SetTimeout(time.Duration)          { return }
func (m *mockConn) Bind(username, password string) error {
	if username == "uid=foo,path" && password == "hunter2" {
		return nil
	}
	return errors.Errorf("failed to Bind (%s, %s)", username, password)
}
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

type searchController int

const (
	searchUserErr searchController = iota
	searchUserSuccess
)

var searchControl = searchUserSuccess

func (m *mockConn) Search(searchRequest *ldap.SearchRequest) (*ldap.SearchResult, error) {
	if searchControl == searchUserErr {
		if len(searchRequest.Attributes) == 0 || searchRequest.Attributes[0] != "ismemberof" {
			return nil, errors.New("getUserErr")
		}
	}
	return &ldap.SearchResult{
		Entries: []*ldap.Entry{
			&ldap.Entry{
				Attributes: []*ldap.EntryAttribute{
					&ldap.EntryAttribute{
						Values: []string{"10gen"},
					},
					&ldap.EntryAttribute{
						Name:   "uid",
						Values: []string{"foo"},
					},
					&ldap.EntryAttribute{
						Name:   "mail",
						Values: []string{"foo@example.com"},
					},
					&ldap.EntryAttribute{
						Name:   "cn",
						Values: []string{"Foo Bar"},
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

var mockPutUser gimlet.User

type putController int

const (
	putErr putController = iota
	putSuccess
)

var putControl = putErr

func mockPut(u gimlet.User) (string, error) {
	mockPutUser = u
	if u.Username() == "badUser" {
		return "", errors.New("got bad user")
	}
	if putControl == putErr {
		return "", errors.New("putErr")
	}
	return "123456", nil
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

func mockGetUserByID(id string) (gimlet.User, error) {
	u := gimlet.NewBasicUser("foo", "", "", "", []string{})
	return u, nil
}

func mockGetOrCreateUser(user gimlet.User) (gimlet.User, error) {
	u := gimlet.NewBasicUser("foo", "", "", "", []string{})
	return u, nil
}

func (s *LDAPSuite) TestLDAPConstructorRequiresNonEmptyArgs() {
	l, err := NewUserService(CreationOpts{
		URL:           "url",
		Port:          "port",
		Path:          "path",
		Group:         "group",
		PutCache:      mockPut,
		GetCache:      mockGet,
		GetUser:       mockGetUserByID,
		GetCreateUser: mockGetOrCreateUser,
	})
	s.NotNil(l)
	s.NoError(err)

	l, err = NewUserService(CreationOpts{
		URL:           "",
		Port:          "port",
		Path:          "path",
		Group:         "group",
		PutCache:      mockPut,
		GetCache:      mockGet,
		GetUser:       mockGetUserByID,
		GetCreateUser: mockGetOrCreateUser,
	})
	s.Nil(l)
	s.Error(err)

	l, err = NewUserService(CreationOpts{
		URL:           "url",
		Port:          "",
		Path:          "path",
		Group:         "group",
		PutCache:      mockPut,
		GetCache:      mockGet,
		GetUser:       mockGetUserByID,
		GetCreateUser: mockGetOrCreateUser,
	})
	s.Nil(l)
	s.Error(err)

	l, err = NewUserService(CreationOpts{
		URL:           "url",
		Port:          "port",
		Path:          "",
		Group:         "group",
		PutCache:      mockPut,
		GetCache:      mockGet,
		GetUser:       mockGetUserByID,
		GetCreateUser: mockGetOrCreateUser,
	})
	s.Nil(l)
	s.Error(err)

	l, err = NewUserService(CreationOpts{
		URL:           "url",
		Port:          "port",
		Path:          "path",
		Group:         "",
		PutCache:      mockPut,
		GetCache:      mockGet,
		GetUser:       mockGetUserByID,
		GetCreateUser: mockGetOrCreateUser,
	})
	s.Nil(l)
	s.Error(err)

	l, err = NewUserService(CreationOpts{
		URL:           "url",
		Port:          "port",
		Path:          "path",
		Group:         "group",
		PutCache:      nil,
		GetCache:      mockGet,
		GetUser:       mockGetUserByID,
		GetCreateUser: mockGetOrCreateUser,
	})
	s.Nil(l)
	s.Error(err)

	l, err = NewUserService(CreationOpts{
		URL:           "url",
		Port:          "port",
		Path:          "path",
		Group:         "group",
		PutCache:      mockPut,
		GetCache:      nil,
		GetUser:       mockGetUserByID,
		GetCreateUser: mockGetOrCreateUser,
	})
	s.Nil(l)
	s.Error(err)

	l, err = NewUserService(CreationOpts{
		URL:           "url",
		Port:          "port",
		Path:          "path",
		Group:         "group",
		PutCache:      mockPut,
		GetCache:      mockGet,
		GetUser:       nil,
		GetCreateUser: mockGetOrCreateUser,
	})
	s.Nil(l)
	s.Error(err)

	l, err = NewUserService(CreationOpts{
		URL:           "url",
		Port:          "port",
		Path:          "path",
		Group:         "group",
		PutCache:      mockPut,
		GetCache:      mockGet,
		GetUser:       mockGetUserByID,
		GetCreateUser: nil,
	})
	s.Nil(l)
	s.Error(err)
}

func (s *LDAPSuite) TestGetUserByToken() {
	ctx := context.Background()
	searchControl = searchUserSuccess
	putControl = putSuccess

	getControl = getErr
	u, err := s.um.GetUserByToken(ctx, "foo")
	s.Error(err)
	s.Nil(u)

	getControl = getValidUser
	u, err = s.um.GetUserByToken(ctx, "foo")
	s.NoError(err)
	s.Equal("foo", u.Username())

	getControl = getExpiredUser
	u, err = s.um.GetUserByToken(ctx, "foo")
	s.NoError(err)
	s.Equal("foo", u.Username())
	u, err = s.badGroupUm.GetUserByToken(ctx, "foo")
	s.Error(err)
	s.Nil(u)
	u, err = s.um.GetUserByToken(ctx, "badUser")
	s.Error(err)
	s.Nil(u)

	getControl = getMissingUser
	u, err = s.um.GetUserByToken(ctx, "foo")
	s.Error(err)
	s.Nil(u)

	getControl = getExpiredUser
	u, err = s.realConnUm.GetUserByToken(ctx, "foo")
	s.Error(err)
	s.Nil(u)
}

func (s *LDAPSuite) TestCreateUserToken() {
	searchControl = searchUserSuccess
	putControl = putSuccess
	token, err := s.um.CreateUserToken("foo", "badpassword")
	s.Error(err)

	token, err = s.um.CreateUserToken("nosuchuser", "")
	s.Error(err)

	token, err = s.um.CreateUserToken("foo", "hunter2")
	s.NoError(err)
	s.Equal("123456", token)
	s.Equal("foo", mockPutUser.Username())
	s.Equal("Foo Bar", mockPutUser.DisplayName())
	s.Equal("foo@example.com", mockPutUser.Email())

	token, err = s.badGroupUm.CreateUserToken("foo", "hunter2")
	s.Error(err)
	s.Empty(token)

	searchControl = searchUserErr
	token, err = s.um.CreateUserToken("foo", "hunter2")
	s.Error(err)
	s.Empty(token)

	searchControl = searchUserSuccess
	putControl = putErr
	token, err = s.um.CreateUserToken("foo", "hunter2")
	s.Error(err)
	s.Empty(token)

	token, err = s.realConnUm.CreateUserToken("foo", "hunter2")
	s.Empty(token)
	s.Error(err)
}

func (s *LDAPSuite) TestGetLoginHandler() {
	s.Nil(s.um.GetLoginHandler(""))
}

func (s *LDAPSuite) TestGetLoginCallbackHandler() {
	s.Nil(s.um.GetLoginCallbackHandler())
}

func (s *LDAPSuite) TestIsRedirect() {
	s.False(s.um.IsRedirect())
}

func (s *LDAPSuite) TestGetUser() {
	user, err := s.um.GetUserByID("foo")
	s.NoError(err)
	s.Equal("foo", user.Username())
}

func (s *LDAPSuite) TestGetOrCreateUser() {
	basicUser := gimlet.MakeBasicUser()
	user, err := s.um.GetOrCreateUser(basicUser)
	s.NoError(err)
	s.Equal("foo", user.Username())
}
