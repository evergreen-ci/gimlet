package gimlet

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMultiUserManager(t *testing.T) {
	makeUser := func(n int) *MockUser {
		ns := fmt.Sprint(n)
		return &MockUser{
			ID:       "user" + ns,
			Password: "password" + ns,
			Token:    "token" + ns,
			Groups:   []string{"group" + ns},
		}
	}
	readWrite := func() *MockUserManager {
		return &MockUserManager{
			Users:                []*MockUser{makeUser(1), makeUser(2)},
			Redirect:             true,
			LoginHandler:         func(w http.ResponseWriter, r *http.Request) {},
			LoginCallbackHandler: func(w http.ResponseWriter, r *http.Request) {},
		}
	}
	readOnly := func() *MockUserManager {
		return &MockUserManager{
			Users:                []*MockUser{makeUser(1), makeUser(3)},
			Redirect:             true,
			LoginHandler:         func(http.ResponseWriter, *http.Request) {},
			LoginCallbackHandler: func(http.ResponseWriter, *http.Request) {},
		}
	}
	for testName, testCase := range map[string]func(t *testing.T, um UserManager, readWrite *MockUserManager, readOnly *MockUserManager){
		"GetUserByTokenSucceeds": func(t *testing.T, um UserManager, readWrite *MockUserManager, readOnly *MockUserManager) {
			u, err := um.GetUserByToken(t.Context(), makeUser(2).Token)
			require.NoError(t, err)
			assert.Equal(t, makeUser(2).Username(), u.Username())
		},
		"GetUserByTokenFails": func(t *testing.T, um UserManager, readWrite *MockUserManager, readOnly *MockUserManager) {
			readWrite.FailGetUserByToken = true
			u, err := um.GetUserByToken(t.Context(), makeUser(2).Token)
			assert.Error(t, err)
			assert.Nil(t, u)
		},
		"GetUserByTokenNonexistentFails": func(t *testing.T, um UserManager, readWrite *MockUserManager, readOnly *MockUserManager) {
			u, err := um.GetUserByToken(t.Context(), makeUser(4).Token)
			assert.Error(t, err)
			assert.Nil(t, u)
		},
		"GetUserByTokenTriesAllManagers": func(t *testing.T, um UserManager, readWrite *MockUserManager, readOnly *MockUserManager) {
			readWrite.FailGetUserByToken = true
			u, err := um.GetUserByToken(t.Context(), makeUser(1).Token)
			require.NoError(t, err)
			assert.Equal(t, makeUser(1).Username(), u.Username())
		},
		"GetUserByTokenTriesReadManagers": func(t *testing.T, um UserManager, readWrite *MockUserManager, readOnly *MockUserManager) {
			u, err := um.GetUserByToken(t.Context(), makeUser(3).Token)
			require.NoError(t, err)
			assert.Equal(t, makeUser(3).Username(), u.Username())
		},
		"GetUserByTokenPrioritizesReadWriteManagers": func(t *testing.T, um UserManager, readWrite *MockUserManager, readOnly *MockUserManager) {
			readOnly.FailGetUserByToken = true
			u, err := um.GetUserByToken(t.Context(), makeUser(1).Token)
			require.NoError(t, err)
			assert.Equal(t, makeUser(1).Username(), u.Username())
		},
		"GetUserByTokenFailsIfAllManagersFail": func(t *testing.T, um UserManager, readWrite *MockUserManager, readOnly *MockUserManager) {
			readWrite.FailGetUserByToken = true
			readOnly.FailGetUserByToken = true
			u, err := um.GetUserByToken(t.Context(), makeUser(1).Token)
			assert.Error(t, err)
			assert.Nil(t, u)
		},
		"GetUserByIDSucceeds": func(t *testing.T, um UserManager, readWrite *MockUserManager, readOnly *MockUserManager) {
			u, err := um.GetUserByID(t.Context(), makeUser(2).Username())
			require.NoError(t, err)
			assert.Equal(t, makeUser(2).Username(), u.Username())
		},
		"GetUserByIDFails": func(t *testing.T, um UserManager, readWrite *MockUserManager, readOnly *MockUserManager) {
			readWrite.FailGetUserByID = true
			u, err := um.GetUserByID(t.Context(), makeUser(2).Username())
			assert.Error(t, err)
			assert.Nil(t, u)
		},
		"GetUserByIDNonexistentFails": func(t *testing.T, um UserManager, readWrite *MockUserManager, readOnly *MockUserManager) {
			u, err := um.GetUserByID(t.Context(), makeUser(4).Username())
			assert.Error(t, err)
			assert.Nil(t, u)
		},
		"GetUserByIDTriesAllManagers": func(t *testing.T, um UserManager, readWrite *MockUserManager, readOnly *MockUserManager) {
			readWrite.FailGetUserByID = true
			u, err := um.GetUserByID(t.Context(), makeUser(1).Username())
			require.NoError(t, err)
			assert.Equal(t, makeUser(1).Username(), u.Username())
		},
		"GetUserByIDTriesReadManagers": func(t *testing.T, um UserManager, readWrite *MockUserManager, readOnly *MockUserManager) {
			readWrite.FailGetUserByID = true
			u, err := um.GetUserByID(t.Context(), makeUser(3).Username())
			require.NoError(t, err)
			assert.Equal(t, makeUser(3).Username(), u.Username())
		},
		"GetUserByIDPrioritizesReadWriteManagers": func(t *testing.T, um UserManager, readWrite *MockUserManager, readOnly *MockUserManager) {
			readOnly.FailGetUserByID = true
			u, err := um.GetUserByID(t.Context(), makeUser(1).Username())
			require.NoError(t, err)
			assert.Equal(t, makeUser(1).Username(), u.Username())
		},
		"GetUserByIDFailsIfAllManagersFail": func(t *testing.T, um UserManager, readWrite *MockUserManager, readOnly *MockUserManager) {
			readWrite.FailGetUserByID = true
			readOnly.FailGetUserByID = true
			u, err := um.GetUserByID(t.Context(), makeUser(1).Username())
			assert.Error(t, err)
			assert.Nil(t, u)
		},
		"GetGroupsForUserSucceeds": func(t *testing.T, um UserManager, readWrite *MockUserManager, readOnly *MockUserManager) {
			groups, err := um.GetGroupsForUser(makeUser(2).Username())
			require.NoError(t, err)
			assert.Equal(t, makeUser(2).Groups, groups)
		},
		"GetGroupsForUserFails": func(t *testing.T, um UserManager, readWrite *MockUserManager, readOnly *MockUserManager) {
			readWrite.FailGetGroupsForUser = true
			groups, err := um.GetGroupsForUser(makeUser(2).Username())
			assert.Error(t, err)
			assert.Empty(t, groups)
		},
		"GetGroupsForUserNonexistentFails": func(t *testing.T, um UserManager, readWrite *MockUserManager, readOnly *MockUserManager) {
			groups, err := um.GetGroupsForUser(makeUser(4).Username())
			assert.Error(t, err)
			assert.Empty(t, groups)
		},
		"GetGroupsForUserTriesAllManagers": func(t *testing.T, um UserManager, readWrite *MockUserManager, readOnly *MockUserManager) {
			readWrite.FailGetGroupsForUser = true
			groups, err := um.GetGroupsForUser(makeUser(1).Username())
			require.NoError(t, err)
			assert.Equal(t, makeUser(1).Groups, groups)
		},
		"GetGroupsForUserTriesReadManagers": func(t *testing.T, um UserManager, readWrite *MockUserManager, readOnly *MockUserManager) {
			groups, err := um.GetGroupsForUser(makeUser(3).Username())
			require.NoError(t, err)
			assert.Equal(t, makeUser(3).Groups, groups)
		},
		"GetGroupsForUserPrioritizesReadWriteManagers": func(t *testing.T, um UserManager, readWrite *MockUserManager, readOnly *MockUserManager) {
			readOnly.FailGetGroupsForUser = true
			groups, err := um.GetGroupsForUser(makeUser(1).Username())
			require.NoError(t, err)
			assert.Equal(t, makeUser(1).Groups, groups)
		},
		"GetGroupsForUserFailsIfAllManagersFail": func(t *testing.T, um UserManager, readWrite *MockUserManager, readOnly *MockUserManager) {
			readWrite.FailGetGroupsForUser = true
			readOnly.FailGetGroupsForUser = true
			u, err := um.GetGroupsForUser(makeUser(1).Username())
			assert.Error(t, err)
			assert.Empty(t, u)
		},
		"ReauthorizeUserSucceeds": func(t *testing.T, um UserManager, readWrite *MockUserManager, readOnly *MockUserManager) {
			assert.NoError(t, um.ReauthorizeUser(t.Context(), makeUser(1)))
		},
		"ReauthorizeUserIgnoresReadOnlyUserManagers": func(t *testing.T, um UserManager, readWrite *MockUserManager, readOnly *MockUserManager) {
			assert.Error(t, um.ReauthorizeUser(t.Context(), makeUser(3)))
			readOnly.FailReauthorizeUser = true
			assert.NoError(t, um.ReauthorizeUser(t.Context(), makeUser(1)))
		},
		"ReauthorizeUserNonexistentFails": func(t *testing.T, um UserManager, readWrite *MockUserManager, readOnly *MockUserManager) {
			assert.Error(t, um.ReauthorizeUser(t.Context(), makeUser(4)))
		},
		"ReauthorizeUserFails": func(t *testing.T, um UserManager, readWrite *MockUserManager, readOnly *MockUserManager) {
			readWrite.FailReauthorizeUser = true
			assert.Error(t, um.ReauthorizeUser(t.Context(), makeUser(1)))
		},
		"CreateUserTokenSucceeds": func(t *testing.T, um UserManager, readWrite *MockUserManager, readOnly *MockUserManager) {
			user := makeUser(4)
			token, err := um.CreateUserToken(t.Context(), user.Username(), user.Password)
			require.NoError(t, err)
			assert.Equal(t, mockUserToken(user.Username(), user.Password), token)
		},
		"CreateUserTokenIgnoresReadOnlyUserManagers": func(t *testing.T, um UserManager, readWrite *MockUserManager, readOnly *MockUserManager) {
			user := makeUser(4)
			readOnly.FailCreateUserToken = true
			token, err := um.CreateUserToken(t.Context(), user.Username(), user.Password)
			require.NoError(t, err)
			assert.Equal(t, mockUserToken(user.Username(), user.Password), token)
		},
		"CreateUserTokenFails": func(t *testing.T, um UserManager, readWrite *MockUserManager, readOnly *MockUserManager) {
			user := makeUser(4)
			readWrite.FailCreateUserToken = true
			token, err := um.CreateUserToken(t.Context(), user.Username(), user.Password)
			assert.Error(t, err)
			assert.Empty(t, token)
		},
		"GetOrCreateUserSucceeds": func(t *testing.T, um UserManager, readWrite *MockUserManager, readOnly *MockUserManager) {
			user := makeUser(4)
			u, err := um.GetOrCreateUser(t.Context(), user)
			require.NoError(t, err)
			assert.Equal(t, user.Username(), u.Username())
		},
		"GetOrCreateUserIgnoresReadOnlyUserManagers": func(t *testing.T, um UserManager, readWrite *MockUserManager, readOnly *MockUserManager) {
			user := makeUser(4)
			readOnly.FailGetOrCreateUser = true
			u, err := um.GetOrCreateUser(t.Context(), user)
			require.NoError(t, err)
			assert.Equal(t, user.Username(), u.Username())
		},
		"GetOrCreateUserFails": func(t *testing.T, um UserManager, readWrite *MockUserManager, readOnly *MockUserManager) {
			user := makeUser(4)
			readWrite.FailGetOrCreateUser = true
			u, err := um.GetOrCreateUser(t.Context(), user)
			assert.Error(t, err)
			assert.Nil(t, u)
		},
		"ClearUserSucceeds": func(t *testing.T, um UserManager, readWrite *MockUserManager, readOnly *MockUserManager) {
			user := makeUser(4)
			assert.NoError(t, um.ClearUser(t.Context(), user, false))
		},
		"ClearUserIgnoresReadOnlyUserManagers": func(t *testing.T, um UserManager, readWrite *MockUserManager, readOnly *MockUserManager) {
			user := makeUser(4)
			readOnly.FailClearUser = true
			assert.NoError(t, um.ClearUser(t.Context(), user, false))
		},
		"ClearUserFails": func(t *testing.T, um UserManager, readWrite *MockUserManager, readOnly *MockUserManager) {
			user := makeUser(4)
			readWrite.FailClearUser = true
			assert.Error(t, um.ClearUser(t.Context(), user, false))
		},
		"GetLoginHandlerSucceeds": func(t *testing.T, um UserManager, readWrite *MockUserManager, readOnly *MockUserManager) {
			h := um.GetLoginHandler("")
			assert.NotNil(t, h)
		},
		"GetLoginHandlerIgnoresReadOnlyUserManagers": func(t *testing.T, um UserManager, readWrite *MockUserManager, readOnly *MockUserManager) {
			readOnly.LoginHandler = nil
			h := um.GetLoginHandler("")
			assert.NotNil(t, h)
		},
		"GetLoginHandlerNil": func(t *testing.T, um UserManager, readWrite *MockUserManager, readOnly *MockUserManager) {
			readWrite.LoginHandler = nil
			h := um.GetLoginHandler("")
			assert.Nil(t, h)
		},
		"GetLoginCallbackHandlerSucceeds": func(t *testing.T, um UserManager, readWrite *MockUserManager, readOnly *MockUserManager) {
			h := um.GetLoginCallbackHandler()
			assert.NotNil(t, h)
		},
		"GetLoginCallbackHandlerIgnoresReadOnlyUserManagers": func(t *testing.T, um UserManager, readWrite *MockUserManager, readOnly *MockUserManager) {
			readOnly.LoginCallbackHandler = nil
			h := um.GetLoginCallbackHandler()
			assert.NotNil(t, h)
		},
		"GetLoginCallbackHandlerFails": func(t *testing.T, um UserManager, readWrite *MockUserManager, readOnly *MockUserManager) {
			readWrite.LoginCallbackHandler = nil
			h := um.GetLoginCallbackHandler()
			assert.Nil(t, h)
		},
		"IsRedirectTrue": func(t *testing.T, um UserManager, readWrite *MockUserManager, readOnly *MockUserManager) {
			assert.True(t, um.IsRedirect())
		},
		"IsRedirectIgnoresReadOnlyUserManagers": func(t *testing.T, um UserManager, readWrite *MockUserManager, readOnly *MockUserManager) {
			readOnly.Redirect = false
			assert.True(t, um.IsRedirect())
		},
		"IsRedirectFalse": func(t *testing.T, um UserManager, readWrite *MockUserManager, readOnly *MockUserManager) {
			readWrite.Redirect = false
			assert.False(t, um.IsRedirect())
		},
		// "": func(t *testing.T, um UserManager, readWrite *MockUserManager, readOnly *MockUserManager) {},
	} {
		t.Run(testName, func(t *testing.T) {
			rw := readWrite()
			ro := readOnly()
			um := NewMultiUserManager([]UserManager{rw}, []UserManager{ro})
			testCase(t, um, rw, ro)
		})
	}
}
