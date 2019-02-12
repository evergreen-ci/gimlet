package gimlet

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNaiveUserManager(t *testing.T) {
	assert := assert.New(t)
	assert.Implements((*UserManager)(nil), &NaiveUserManager{})

	u, err := NewNaiveUserManager([]*NaiveUser{
		{
			User:         "foo",
			Pass:         "bar",
			EmailAddress: "baz",
		},
	})
	user, err := u.GetUserByToken(context.Background(), "0:baz:[56 88 246 34 48 172 60 145 95 48 12 102 67 18 198 63]")
	assert.NoError(err)
	assert.NotNil(user)
	assert.Equal("foo", user.Username())
	assert.Equal("baz", user.Email())

	user, err = u.GetUserByToken(context.Background(), "")
	assert.Error(err)
	assert.Nil(user)

	token, err := u.CreateUserToken("foo", "bar")
	assert.NoError(err)
	assert.Equal(token, "0:baz:[56 88 246 34 48 172 60 145 95 48 12 102 67 18 198 63]")

	assert.Nil(u.GetLoginHandler(""))
	assert.Nil(u.GetLoginCallbackHandler())
	assert.False(u.IsRedirect())

	user, err = u.GetUserByID("bar")
	assert.Error(err)
	assert.Nil(user)

	user, err = u.GetUserByID("foo")
	assert.NoError(err)
	assert.NotNil(user)
	assert.Equal("foo", user.Username())
	assert.Equal("baz", user.Email())

	newUser := &NaiveUser{User: "foo"}
	user, err = u.GetOrCreateUser(newUser)
	assert.NoError(err)
	assert.NotNil(user)
	assert.Equal("foo", user.Username())
	assert.Equal("baz", user.Email())

	newUser = &NaiveUser{User: "new_user", Pass: "password", EmailAddress: "email@example.com"}
	user, err = u.GetOrCreateUser(newUser)
	assert.NoError(err)
	assert.NotNil(user)
	assert.Equal("new_user", user.Username())
	assert.Equal("email@example.com", user.Email())

	assert.Error(u.ClearUser(newUser, false))
}
