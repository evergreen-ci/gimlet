package gimlet

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBasicAuthenticator(t *testing.T) {
	assert := assert.New(t)

	assert.Implements((*Authenticator)(nil), &basicAuthenticator{})
	auth := NewBasicAuthenticator([]User{}, map[string]string{})
	assert.NotNil(auth)
	assert.NotNil(auth.(*basicAuthenticator).groups)
	assert.NotNil(auth.(*basicAuthenticator).users)
	assert.Len(auth.(*basicAuthenticator).groups, 0)
	assert.Len(auth.(*basicAuthenticator).users, 0)

	// constructor avoids nils
	auth = NewBasicAuthenticator(nil, nil)
	assert.NotNil(auth)
	assert.NotNil(auth.(*basicAuthenticator).groups)
	assert.NotNil(auth.(*basicAuthenticator).users)
	assert.Len(auth.(*basicAuthenticator).groups, 0)
	assert.Len(auth.(*basicAuthenticator).users, 0)

	// constructor avoids nils
	usr := NewBasicUser("id", "email", "key", []string{})
	auth = NewBasicAuthenticator([]User{usr}, nil)
	assert.NotNil(auth)
	assert.NotNil(auth.(*basicAuthenticator).groups)
	assert.NotNil(auth.(*basicAuthenticator).users)
	assert.Len(auth.(*basicAuthenticator).groups, 0)
	assert.Len(auth.(*basicAuthenticator).users, 1)

	// if a user exists then it should work
	assert.True(auth.CheckAuthenticated(usr))

	// a second user shouldn't validate
	usr2 := NewBasicUser("id2", "email", "key", []string{})
	assert.False(auth.CheckAuthenticated(usr2))
}
