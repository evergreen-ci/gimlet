package gimlet

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLDAPConstructorRequiresNonEmptyArgs(t *testing.T) {
	assert := assert.New(t)

	l, err := NewLDAPAuthenticator("foo", "bar", "baz")
	assert.NotNil(l)
	assert.NoError(err)

	l, err = NewLDAPAuthenticator("", "bar", "baz")
	assert.Nil(l)
	assert.Error(err)

	l, err = NewLDAPAuthenticator("foo", "", "baz")
	assert.Nil(l)
	assert.Error(err)

	l, err = NewLDAPAuthenticator("foo", "bar", "")
	assert.Nil(l)
	assert.Error(err)
}

// This test requires an LDAP server. Uncomment to test.
//
// func TestLDAPIntegration(t *testing.T) {
// 	const (
// 		url      = ""
// 		port     = ""
// 		path     = ""
// 		user     = ""
// 		password = ""
// 		group    = ""
// 	)
// 	assert := assert.New(t)
// 	l, err := NewLDAPAuthenticator(url, port, path)
// 	assert.NotNil(l)
// 	assert.NoError(err)
// 	assert.NoError(l.Authenticate(user, password))
// 	assert.NoError(l.Authorize(user, group))
// }
