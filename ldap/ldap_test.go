package ldap

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLDAPConstructorRequiresNonEmptyArgs(t *testing.T) {
	assert := assert.New(t)

	l, err := NewUserService(CreationOpts{"foo", "bar", "baz"})
	assert.NotNil(l)
	assert.NoError(err)

	l, err = NewUserService(CreationOpts{"", "bar", "baz"})
	assert.Nil(l)
	assert.Error(err)

	l, err = NewUserService(CreationOpts{"foo", "", "baz"})
	assert.Nil(l)
	assert.Error(err)

	l, err = NewUserService(CreationOpts{"foo", "bar", ""})
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
// 	l, err := NewUserService(CreationOpts{url, port, path})
// 	assert.NotNil(l)
// 	assert.NoError(err)
// 	assert.NoError(l.authenticate(user, password))
// 	assert.NoError(l.authorize(user, group))
// }
