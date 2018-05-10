package gimlet

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInterfaceCompliance(t *testing.T) {
	assert := assert.New(t)

	assert.Implements((*User)(nil), &basicUser{})
	assert.Implements((*Authenticator)(nil), &basicAuthenticator{})
}
