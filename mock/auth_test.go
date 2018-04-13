package mock

import (
	"testing"

	"github.com/evergreen-ci/gimlet/auth"
	"github.com/stretchr/testify/assert"
)

func TestInterfacesAteImplemented(t *testing.T) {
	assert := assert.New(t)

	assert.Implements((*auth.Authenticator)(nil), &Authenticator{})
	assert.Implements((*auth.Provider)(nil), &Provider{})
	assert.Implements((*auth.UserManager)(nil), &UserManager{})
	assert.Implements((*auth.User)(nil), &User{})

}
