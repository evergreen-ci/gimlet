package gimlet

import (
	"context"
	"testing"

	"github.com/evergreen-ci/gimlet/auth"
	"github.com/stretchr/testify/assert"
)

func TestMiddlewareValueAccessors(t *testing.T) {
	assert := assert.New(t)
	ctx := context.Background()

	a, ok := auth.GetAuthenticator(ctx)
	assert.False(ok)
	assert.Nil(a)

	userm, ok := auth.GetUserManager(ctx)
	assert.False(ok)
	assert.Nil(userm)

	var idone, idtwo int
	idone = getNumber()
	assert.Equal(0, idtwo)
	assert.True(idone > 0)
	assert.NotPanics(func() { idtwo = GetRequestID(ctx) })
	assert.True(idone > idtwo)
	assert.Equal(-1, idtwo)
}
