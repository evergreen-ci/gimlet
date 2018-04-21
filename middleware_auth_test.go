package gimlet

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/evergreen-ci/gimlet/auth"
	"github.com/evergreen-ci/gimlet/mock"
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

func TestAuthMiddlewareConstructors(t *testing.T) {
	assert := assert.New(t) // nolint
	provider := &mock.Provider{}

	ah, ok := NewAuthenticationHandler(provider).(*authHandler)
	assert.True(ok)
	assert.NotNil(ah)
	assert.Equal(provider, ah.provider)

	ra, ok := NewAccessRequirement("foo").(*requiredAccess)
	assert.True(ok)
	assert.NotNil(ra)
	assert.Equal("foo", ra.role)

	rah, ok := NewRequireAuthHandler().(*requireAuthHandler)
	assert.True(ok)
	assert.NotNil(rah)
}

func TestAuthRequiredBehavior(t *testing.T) {
	assert := assert.New(t) // nolint
	buf := []byte{}
	body := bytes.NewBuffer(buf)

	counter := 0
	next := func(rw http.ResponseWriter, r *http.Request) {
		counter++
		rw.WriteHeader(http.StatusOK)
	}

	authenticator := &mock.Authenticator{
		UserToken:               "test",
		CheckAuthenticatedState: map[string]bool{},
	}
	user := &mock.User{
		ID: "test-user",
	}
	usermanager := &mock.UserManager{
		TokenToUsers: map[string]auth.User{},
	}

	ra := NewRequireAuthHandler()

	// start without any context setup
	//
	req := httptest.NewRequest("GET", "http://localhost/bar", body)
	rw := httptest.NewRecorder()
	ra.ServeHTTP(rw, req, next)

	// there's nothing attached to the context, so it's a 401
	assert.Equal(http.StatusUnauthorized, rw.Code)
	assert.Equal(0, counter)

	// try again with an authenticator...
	//
	req = httptest.NewRequest("GET", "http://localhost/bar", body)
	rw = httptest.NewRecorder()
	rw = httptest.NewRecorder()
	ctx := req.Context()
	ctx = auth.SetAuthenticator(ctx, authenticator)
	req = req.WithContext(ctx)

	ra.ServeHTTP(rw, req, next)

	// just the authenticator isn't enough
	assert.Equal(http.StatusUnauthorized, rw.Code)
	assert.Equal(0, counter)

	// try with a user manager
	//
	req = httptest.NewRequest("GET", "http://localhost/bar", body)
	rw = httptest.NewRecorder()
	ctx = req.Context()
	ctx = auth.SetAuthenticator(ctx, authenticator)
	ctx = auth.SetUserManager(ctx, usermanager)
	req = req.WithContext(ctx)
	ra.ServeHTTP(rw, req, next)

	// just the authenticator isn't users aren't enough
	assert.Equal(http.StatusUnauthorized, rw.Code)
	assert.Equal(0, counter)

	// now set up the user
	//
	usermanager.TokenToUsers[authenticator.UserToken] = user

	req = httptest.NewRequest("GET", "http://localhost/bar", body)
	rw = httptest.NewRecorder()
	ctx = req.Context()
	ctx = auth.SetAuthenticator(ctx, authenticator)
	ctx = auth.SetUserManager(ctx, usermanager)
	req = req.WithContext(ctx)

	ra.ServeHTTP(rw, req, next)

	// shouldn't work because the authenticator doesn't have the user registered
	assert.Equal(http.StatusUnauthorized, rw.Code)
	assert.Equal(0, counter)

	// register the user
	//
	authenticator.CheckAuthenticatedState[user.Username()] = true
	req = httptest.NewRequest("GET", "http://localhost/bar", body)
	rw = httptest.NewRecorder()
	ctx = req.Context()
	ctx = auth.SetAuthenticator(ctx, authenticator)
	ctx = auth.SetUserManager(ctx, usermanager)
	req = req.WithContext(ctx)

	ra.ServeHTTP(rw, req, next)

	assert.Equal(http.StatusOK, rw.Code)
	assert.Equal(1, counter)

}

func TestAuthAttachWrapper(t *testing.T) {
	assert := assert.New(t) // nolint
	buf := []byte{}
	body := bytes.NewBuffer(buf)

	req := httptest.NewRequest("GET", "http://localhost/bar", body)
	rw := httptest.NewRecorder()
	counter := 0
	authenticator := &mock.Authenticator{
		UserToken:               "test",
		CheckAuthenticatedState: map[string]bool{},
	}
	usermanager := &mock.UserManager{
		TokenToUsers: map[string]auth.User{},
	}

	provider := &mock.Provider{
		MockAuthenticator: authenticator,
		MockUserManager:   usermanager,
	}

	ah := NewAuthenticationHandler(provider)
	assert.NotNil(ah)
	assert.Equal(ah.(*authHandler).provider, provider)

	baseCtx := context.Background()
	req = req.WithContext(baseCtx)

	assert.Exactly(req.Context(), baseCtx)

	ah.ServeHTTP(rw, req, func(nrw http.ResponseWriter, r *http.Request) {
		rctx := r.Context()
		assert.NotEqual(rctx, baseCtx)

		um, ok := auth.GetUserManager(rctx)
		assert.True(ok)
		assert.Equal(usermanager, um)

		ath, ok := auth.GetAuthenticator(rctx)
		assert.True(ok)
		assert.Equal(authenticator, ath)

		counter++
		nrw.WriteHeader(http.StatusTeapot)
	})

	assert.Equal(1, counter)
	assert.Equal(http.StatusTeapot, rw.Code)
}
