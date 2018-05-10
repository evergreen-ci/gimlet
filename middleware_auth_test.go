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

	a, ok := GetAuthenticator(ctx)
	assert.False(ok)
	assert.Nil(a)

	userm, ok := GetUserManager(ctx)
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
	authenticator := &mock.Authenticator{}
	usermanager := &mock.UserManager{}

	ah, ok := NewAuthenticationHandler(authenticator, usermanager).(*authHandler)
	assert.True(ok)
	assert.NotNil(ah)
	assert.Equal(authenticator, ah.auth)
	assert.Equal(usermanager, ah.um)

	ra, ok := NewRoleRequired("foo").(*requiredRole)
	assert.True(ok)
	assert.NotNil(ra)
	assert.Equal("foo", ra.role)

	rg, ok := NewGroupMembershipRequired("foo").(*requiredGroup)
	assert.True(ok)
	assert.NotNil(rg)
	assert.Equal("foo", rg.group)

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
	ctx = SetAuthenticator(ctx, authenticator)
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
	ctx = SetAuthenticator(ctx, authenticator)
	ctx = SetUserManager(ctx, usermanager)
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
	ctx = SetAuthenticator(ctx, authenticator)
	ctx = SetUserManager(ctx, usermanager)
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
	ctx = SetAuthenticator(ctx, authenticator)
	ctx = SetUserManager(ctx, usermanager)
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

	ah := NewAuthenticationHandler(authenticator, usermanager)
	assert.NotNil(ah)
	assert.Equal(ah.(*authHandler).um, usermanager)
	assert.Equal(ah.(*authHandler).auth, authenticator)

	baseCtx := context.Background()
	req = req.WithContext(baseCtx)

	assert.Exactly(req.Context(), baseCtx)

	ah.ServeHTTP(rw, req, func(nrw http.ResponseWriter, r *http.Request) {
		rctx := r.Context()
		assert.NotEqual(rctx, baseCtx)

		um, ok := GetUserManager(rctx)
		assert.True(ok)
		assert.Equal(usermanager, um)

		ath, ok := GetAuthenticator(rctx)
		assert.True(ok)
		assert.Equal(authenticator, ath)

		counter++
		nrw.WriteHeader(http.StatusTeapot)
	})

	assert.Equal(1, counter)
	assert.Equal(http.StatusTeapot, rw.Code)
}

func TestRoleRestrictedAccessMiddleware(t *testing.T) {
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
		GroupUserMapping:        map[string]string{},
	}
	user := &mock.User{
		ID:        "test-user",
		RoleNames: []string{"staff"},
	}
	usermanager := &mock.UserManager{
		TokenToUsers: map[string]auth.User{},
	}

	ra := NewRoleRequired("sudo")

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
	ctx = SetAuthenticator(ctx, authenticator)
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
	ctx = SetAuthenticator(ctx, authenticator)
	ctx = SetUserManager(ctx, usermanager)
	req = req.WithContext(ctx)
	ra.ServeHTTP(rw, req, next)

	// just the authenticator isn't users aren't enough
	assert.Equal(http.StatusUnauthorized, rw.Code)
	assert.Equal(0, counter)

	// now set up the user (which is defined with the wrong role, so won't work)
	//
	usermanager.TokenToUsers[authenticator.UserToken] = user

	req = httptest.NewRequest("GET", "http://localhost/bar", body)
	rw = httptest.NewRecorder()
	ctx = req.Context()
	ctx = SetAuthenticator(ctx, authenticator)
	ctx = SetUserManager(ctx, usermanager)
	req = req.WithContext(ctx)

	ra.ServeHTTP(rw, req, next)

	// shouldn't work because the authenticator doesn't have the user registered
	assert.Equal(http.StatusUnauthorized, rw.Code)
	assert.Equal(0, counter)

	// make the user have the right access
	//
	user.RoleNames = []string{"sudo"}

	req = httptest.NewRequest("GET", "http://localhost/bar", body)
	rw = httptest.NewRecorder()
	ctx = req.Context()
	ctx = SetAuthenticator(ctx, authenticator)
	ctx = SetUserManager(ctx, usermanager)
	req = req.WithContext(ctx)

	ra.ServeHTTP(rw, req, next)

	assert.Equal(http.StatusOK, rw.Code)
	assert.Equal(1, counter)
}

func TestGroupAccessRequired(t *testing.T) {
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
		GroupUserMapping: map[string]string{
			"test-user": "staff",
		},
	}
	user := &mock.User{
		ID: "test-user",
	}
	usermanager := &mock.UserManager{
		TokenToUsers: map[string]auth.User{},
	}

	ra := NewGroupMembershipRequired("sudo")

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
	ctx = SetAuthenticator(ctx, authenticator)
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
	ctx = SetAuthenticator(ctx, authenticator)
	ctx = SetUserManager(ctx, usermanager)
	req = req.WithContext(ctx)
	ra.ServeHTTP(rw, req, next)

	// just the authenticator isn't users aren't enough
	assert.Equal(http.StatusUnauthorized, rw.Code)
	assert.Equal(0, counter)

	// now set up the user (which has the wrong access defined)
	//
	usermanager.TokenToUsers[authenticator.UserToken] = user

	req = httptest.NewRequest("GET", "http://localhost/bar", body)
	rw = httptest.NewRecorder()
	ctx = req.Context()
	ctx = SetAuthenticator(ctx, authenticator)
	ctx = SetUserManager(ctx, usermanager)
	req = req.WithContext(ctx)

	ra.ServeHTTP(rw, req, next)

	// shouldn't work because the authenticator doesn't have the user registered
	assert.Equal(http.StatusUnauthorized, rw.Code)
	assert.Equal(0, counter)

	// make the user have the right access
	//
	authenticator.GroupUserMapping["test-user"] = "sudo"

	req = httptest.NewRequest("GET", "http://localhost/bar", body)
	rw = httptest.NewRecorder()
	ctx = req.Context()
	ctx = SetAuthenticator(ctx, authenticator)
	ctx = SetUserManager(ctx, usermanager)
	req = req.WithContext(ctx)

	ra.ServeHTTP(rw, req, next)

	assert.Equal(http.StatusOK, rw.Code)
	assert.Equal(1, counter)
}
