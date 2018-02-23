package gimlet

import (
	"context"
	"net/http"

	"github.com/tychoish/gimlet/auth"
	"github.com/urfave/negroni"
)

type contextKey int

const (
	authHandlerKey contextKey = iota
	userManagerKey
)

func GetAuthenticator(ctx context.Context) auth.Authenticator {
	a, ok := safeGetAuthenticator(ctx)
	if !ok {
		panic("authenticator not attached")
	}

	return a
}

func safeGetAuthenticator(ctx context.Context) (auth.Authenticator, bool) {
	a := ctx.Value(authHandlerKey)
	if a == nil {
		return nil, false
	}

	amgr, ok := a.(auth.Authenticator)
	if !ok {
		return nil, false
	}

	return amgr, true
}

func GetUserManager(ctx context.Context) auth.UserManager {
	m, ok := safeGetUserManager(ctx)
	if !ok {
		panic("user manager not attached")
	}
	return m
}

func safeGetUserManager(ctx context.Context) (auth.UserManager, bool) {
	m := ctx.Value(userManagerKey)
	if m == nil {
		return nil, false
	}

	umgr, ok := m.(auth.UserManager)
	if !ok {
		return nil, false
	}

	return umgr, true
}

// NewAuthenticationHandler produces middleware that attaches
// Authenticator and UserManager instances to the request context,
// enabling the use of GetAuthenticator and GetUserManager accessors.
//
// While your application can have multiple authentication mechanisms,
// a single request can only have one authentication provider
// associated with it.
func NewAuthenticationHandler(a auth.Provider) negroni.Handler {
	return &authHandler{provider: a}
}

type authHandler struct {
	provider auth.Provider
}

func (a *authHandler) ServeHTTP(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	ctx := r.Context()
	ctx = context.WithValue(ctx, authHandlerKey, a.provider.Authenticator())
	ctx = context.WithValue(ctx, userManagerKey, a.provider.UserManager())

	r = r.WithContext(ctx)
	next(rw, r)
}

func NewAccessRequirement(role string) negroni.Handler { return &requiredAccess{role: role} }

type requiredAccess struct {
	role string
}

func (ra *requiredAccess) ServeHTTP(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	ctx := r.Context()

	authenticator, ok := safeGetAuthenticator(ctx)
	if !ok {
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	userMgr, ok := safeGetUserManager(ctx)
	if !ok {
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	// TODO get user from request here!
	user, err := authenticator.GetUserFromRequest(userMgr, r)
	if err != nil {
		writeResponse(TEXT, rw, http.StatusUnauthorized, []byte(err.Error()))
	}

	if !authenticator.CheckGroupAccess(user, ra.role) {
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	// log?

	next(rw, r)
}

func NewRequireAuthHandler() negroni.Handler { return &requireAuthHandler{} }

type requireAuthHandler struct{}

func (_ *requireAuthHandler) ServeHTTP(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	ctx := r.Context()

	authenticator, ok := safeGetAuthenticator(ctx)
	if !ok {
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	userMgr, ok := safeGetUserManager(ctx)
	if !ok {
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	user, err := authenticator.GetUserFromRequest(userMgr, r)
	if err != nil {
		writeResponse(TEXT, rw, http.StatusUnauthorized, []byte(err.Error()))
	}

	if !authenticator.CheckAuthenticated(user) {
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	next(rw, r)
}
