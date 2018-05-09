package gimlet

import (
	"context"

	"github.com/evergreen-ci/gimlet/auth"
	"github.com/urfave/negroni"
)

// Middleware is a local alias for negroni.Handler types.
type Middleware negroni.Handler

type contextKey int

const (
	requestIDKey contextKey = iota
	loggerKey
	startAtKey
	authHandlerKey
	userManagerKey
	userKey
)

func SetAuthenticator(ctx context.Context, a auth.Authenticator) context.Context {
	return context.WithValue(ctx, authHandlerKey, a)
}
func GetAuthenticator(ctx context.Context) (auth.Authenticator, bool) {
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

func SetUserManager(ctx context.Context, um auth.UserManager) context.Context {
	return context.WithValue(ctx, userManagerKey, um)
}
func GetUserManager(ctx context.Context) (auth.UserManager, bool) {
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
