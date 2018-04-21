package auth

import (
	"context"
)

type contextKey string

const (
	authHandlerKey contextKey = "auth-handler"
	userManagerKey            = "user-manager"
)

func SetAuthenticator(ctx context.Context, a Authenticator) context.Context {
	return context.WithValue(ctx, authHandlerKey, a)
}

func SetUserManager(ctx context.Context, um UserManager) context.Context {
	return context.WithValue(ctx, userManagerKey, um)
}

func GetAuthenticator(ctx context.Context) (Authenticator, bool) {
	a := ctx.Value(authHandlerKey)
	if a == nil {
		return nil, false
	}

	amgr, ok := a.(Authenticator)
	if !ok {
		return nil, false
	}

	return amgr, true
}

func GetUserManager(ctx context.Context) (UserManager, bool) {
	m := ctx.Value(userManagerKey)
	if m == nil {
		return nil, false
	}

	umgr, ok := m.(UserManager)
	if !ok {
		return nil, false
	}

	return umgr, true
}
