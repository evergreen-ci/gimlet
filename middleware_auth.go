package gimlet

import (
	"net/http"

	"github.com/evergreen-ci/gimlet/auth"
	"github.com/mongodb/grip"
	"github.com/mongodb/grip/message"
	"github.com/urfave/negroni"
)

type contextKey int

const (
	requestIDKey contextKey = iota
	loggerKey
	startAtKey
)

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
	ctx = auth.SetAuthenticator(ctx, a.provider.Authenticator())
	ctx = auth.SetUserManager(ctx, a.provider.UserManager())

	r = r.WithContext(ctx)
	next(rw, r)
}

// NewRoleRequired provides middlesware that requires a specific role
// to access a resource. This access is defined as a property of the
// user objects.
func NewRoleRequired(role string) negroni.Handler { return &requiredRole{role: role} }

type requiredRole struct {
	role string
}

func (rr *requiredRole) ServeHTTP(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	ctx := r.Context()

	authenticator, ok := auth.GetAuthenticator(ctx)
	if !ok {
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	userMgr, ok := auth.GetUserManager(ctx)
	if !ok {
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	user, err := authenticator.GetUserFromRequest(userMgr, r)
	if err != nil {
		writeResponse(TEXT, rw, http.StatusUnauthorized, []byte(err.Error()))
		return
	}

	if !auth.UserHasRole(user, rr.role) {
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	grip.Info(message.Fields{
		"path":          r.URL.Path,
		"remote":        r.RemoteAddr,
		"request":       GetRequestID(ctx),
		"user":          user.Username(),
		"user_roles":    user.Roles(),
		"required_role": rr.role,
	})

	next(rw, r)
}

// NewGroupMembershipRequired provides middleware that requires that
// users belong to a group to gain access to a resource. This is
// access is defined as a property of the authentication system.
func NewGroupMembershipRequired(name string) negroni.Handler { return &requiredGroup{group: name} }

type requiredGroup struct {
	group string
}

func (rg *requiredGroup) ServeHTTP(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	ctx := r.Context()

	authenticator, ok := auth.GetAuthenticator(ctx)
	if !ok {
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	userMgr, ok := auth.GetUserManager(ctx)
	if !ok {
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	user, err := authenticator.GetUserFromRequest(userMgr, r)
	if err != nil {
		writeResponse(TEXT, rw, http.StatusUnauthorized, []byte(err.Error()))
		return
	}

	if !authenticator.CheckGroupAccess(user, rg.group) {
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	grip.Info(message.Fields{
		"path":           r.URL.Path,
		"remote":         r.RemoteAddr,
		"request":        GetRequestID(ctx),
		"user":           user.Username(),
		"user_roles":     user.Roles(),
		"required_group": rg.group,
	})

	next(rw, r)
}

// NewRequireAuth provides middlesware that requires that users be
// authenticated generally to access the resource, but does no
// validation of their access.
func NewRequireAuthHandler() negroni.Handler { return &requireAuthHandler{} }

type requireAuthHandler struct{}

func (_ *requireAuthHandler) ServeHTTP(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	ctx := r.Context()

	authenticator, ok := auth.GetAuthenticator(ctx)
	if !ok {
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	userMgr, ok := auth.GetUserManager(ctx)
	if !ok {
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	user, err := authenticator.GetUserFromRequest(userMgr, r)
	if err != nil {
		writeResponse(TEXT, rw, http.StatusUnauthorized, []byte(err.Error()))
		return
	}

	if !authenticator.CheckAuthenticated(user) {
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	grip.Info(message.Fields{
		"path":       r.URL.Path,
		"remote":     r.RemoteAddr,
		"request":    GetRequestID(ctx),
		"user":       user.Username(),
		"user_roles": user.Roles(),
	})

	next(rw, r)
}
