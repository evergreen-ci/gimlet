package gimlet

import (
	"context"
	"net/http"
	"net/url"

	"github.com/evergreen-ci/gimlet/auth"
	"github.com/mongodb/grip"
	"github.com/mongodb/grip/message"
)

type UserMiddlewareConfiguration struct {
	SkipCookie      bool
	SkipHeaderCheck bool
	CookieName      string
	HeaderUserName  string
	HeaderKeyName   string
}

func setUserForRequest(r *http.Request, u auth.User) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), userKey, u))
}

func GetUser(ctx context.Context) (auth.User, bool) {
	u := ctx.Value(userKey)
	if u == nil {
		return nil, false
	}

	usr, ok := u.(auth.User)
	if !ok {
		return nil, false
	}

	return usr, true
}

type userMiddleware struct {
	conf    UserMiddlewareConfiguration
	manager auth.UserManager
}

func UserMiddleware(um auth.UserManager, conf UserMiddlewareConfiguration) Middleware {
	return &userMiddleware{
		conf:    conf,
		manager: um,
	}
}

func (u *userMiddleware) ServeHTTP(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	var err error

	if !u.conf.SkipCookie {
		var token string

		// Grab token auth from cookies
		for _, cookie := range r.Cookies() {
			if cookie.Name == u.conf.CookieName {
				if token, err = url.QueryUnescape(cookie.Value); err == nil {
					break
				}
			}
		}

		// set the user, preferring the cookie, maye change
		if len(token) > 0 {
			ctx := r.Context()
			usr, err := u.manager.GetUserByToken(ctx, token)

			if err != nil {
				// TODO fix this error report,
				grip.Infof("Error getting user %s: %+v", usr.Username(), err)
			} else {
				usr, err = u.manager.GetOrCreateUser(usr)
				// Get the user's full details from the DB or create them if they don't exists
				if err != nil {
					// TODO fix this error report, add context
					grip.Debug(message.WrapError(err, message.Fields{
						"message": "error looking up user",
						"user":    usr.Username(),
					}))
				} else {
					r = setUserForRequest(r, usr)
				}
			}
		}

	}

	if !u.conf.SkipHeaderCheck {
		var (
			authDataAPIKey string
			authDataName   string
		)

		// Grab API auth details from header
		if len(r.Header[u.conf.HeaderKeyName]) > 0 {
			authDataAPIKey = r.Header[u.conf.HeaderKeyName][0]
		}
		if len(r.Header[u.conf.HeaderUserName]) > 0 {
			authDataName = r.Header[u.conf.HeaderUserName][0]
		}

		if len(authDataAPIKey) > 0 {
			usr, err := u.manager.GetUserByID(authDataName)
			if u != nil && err == nil {
				if usr.GetAPIKey() != authDataAPIKey {
					http.Error(rw, "Unauthorized - invalid API key", http.StatusUnauthorized)
					return
				}
				r = setUserForRequest(r, usr)
			} else {
				// TODO fix this error report
				grip.Errorln("Error getting user:", err)
			}
		}

	}

	next(rw, r)
}
