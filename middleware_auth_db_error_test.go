package gimlet

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mongodb/grip"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/mongo"
)

func TestIsTransientDBAuthError(t *testing.T) {
	for testName, testCase := range map[string]struct {
		err      error
		expected bool
	}{
		"NilErrorShouldNotMatch": {
			err:      nil,
			expected: false,
		},
		"CommandErrorWithReauthCodeShouldMatch": {
			err:      mongo.CommandError{Code: reauthenticationRequiredCode, Name: "ReauthenticationRequired"},
			expected: true,
		},
		"WrappedCommandErrorWithReauthCodeShouldMatch": {
			err:      errors.Wrap(mongo.CommandError{Code: reauthenticationRequiredCode}, "finding user by ID"),
			expected: true,
		},
		"FailedReauthAttemptFromDriverShouldMatch": {
			err:      fmt.Errorf("error reauthenticating: %w", errors.New("oidc callback failed")),
			expected: true,
		},
		"WrappedFailedReauthAttemptShouldMatch": {
			err:      errors.Wrap(fmt.Errorf("error reauthenticating: %w", errors.New("oidc callback failed")), "finding user by ID"),
			expected: true,
		},
		// The aggregate cannot be unwrapped back into a mongo.CommandError.
		"AggregatedMultiManagerErrorShouldMatch": {
			err: func() error {
				catcher := grip.NewBasicCatcher()
				catcher.Add(errors.New("user not found in cache with ID"))
				catcher.Add(errors.Wrap(mongo.CommandError{
					Code: reauthenticationRequiredCode,
					Name: reauthenticationRequiredName,
				}, "getting API-only user"))
				return errors.Wrap(catcher.Resolve(), "getting user by ID")
			}(),
			expected: true,
		},
		"UnrelatedCommandErrorShouldNotMatch": {
			err:      mongo.CommandError{Code: 11000, Name: "DuplicateKey"},
			expected: false,
		},
		"UserNotFoundErrorShouldNotMatch": {
			err:      errors.New("user does not exist"),
			expected: false,
		},
	} {
		t.Run(testName, func(t *testing.T) {
			assert.Equal(t, testCase.expected, isTransientDBAuthError(testCase.err))
		})
	}
}

func TestUserMiddlewareTransientDBAuthError(t *testing.T) {
	reauthErr := mongo.CommandError{Code: reauthenticationRequiredCode, Name: "ReauthenticationRequired"}
	user := &MockUser{ID: "service-user", APIKey: "DEADBEEF", APIOnly: true}

	headerConf := UserMiddlewareConfiguration{
		SkipCookie:     true,
		HeaderKeyName:  "Api-Key",
		HeaderUserName: "Api-User",
	}

	newHeaderRequest := func() *http.Request {
		req := httptest.NewRequest("GET", "http://localhost/bar", nil)
		req.Header.Set("Api-User", user.ID)
		req.Header.Set("Api-Key", user.APIKey)
		return req
	}

	t.Run("ReauthErrorOnHeaderCheckShouldReturnServiceUnavailableAndNotCallNext", func(t *testing.T) {
		um := &MockUserManager{Users: []*MockUser{user}, GetUserByIDError: reauthErr}
		m := UserMiddleware(t.Context(), um, headerConf)
		require.NotNil(t, m)
		rw := httptest.NewRecorder()

		nextCalled := false
		m.ServeHTTP(rw, newHeaderRequest(), func(rw http.ResponseWriter, r *http.Request) {
			nextCalled = true
		})

		assert.Equal(t, http.StatusServiceUnavailable, rw.Code)
		assert.False(t, nextCalled)
		assert.Contains(t, rw.Body.String(), "retry the request")
	})

	t.Run("FailedReauthAttemptOnHeaderCheckShouldReturnServiceUnavailable", func(t *testing.T) {
		um := &MockUserManager{
			Users:            []*MockUser{user},
			GetUserByIDError: errors.Wrap(fmt.Errorf("error reauthenticating: %w", errors.New("token expired")), "finding user by ID"),
		}
		m := UserMiddleware(t.Context(), um, headerConf)
		rw := httptest.NewRecorder()

		m.ServeHTTP(rw, newHeaderRequest(), func(rw http.ResponseWriter, r *http.Request) {
			rw.WriteHeader(http.StatusOK)
		})

		assert.Equal(t, http.StatusServiceUnavailable, rw.Code)
	})

	// An unknown user is not a server-side failure.
	t.Run("UnknownUserShouldStillFallThroughWithoutUser", func(t *testing.T) {
		um := &MockUserManager{Users: []*MockUser{user}}
		m := UserMiddleware(t.Context(), um, headerConf)
		req := httptest.NewRequest("GET", "http://localhost/bar", nil)
		req.Header.Set("Api-User", "nonexistent")
		req.Header.Set("Api-Key", "whatever")
		rw := httptest.NewRecorder()

		m.ServeHTTP(rw, req, func(rw http.ResponseWriter, r *http.Request) {
			rw.WriteHeader(http.StatusOK)
			assert.Nil(t, GetUser(r.Context()))
		})

		assert.Equal(t, http.StatusOK, rw.Code)
	})

	t.Run("ValidAPIKeyShouldStillAuthenticate", func(t *testing.T) {
		um := &MockUserManager{Users: []*MockUser{user}}
		m := UserMiddleware(t.Context(), um, headerConf)
		rw := httptest.NewRecorder()

		var authenticated User
		m.ServeHTTP(rw, newHeaderRequest(), func(rw http.ResponseWriter, r *http.Request) {
			authenticated = GetUser(r.Context())
			rw.WriteHeader(http.StatusOK)
		})

		assert.Equal(t, http.StatusOK, rw.Code)
		require.NotNil(t, authenticated)
		assert.Equal(t, user.ID, authenticated.Username())
	})

	t.Run("ReauthErrorOnCookieCheckShouldReturnServiceUnavailable", func(t *testing.T) {
		um := &MockUserManager{Users: []*MockUser{user}, GetUserByTokenError: reauthErr}
		m := UserMiddleware(t.Context(), um, UserMiddlewareConfiguration{
			SkipHeaderCheck: true,
			CookieName:      "auth-token",
		})
		req := httptest.NewRequest("GET", "http://localhost/bar", nil)
		req.AddCookie(&http.Cookie{Name: "auth-token", Value: "42"})
		rw := httptest.NewRecorder()

		nextCalled := false
		m.ServeHTTP(rw, req, func(rw http.ResponseWriter, r *http.Request) {
			nextCalled = true
		})

		assert.Equal(t, http.StatusServiceUnavailable, rw.Code)
		assert.False(t, nextCalled)
	})
}
