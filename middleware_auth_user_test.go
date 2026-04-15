package gimlet

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/evergreen-ci/negroni"
	"github.com/golang-jwt/jwt/v4"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUserMiddleware(t *testing.T) {
	user := &MockUser{
		ID:     "sam-i-am",
		APIKey: "DEADBEEF",
		Token:  "42",
	}
	serviceUser := &MockUser{
		ID:      "service-user",
		APIKey:  "BEEFDEAD",
		APIOnly: true,
	}
	um := &MockUserManager{Users: []*MockUser{user, serviceUser}}

	for name, testCase := range map[string]func(*testing.T){
		"Constructor": func(t *testing.T) {
			m := UserMiddleware(t.Context(), um, UserMiddlewareConfiguration{})
			require.NotNil(t, m)
			assert.Implements(t, (*Middleware)(nil), m)
			assert.Implements(t, (*negroni.Handler)(nil), m)
			assert.Equal(t, m.(*userMiddleware).conf, UserMiddlewareConfiguration{})
			assert.Equal(t, m.(*userMiddleware).manager, um)
		},
		"NothingEnabled": func(t *testing.T) {
			m := UserMiddleware(t.Context(), um, UserMiddlewareConfiguration{SkipHeaderCheck: true, SkipCookie: true})
			require.NotNil(t, m)
			req := httptest.NewRequest("GET", "http://localhost/bar", nil)
			rw := httptest.NewRecorder()

			next := func(rw http.ResponseWriter, r *http.Request) {
				rw.WriteHeader(http.StatusOK)
			}

			m.ServeHTTP(rw, req, next)
			assert.Equal(t, http.StatusOK, rw.Code)
			rusr := GetUser(req.Context())
			assert.Nil(t, rusr)
		},
		"EnabledNotConfigured": func(t *testing.T) {
			for _, conf := range []UserMiddlewareConfiguration{
				{SkipHeaderCheck: true, SkipCookie: false},
				{SkipHeaderCheck: false, SkipCookie: true},
				{SkipHeaderCheck: false, SkipCookie: false},
			} {
				m := UserMiddleware(t.Context(), um, conf)
				require.NotNil(t, m)
				req := httptest.NewRequest("GET", "http://localhost/bar", nil)
				rw := httptest.NewRecorder()
				next := func(rw http.ResponseWriter, r *http.Request) {
					rw.WriteHeader(http.StatusOK)
				}

				m.ServeHTTP(rw, req, next)
				assert.Equal(t, http.StatusOK, rw.Code)

				rusr := GetUser(req.Context())
				assert.Nil(t, rusr)
			}
		},
		"HeaderCheck": func(t *testing.T) {
			conf := UserMiddlewareConfiguration{
				SkipHeaderCheck: false,
				SkipCookie:      true,
				HeaderUserName:  "api-user",
				HeaderKeyName:   "api-key",
			}
			m := UserMiddleware(t.Context(), um, conf)
			require.NotNil(t, m)

			req := httptest.NewRequest("GET", "http://localhost/bar", nil)
			req.Header[conf.HeaderUserName] = []string{user.ID}
			req.Header[conf.HeaderKeyName] = []string{user.APIKey}
			rw := httptest.NewRecorder()
			m.ServeHTTP(rw, req, func(rw http.ResponseWriter, r *http.Request) {
				rusr := GetUser(r.Context())
				assert.Equal(t, user, rusr)
			})
			assert.Equal(t, http.StatusOK, rw.Code)
		},
		"HeaderCheck/StaticKeysDisabled/HumanUser": func(t *testing.T) {
			conf := UserMiddlewareConfiguration{
				SkipHeaderCheck:                 false,
				SkipCookie:                      true,
				HeaderUserName:                  "api-user",
				HeaderKeyName:                   "api-key",
				StaticKeysDisabledForHumanUsers: true,
			}
			m := UserMiddleware(t.Context(), um, conf)
			require.NotNil(t, m)

			req := httptest.NewRequest("GET", "http://localhost/bar", nil)
			req.Header[conf.HeaderUserName] = []string{user.ID}
			req.Header[conf.HeaderKeyName] = []string{user.APIKey}
			rw := httptest.NewRecorder()
			m.ServeHTTP(rw, req, func(rw http.ResponseWriter, r *http.Request) {
				rusr := GetUser(r.Context())
				assert.Equal(t, user, rusr)
			})
			assert.Equal(t, http.StatusUnauthorized, rw.Code)
			assert.Equal(t, "static API keys are disabled for human users", rw.Body.String())
		},
		"HeaderCheck/StaticKeysDisabled/HumanUserMultipleAuth": func(t *testing.T) {
			conf := UserMiddlewareConfiguration{
				SkipHeaderCheck:                 false,
				HeaderUserName:                  "api-user",
				HeaderKeyName:                   "api-key",
				SkipCookie:                      false,
				CookieName:                      "gimlet-token",
				StaticKeysDisabledForHumanUsers: true,
			}
			m := UserMiddleware(t.Context(), um, conf)
			require.NotNil(t, m)

			req := httptest.NewRequest("GET", "http://localhost/bar", nil)
			req.Header[conf.HeaderUserName] = []string{user.ID}
			req.Header[conf.HeaderKeyName] = []string{user.APIKey}
			req.AddCookie(&http.Cookie{
				Name:  conf.CookieName,
				Value: user.Token,
			})
			rw := httptest.NewRecorder()
			m.ServeHTTP(rw, req, func(rw http.ResponseWriter, r *http.Request) {
				rusr := GetUser(r.Context())
				assert.Equal(t, user, rusr)
			})
			assert.Equal(t, http.StatusOK, rw.Code)
		},
		"HeaderCheck/StaticKeysDisabled/ServiceUser": func(t *testing.T) {
			conf := UserMiddlewareConfiguration{
				SkipHeaderCheck:                 false,
				SkipCookie:                      true,
				HeaderUserName:                  "api-user",
				HeaderKeyName:                   "api-key",
				StaticKeysDisabledForHumanUsers: true,
			}
			m := UserMiddleware(t.Context(), um, conf)
			require.NotNil(t, m)

			req := httptest.NewRequest("GET", "http://localhost/bar", nil)
			req.Header[conf.HeaderUserName] = []string{serviceUser.ID}
			req.Header[conf.HeaderKeyName] = []string{serviceUser.APIKey}
			rw := httptest.NewRecorder()
			m.ServeHTTP(rw, req, func(rw http.ResponseWriter, r *http.Request) {
				rusr := GetUser(r.Context())
				assert.Equal(t, serviceUser, rusr)
			})
			assert.Equal(t, http.StatusOK, rw.Code)
		},
		"WrongHeaderKey": func(t *testing.T) {
			conf := UserMiddlewareConfiguration{
				SkipHeaderCheck: false,
				SkipCookie:      true,
				HeaderUserName:  "api-user",
				HeaderKeyName:   "api-key",
			}
			m := UserMiddleware(t.Context(), um, conf)
			require.NotNil(t, m)

			req := httptest.NewRequest("GET", "http://localhost/bar", nil)
			req.Header[conf.HeaderUserName] = []string{user.ID}
			req.Header[conf.HeaderKeyName] = []string{"DECAFBAD"}
			rw := httptest.NewRecorder()

			m.ServeHTTP(rw, req, func(rw http.ResponseWriter, r *http.Request) {
				rusr := GetUser(r.Context())
				assert.Nil(t, rusr)
			})
			assert.Equal(t, http.StatusUnauthorized, rw.Code)
		},
		"CookieCheck": func(t *testing.T) {
			conf := UserMiddlewareConfiguration{
				SkipHeaderCheck: true,
				SkipCookie:      false,
				CookieName:      "gimlet-token",
			}
			m := UserMiddleware(t.Context(), um, conf)

			req := httptest.NewRequest("GET", "http://localhost/bar", nil)
			require.NotNil(t, req)
			req.AddCookie(&http.Cookie{
				Name:  conf.CookieName,
				Value: user.Token,
			})
			rw := httptest.NewRecorder()
			m.ServeHTTP(rw, req, func(rw http.ResponseWriter, r *http.Request) {
				rusr := GetUser(r.Context())
				assert.Equal(t, user, rusr)
			})
			assert.Equal(t, http.StatusOK, rw.Code)
		},
		"WrongCookieName": func(t *testing.T) {
			conf := UserMiddlewareConfiguration{
				SkipHeaderCheck: true,
				SkipCookie:      false,
				CookieName:      "gimlet-token",
			}
			m := UserMiddleware(t.Context(), um, conf)

			req := httptest.NewRequest("GET", "http://localhost/bar", nil)
			req.AddCookie(&http.Cookie{
				Name:  "foo",
				Value: "DEADBEEF",
			})
			rw := httptest.NewRecorder()
			m.ServeHTTP(rw, req, func(rw http.ResponseWriter, r *http.Request) {
				rusr := GetUser(r.Context())
				assert.Nil(t, rusr)
			})
			assert.Equal(t, http.StatusOK, rw.Code)
		},
		"WrongCookieValue": func(t *testing.T) {
			conf := UserMiddlewareConfiguration{
				SkipHeaderCheck: true,
				SkipCookie:      false,
				CookieName:      "gimlet-token",
			}
			m := UserMiddleware(t.Context(), um, conf)

			req := httptest.NewRequest("GET", "http://localhost/bar", nil)
			require.NotNil(t, req)
			req.AddCookie(&http.Cookie{
				Name:  "gimlet-token",
				Value: "DEADC0DE",
			})
			rw := httptest.NewRecorder()
			m.ServeHTTP(rw, req, func(rw http.ResponseWriter, r *http.Request) {
				rusr := GetUser(r.Context())
				assert.Nil(t, rusr)
			})
			assert.Equal(t, http.StatusOK, rw.Code)
		},
		"GetOrCreateFails": func(t *testing.T) {
			um := &MockUserManager{Users: []*MockUser{user}, FailGetOrCreateUser: true}
			conf := UserMiddlewareConfiguration{
				SkipHeaderCheck: true,
				SkipCookie:      false,
				CookieName:      "gimlet-token",
			}
			m := UserMiddleware(t.Context(), um, conf)

			req := httptest.NewRequest("GET", "http://localhost/bar", nil)
			require.NotNil(t, req)
			req.AddCookie(&http.Cookie{
				Name:  conf.CookieName,
				Value: user.Token,
			})
			rw := httptest.NewRecorder()
			m.ServeHTTP(rw, req, func(rw http.ResponseWriter, r *http.Request) {
				rusr := GetUser(r.Context())
				assert.Nil(t, rusr)
			})
			assert.Equal(t, http.StatusOK, rw.Code)
		},
	} {
		t.Run(name, testCase)
	}

	// test that if get-or-create fails that the op does

}

type mockKeyset struct {
	validSignature bool
	payload        string
	verifyCalls    int
}

func (k *mockKeyset) VerifySignature(ctx context.Context, jwt string) (payload []byte, err error) {
	k.verifyCalls++
	if !k.validSignature {
		return nil, errors.New("invalid signature")
	}
	return []byte(k.payload), nil
}

func TestOIDCValidation(t *testing.T) {
	headerName := "internal_header"
	user := &MockUser{ID: "i-am-sam"}
	um := &MockUserManager{Users: []*MockUser{user}}

	t.Run("ValidJWT", func(t *testing.T) {
		conf := UserMiddlewareConfiguration{
			SkipHeaderCheck: true,
			SkipCookie:      true,
			OIDCConfigs: []*OIDCConfig{
				{HeaderName: headerName, Issuer: "www.mongodb.com", KeysetURL: "http://example.com"},
			},
		}
		payload := `{"sub":"i-am-sam","iat":1727208337,"iss":"www.mongodb.com"}`
		m := UserMiddleware(t.Context(), um, conf).(*userMiddleware)
		m.oidcKeyToVerifierPair[oidcKey(headerName, conf.OIDCConfigs[0].Issuer)].verifier = oidc.NewVerifier(
			conf.OIDCConfigs[0].Issuer,
			&mockKeyset{validSignature: true, payload: payload},
			&oidc.Config{SkipClientIDCheck: true, SkipExpiryCheck: true, SupportedSigningAlgs: []string{"HS256"}},
		)
		req := httptest.NewRequest("GET", "http://localhost/bar", nil)
		req.Header.Add(headerName, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJpLWFtLXNhbSIsImlhdCI6MTcyNzIwODMzNywiaXNzIjoid3d3Lm1vbmdvZGIuY29tIn0.RpKLMhvXe6IISKzmwLbVT6trddAy37_7A4Dmq_SSeh0")
		rw := httptest.NewRecorder()
		m.ServeHTTP(rw, req, func(rw http.ResponseWriter, r *http.Request) {
			assert.Equal(t, user.Username(), GetUser(r.Context()).Username())
		})
		assert.Equal(t, http.StatusOK, rw.Code)
	})

	t.Run("IssuerRouting", func(t *testing.T) {
		multiConf := UserMiddlewareConfiguration{
			SkipHeaderCheck: true,
			SkipCookie:      true,
			OIDCConfigs: []*OIDCConfig{
				{HeaderName: headerName, Issuer: "issuer-a", KeysetURL: "http://example.com/a"},
				{HeaderName: headerName, Issuer: "issuer-b", KeysetURL: "http://example.com/b"},
			},
		}
		require.NoError(t, multiConf.Validate())
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub": "i-am-sam",
			"iat": float64(1727208337),
			"iss": "issuer-b",
		})
		tokenString, err := token.SignedString([]byte("secret"))
		require.NoError(t, err)
		parts := strings.Split(tokenString, ".")
		require.Len(t, parts, 3)
		payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
		require.NoError(t, err)
		payload := string(payloadBytes)
		mMulti := UserMiddleware(t.Context(), um, multiConf).(*userMiddleware)
		mMulti.oidcKeyToVerifierPair[oidcKey(headerName, "issuer-b")].verifier = oidc.NewVerifier(
			"issuer-b",
			&mockKeyset{validSignature: true, payload: payload},
			&oidc.Config{SkipClientIDCheck: true, SkipExpiryCheck: true, SupportedSigningAlgs: []string{"HS256"}},
		)
		req := httptest.NewRequest("GET", "http://localhost/bar", nil)
		req.Header.Add(headerName, tokenString)
		rw := httptest.NewRecorder()
		mMulti.ServeHTTP(rw, req, func(rw http.ResponseWriter, r *http.Request) {
			assert.Equal(t, user.Username(), GetUser(r.Context()).Username())
		})
		assert.Equal(t, http.StatusOK, rw.Code)

		singleConf := UserMiddlewareConfiguration{
			SkipHeaderCheck: true,
			SkipCookie:      true,
			OIDCConfigs: []*OIDCConfig{
				{HeaderName: headerName, Issuer: "www.mongodb.com", KeysetURL: "http://example.com"},
			},
		}
		ks := &mockKeyset{validSignature: true, payload: `{"sub":"i-am-sam","iss":"www.mongodb.com"}`}
		mSingle := UserMiddleware(t.Context(), um, singleConf).(*userMiddleware)
		mSingle.oidcKeyToVerifierPair[oidcKey(headerName, singleConf.OIDCConfigs[0].Issuer)].verifier = oidc.NewVerifier(
			singleConf.OIDCConfigs[0].Issuer,
			ks,
			&oidc.Config{SkipClientIDCheck: true, SkipExpiryCheck: true, SupportedSigningAlgs: []string{"HS256"}},
		)
		badToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub": "i-am-sam",
			"iat": float64(1727208337),
			"iss": "unknown-issuer",
		})
		badTokenString, err := badToken.SignedString([]byte("secret"))
		require.NoError(t, err)
		req2 := httptest.NewRequest("GET", "http://localhost/bar", nil)
		req2.Header.Add(headerName, badTokenString)
		rw2 := httptest.NewRecorder()
		mSingle.ServeHTTP(rw2, req2, func(rw http.ResponseWriter, r *http.Request) {
			assert.Nil(t, GetUser(r.Context()))
		})
		assert.Equal(t, http.StatusOK, rw2.Code)
		assert.Zero(t, ks.verifyCalls)
	})
}

func TestUserMiddlewareConfiguration(t *testing.T) {
	conf := UserMiddlewareConfiguration{
		HeaderUserName: "u",
		HeaderKeyName:  "k",
		CookieName:     "c",
		CookieTTL:      time.Hour,
		CookiePath:     "/p",
		OIDCConfigs: []*OIDCConfig{
			{HeaderName: "internal_header", KeysetURL: "www.example.com", Issuer: "www.google.com"},
		},
	}
	require.NoError(t, conf.Validate())

	t.Run("DiabledChecksAreValid", func(t *testing.T) {
		emptyConf := UserMiddlewareConfiguration{
			SkipCookie:      true,
			SkipHeaderCheck: true,
		}
		assert.NoError(t, emptyConf.Validate())
	})
	t.Run("ZeroValueIsNotValid", func(t *testing.T) {
		emptyConf := UserMiddlewareConfiguration{}
		assert.Zero(t, emptyConf.CookiePath)
		assert.Error(t, emptyConf.Validate())
		// also we expect that the validate will populate the Tl
		assert.NotZero(t, emptyConf.CookiePath)
	})

	t.Run("Cookie", func(t *testing.T) {
		rw := httptest.NewRecorder()
		assert.Len(t, rw.Header(), 0)
		conf.AttachCookie("foo", rw)
		assert.Len(t, rw.Header(), 1)
		conf.ClearCookie(rw)
		assert.Len(t, rw.Header(), 1)
	})

	t.Run("InvalidConfigurations", func(t *testing.T) {
		for _, test := range []struct {
			name string
			op   func(UserMiddlewareConfiguration) UserMiddlewareConfiguration
		}{
			{
				name: "MissingCoookieName",
				op: func(conf UserMiddlewareConfiguration) UserMiddlewareConfiguration {
					conf.CookieName = ""
					return conf
				},
			},
			{
				name: "TooShortTTL",
				op: func(conf UserMiddlewareConfiguration) UserMiddlewareConfiguration {
					conf.CookieTTL = time.Millisecond
					return conf
				},
			},
			{
				name: "MalformedPath",
				op: func(conf UserMiddlewareConfiguration) UserMiddlewareConfiguration {
					conf.CookiePath = "foo"
					return conf
				},
			},
			{
				name: "MissingUserName",
				op: func(conf UserMiddlewareConfiguration) UserMiddlewareConfiguration {
					conf.HeaderUserName = ""
					return conf
				},
			},
			{
				name: "MissingKeyName",
				op: func(conf UserMiddlewareConfiguration) UserMiddlewareConfiguration {
					conf.HeaderKeyName = ""
					return conf
				},
			},
			{
				name: "MissingOIDCHeaderName",
				op: func(conf UserMiddlewareConfiguration) UserMiddlewareConfiguration {
					conf.OIDCConfigs[0].HeaderName = ""
					return conf
				},
			},
			{
				name: "MissingOIDCKeysetURL",
				op: func(conf UserMiddlewareConfiguration) UserMiddlewareConfiguration {
					conf.OIDCConfigs[0].KeysetURL = ""
					return conf
				},
			},
			{
				name: "MissingOIDCIssuer",
				op: func(conf UserMiddlewareConfiguration) UserMiddlewareConfiguration {
					conf.OIDCConfigs[0].Issuer = ""
					return conf
				},
			},
		} {
			t.Run(test.name, func(t *testing.T) {
				conf := UserMiddlewareConfiguration{
					HeaderUserName: "u",
					HeaderKeyName:  "k",
					CookieName:     "c",
					CookieTTL:      time.Hour,
					CookiePath:     "/p",
					OIDCConfigs: []*OIDCConfig{
						{HeaderName: "internal_header", KeysetURL: "www.example.com", Issuer: "www.google.com"},
					},
				}
				require.NoError(t, conf.Validate())
				conf = test.op(conf)
				require.Error(t, conf.Validate())
			})
		}
	})
}
