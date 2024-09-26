package gimlet

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/evergreen-ci/negroni"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUserMiddleware(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	user := &MockUser{
		ID:     "sam-i-am",
		APIKey: "DEADBEEF",
		Token:  "42",
	}
	um := &MockUserManager{Users: []*MockUser{user}}

	for name, testCase := range map[string]func(*testing.T){
		"Constructor": func(t *testing.T) {
			m := UserMiddleware(ctx, um, UserMiddlewareConfiguration{})
			require.NotNil(t, m)
			assert.Implements(t, (*Middleware)(nil), m)
			assert.Implements(t, (*negroni.Handler)(nil), m)
			assert.Equal(t, m.(*userMiddleware).conf, UserMiddlewareConfiguration{})
			assert.Equal(t, m.(*userMiddleware).manager, um)
		},
		"NothingEnabled": func(t *testing.T) {
			m := UserMiddleware(ctx, um, UserMiddlewareConfiguration{SkipHeaderCheck: true, SkipCookie: true})
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
				m := UserMiddleware(ctx, um, conf)
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
			m := UserMiddleware(ctx, um, conf)
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
		"WrongHeaderKey": func(t *testing.T) {
			conf := UserMiddlewareConfiguration{
				SkipHeaderCheck: false,
				SkipCookie:      true,
				HeaderUserName:  "api-user",
				HeaderKeyName:   "api-key",
			}
			m := UserMiddleware(ctx, um, conf)
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
			m := UserMiddleware(ctx, um, conf)

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
			m := UserMiddleware(ctx, um, conf)

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
			m := UserMiddleware(ctx, um, conf)

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
			m := UserMiddleware(ctx, um, conf)

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
}

func (k *mockKeyset) VerifySignature(ctx context.Context, jwt string) (payload []byte, err error) {
	if !k.validSignature {
		return nil, errors.New("invalid signature")
	}
	return []byte(k.payload), nil
}

func TestOIDCValidation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	user := &MockUser{ID: "i-am-sam"}
	um := &MockUserManager{Users: []*MockUser{user}}
	headerName := "internal_header"
	conf := UserMiddlewareConfiguration{
		SkipHeaderCheck: true,
		SkipCookie:      true,
		OIDC: &OIDCConfig{
			HeaderName: headerName,
			Issuer:     "www.mongodb.com",
		},
	}

	payload := `{"sub":"i-am-sam","iat":1727208337,"iss":"www.mongodb.com"}`
	m := UserMiddleware(ctx, um, conf).(*userMiddleware)
	m.oidcVerifier = oidc.NewVerifier(
		conf.OIDC.Issuer,
		&mockKeyset{validSignature: true, payload: payload},
		&oidc.Config{SkipClientIDCheck: true, SkipExpiryCheck: true, SupportedSigningAlgs: []string{"HS256"}},
	)

	t.Run("ValidJWT", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://localhost/bar", nil)
		require.NotNil(t, req)
		req.Header.Add(headerName, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJpLWFtLXNhbSIsImlhdCI6MTcyNzIwODMzNywiaXNzIjoid3d3Lm1vbmdvZGIuY29tIn0.RpKLMhvXe6IISKzmwLbVT6trddAy37_7A4Dmq_SSeh0")
		rw := httptest.NewRecorder()
		m.ServeHTTP(rw, req, func(rw http.ResponseWriter, r *http.Request) {
			rusr := GetUser(r.Context())
			assert.Equal(t, user.Username(), rusr.Username())
		})
		assert.Equal(t, http.StatusOK, rw.Code)
	})

	t.Run("HeaderMissing", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://localhost/bar", nil)
		require.NotNil(t, req)
		rw := httptest.NewRecorder()
		m.ServeHTTP(rw, req, func(rw http.ResponseWriter, r *http.Request) {
			rusr := GetUser(r.Context())
			assert.Nil(t, rusr)
		})
		assert.Equal(t, http.StatusOK, rw.Code)
	})

	t.Run("InvalidJWT", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://localhost/bar", nil)
		require.NotNil(t, req)
		req.Header.Add(headerName, "not_a_valid_jwt")
		rw := httptest.NewRecorder()
		m.ServeHTTP(rw, req, func(rw http.ResponseWriter, r *http.Request) {
			rusr := GetUser(r.Context())
			assert.Nil(t, rusr)
		})
		assert.Equal(t, http.StatusOK, rw.Code)
	})
}

func TestUserMiddlewareConfiguration(t *testing.T) {
	conf := UserMiddlewareConfiguration{
		HeaderUserName: "u",
		HeaderKeyName:  "k",
		CookieName:     "c",
		CookieTTL:      time.Hour,
		CookiePath:     "/p",
		OIDC: &OIDCConfig{
			HeaderName: "internal_header",
			KeysetURL:  "www.example.com",
			Issuer:     "www.google.com",
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

	t.Run("NilOIDC", func(t *testing.T) {
		conf := UserMiddlewareConfiguration{
			HeaderUserName: "u",
			HeaderKeyName:  "k",
			CookieName:     "c",
			CookieTTL:      time.Hour,
			CookiePath:     "/p",
		}
		assert.NoError(t, conf.Validate())
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
					conf.OIDC.HeaderName = ""
					return conf
				},
			},
			{
				name: "MissingOIDCKeysetURL",
				op: func(conf UserMiddlewareConfiguration) UserMiddlewareConfiguration {
					conf.OIDC.KeysetURL = ""
					return conf
				},
			},
			{
				name: "MissingOIDCIssuer",
				op: func(conf UserMiddlewareConfiguration) UserMiddlewareConfiguration {
					conf.OIDC.Issuer = ""
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
					OIDC: &OIDCConfig{
						HeaderName: "internal_header",
						KeysetURL:  "www.example.com",
						Issuer:     "www.google.com",
					},
				}
				require.NoError(t, conf.Validate())
				conf = test.op(conf)
				require.Error(t, conf.Validate())
			})
		}
	})
}
