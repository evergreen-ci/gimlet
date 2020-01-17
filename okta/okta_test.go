package okta

import (
	"context"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/evergreen-ci/gimlet"
	"github.com/evergreen-ci/gimlet/testutil"
	"github.com/evergreen-ci/gimlet/usercache"
	"github.com/mongodb/grip"
	jwtverifier "github.com/okta/okta-jwt-verifier-golang"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUserManagerCreation(t *testing.T) {
	for testName, testCase := range map[string]struct {
		modifyOpts func(CreationOptions) CreationOptions
		shouldPass bool
	}{
		"AllOptionsSetWithUserCache": {
			modifyOpts: func(opts CreationOptions) CreationOptions { return opts },
			shouldPass: true,
		},
		"AllOptionsSetWithExternalCache": {
			modifyOpts: func(opts CreationOptions) CreationOptions {
				return mockCreationOptionsWithExternalCache()
			},
			shouldPass: true,
		},
		"BothUserCacheAndExternalCacheSet": {
			modifyOpts: func(opts CreationOptions) CreationOptions {
				opts.ExternalCache = mockExternalCacheOptions()
				return opts
			},
			shouldPass: false,
		},
		"MissingClientID": {
			modifyOpts: func(opts CreationOptions) CreationOptions { opts.ClientID = ""; return opts },
			shouldPass: false,
		},
		"MissingClientSecret": {
			modifyOpts: func(opts CreationOptions) CreationOptions { opts.ClientSecret = ""; return opts },
			shouldPass: false,
		},
		"MissingRedirectURI": {
			modifyOpts: func(opts CreationOptions) CreationOptions { opts.RedirectURI = ""; return opts },
			shouldPass: false,
		},
		"MissingIssuer": {
			modifyOpts: func(opts CreationOptions) CreationOptions { opts.Issuer = ""; return opts },
			shouldPass: false,
		},
		"MissingUserGroup": {
			modifyOpts: func(opts CreationOptions) CreationOptions { opts.UserGroup = ""; return opts },
			shouldPass: false,
		},
		"MissingCookiePath": {
			modifyOpts: func(opts CreationOptions) CreationOptions { opts.CookiePath = ""; return opts },
			shouldPass: false,
		},
		"MissingCookieDomain": {
			modifyOpts: func(opts CreationOptions) CreationOptions { opts.CookieDomain = ""; return opts },
			shouldPass: true,
		},
		"MissingLoginCookieName": {
			modifyOpts: func(opts CreationOptions) CreationOptions { opts.LoginCookieName = ""; return opts },
			shouldPass: false,
		},
		"MissingLoginCookieTTL": {
			modifyOpts: func(opts CreationOptions) CreationOptions { opts.LoginCookieTTL = time.Duration(0); return opts },
			shouldPass: true,
		},
		"MissingUserCache": {
			modifyOpts: func(opts CreationOptions) CreationOptions { opts.UserCache = nil; return opts },
			shouldPass: false,
		},
		"MissingGetHTTPClient": {
			modifyOpts: func(opts CreationOptions) CreationOptions { opts.GetHTTPClient = nil; return opts },
			shouldPass: false,
		},
		"MissingPutHTTPClient": {
			modifyOpts: func(opts CreationOptions) CreationOptions { opts.PutHTTPClient = nil; return opts },
			shouldPass: false,
		},
		"MissingReconciliateID": {
			modifyOpts: func(opts CreationOptions) CreationOptions { opts.ReconciliateID = nil; return opts },
			shouldPass: true,
		},
	} {
		t.Run(testName, func(t *testing.T) {
			um, err := NewUserManager(testCase.modifyOpts(mockCreationOptions()))
			if testCase.shouldPass {
				assert.NoError(t, err)
				assert.NotNil(t, um)
			} else {
				assert.Error(t, err)
				assert.Nil(t, um)
			}
		})
	}
}

// TODO (kim): set up mock (echo?) server
// * Set up essential mock validation server
// - Create GET /oauth2/v1/authorize and read query parameters.
// - Create /oauth2/v1/authorize/echo endpoint to check parameters sent.
// - Create POST /oauth2/v1/token endpoint and read query parameters.
// - Create /oauth2/v1/token/echo endpoint to check parameters sent.
// - Create GET /oauth2/v1/userinfo endpoint and read query parameters.
// - Create /oauth2/v1/userinfo/echo endpoint and check parameters sent.
//
// * Test essential helpers
// - redeemTokens()
// - refreshTokens()
// - exchangeCodeForTokens()
// - getUserInfo()
//
// * Test GetLoginHandler
// - Mock out key validation functions (or just comment out for now, until keys
//   are valid).
// - Verify it sends expected parameters in query to /oauth2/v1/authorize
//   Use REST echo response to check parameters.
//
// * Test GetLoginCallbackHandler
// - Attach required cookies (nonce, state) to request to callback.
// - Verify error if state check fails.
// - Verify error if request has error/error description.
// - Attach extra cookies (redirectURI) to request to callback.
// - Check that redirect goes to cookie requestURI.
//
// * Set up more difficult mock validation server methods
// Generate JWKs from master RSA key.
// /v1/keys: put keys to download here in JSON format

// mockAuthorizationServer represents a server against which OIDC requests can
// be sent.
type mockAuthorizationServer struct {
	// AuthorizeParameters are parameters sent to the authorize endpoint.
	AuthorizeParameters url.Values
	// Authorizeheaders are the headers sent to the authorize endpoint.
	AuthorizeHeaders http.Header
	// AuthorizeResponse is returned from the userinfo endpoint.
	AuthorizeResponse map[string]interface{}
	// TokenParameters are parameters sent to the token endpoint.
	TokenParameters url.Values
	// TokenHeaders are the headers sent to the token endpoint.
	TokenHeaders http.Header
	// TokenResponse is returned from the token endpoint.
	TokenResponse *tokenResponse
	// UserInfoHeaders are the headers sent to the userinfo endpoint.
	UserInfoHeaders http.Header
	// UserInfoResponse isre returned from the userinfo endpoint.
	UserInfoResponse *userInfoResponse
	// RedirectToLoginCallback is true if the authorization server should
	// continue the authorization code flow at the login callback.
	RedirectToLoginCallback bool
}

func (s *mockAuthorizationServer) app(port int) (*gimlet.APIApp, error) {
	app := gimlet.NewApp()
	if err := app.SetHost("localhost"); err != nil {
		return nil, errors.WithStack(err)
	}
	if err := app.SetPort(port); err != nil {
		return nil, err
	}

	app.AddRoute("/").Version(1).Get().Handler(s.root)
	app.AddRoute("/oauth2/v1/authorize").Version(1).Get().Handler(s.authorize)
	app.AddRoute("/oauth2/v1/token").Version(1).Post().Handler(s.token)
	app.AddRoute("/oauth2/v1/userinfo").Version(1).Get().Handler(s.userinfo)

	return app, nil
}

func (s *mockAuthorizationServer) startMockServer(ctx context.Context) (port int, err error) {
tryToMakeServer:
	for {
		select {
		case <-ctx.Done():
			grip.Warning("timed out starting mock server")
			return -1, errors.WithStack(ctx.Err())
		default:
			port = testutil.GetPortNumber()
			app, err := s.app(port)
			if err != nil {
				grip.Warning(err)
				continue tryToMakeServer
			}

			go func() {
				grip.Warning(app.Run(ctx))
			}()

			timer := time.NewTimer(5 * time.Millisecond)
			defer timer.Stop()
			url := fmt.Sprintf("http://localhost:%d/v1", port)

			trials := 0
		checkServer:
			for {
				if trials > 5 {
					continue tryToMakeServer
				}

				select {
				case <-ctx.Done():
					return -1, errors.WithStack(ctx.Err())
				case <-timer.C:
					req, err := http.NewRequest(http.MethodGet, url, nil)
					if err != nil {
						timer.Reset(5 * time.Millisecond)
						trials++
						continue checkServer
					}
					rctx, cancel := context.WithTimeout(ctx, time.Second)
					defer cancel()
					req = req.WithContext(rctx)
					resp, err := http.DefaultClient.Do(req)
					if err != nil {
						timer.Reset(5 * time.Millisecond)
						trials++
						continue checkServer
					}
					if resp.StatusCode != http.StatusOK {
						timer.Reset(5 * time.Millisecond)
						trials++
						continue checkServer
					}

					return port, nil
				}
			}
		}
	}
}

func (s *mockAuthorizationServer) root(rw http.ResponseWriter, r *http.Request) {
	gimlet.WriteJSON(rw, struct{}{})
}

func (s *mockAuthorizationServer) authorize(rw http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		gimlet.WriteJSONError(rw, &tokenResponse{ErrorCode: "invalid_request"})
		return
	}
	s.AuthorizeParameters, err = url.ParseQuery(string(body))
	if err != nil {
		gimlet.WriteJSONError(rw, &tokenResponse{ErrorCode: "invalid_request"})
		return
	}
	s.AuthorizeHeaders = r.Header
	if s.AuthorizeResponse == nil {
		gimlet.WriteJSON(rw, struct{}{})
	}
	// TODO (kim): verify that this is correct flow to get to callback handler.
	if s.RedirectToLoginCallback {
		q := url.Values{}
		q.Add("code", s.AuthorizeParameters.Get("code"))
		q.Add("state", s.AuthorizeParameters.Get("state"))
		redirectURI := fmt.Sprintf("%s?%s", s.AuthorizeParameters.Get("redirect_uri"), q.Encode())
		http.Redirect(rw, r, redirectURI, http.StatusFound)
		return
		// client := &http.Client{}
		// req, err := http.NewRequest(http.MethodGet, redirectURI, nil)
		// if err != nil {
		//     gimlet.WriteTextInternalError(rw, "could not create request to redirect callback URI")
		//     return
		// }
		// for _, cookie := range r.Cookies() {
		//     req.AddCookie(cookie)
		// }
		// resp, err := client.Do(req)
		// if err != nil {
		//     gimlet.WriteTextInternalError(rw, "request to login redirect callback URI failed")
		//     return
		// }
		// return
	}
	gimlet.WriteJSON(rw, s.AuthorizeResponse)
}

func (s *mockAuthorizationServer) token(rw http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		gimlet.WriteJSONError(rw, &tokenResponse{ErrorCode: "invalid_request"})
		return
	}
	s.TokenParameters, err = url.ParseQuery(string(body))
	if err != nil {
		gimlet.WriteJSONError(rw, &tokenResponse{ErrorCode: "invalid_request"})
		return
	}
	s.TokenHeaders = r.Header
	if s.TokenResponse == nil {
		gimlet.WriteJSON(rw, struct{}{})
		return
	}
	gimlet.WriteJSON(rw, s.TokenResponse)
}

func (s *mockAuthorizationServer) userinfo(rw http.ResponseWriter, r *http.Request) {
	s.UserInfoHeaders = r.Header
	if s.UserInfoResponse == nil {
		gimlet.WriteJSON(rw, struct{}{})
		return
	}
	gimlet.WriteJSON(rw, s.UserInfoResponse)
}

// startMockApplicationLoginServer starts an application server for testing purposes
// that can handle login requests and callbacks.
func startMockApplicationLoginServer(ctx context.Context, port int, m *userManager) error {
	app := gimlet.NewApp()
	if err := app.SetHost("localhost"); err != nil {
		return errors.WithStack(err)
	}
	if err := app.SetPort(port); err != nil {
		return errors.WithStack(err)
	}

	app.AddRoute("/login").Version(1).Get().Handler(m.GetLoginHandler(""))
	app.AddRoute("/login/callback").Version(1).Get().Handler(m.GetLoginCallbackHandler())

	go func() {
		app.Run(ctx)
	}()

	return nil
}

func mapContains(t *testing.T, set, subset map[string][]string) {
	for k, v := range subset {
		checkVal, ok := set[k]
		require.Truef(t, ok, "missing key '%s'", k)
		assert.ElementsMatch(t, v, checkVal)
	}
}

func TestRequestHelpers(t *testing.T) {
	for testName, testCase := range map[string]func(ctx context.Context, t *testing.T, um *userManager, s *mockAuthorizationServer){
		"TestGetUserInfoSuccess": func(ctx context.Context, t *testing.T, um *userManager, s *mockAuthorizationServer) {
			s.UserInfoResponse = &userInfoResponse{
				Name:   "name",
				Email:  "email",
				Groups: []string{"group"},
			}
			userInfo, err := um.getUserInfo(ctx, "access_token")
			require.NoError(t, err)
			mapContains(t, s.UserInfoHeaders, map[string][]string{
				"Accept":        []string{"application/json"},
				"Authorization": []string{"Bearer access_token"},
			})
			require.NotNil(t, userInfo)
			assert.Equal(t, *s.UserInfoResponse, *userInfo)
		},
		"TestGetUserInfoError": func(ctx context.Context, t *testing.T, um *userManager, s *mockAuthorizationServer) {
			s.UserInfoResponse = &userInfoResponse{
				Name:             "name",
				Email:            "email",
				Groups:           []string{"group"},
				ErrorCode:        "error_code",
				ErrorDescription: "error_description",
			}
			userInfo, err := um.getUserInfo(ctx, "access_token")
			assert.Error(t, err)
			mapContains(t, s.UserInfoHeaders, map[string][]string{
				"Accept":        []string{"application/json"},
				"Authorization": []string{"Bearer access_token"},
			})
			require.NotNil(t, userInfo)
			assert.Equal(t, *s.UserInfoResponse, *userInfo)
		},
		"TestExchangeCodeForTokensSuccess": func(ctx context.Context, t *testing.T, um *userManager, s *mockAuthorizationServer) {
			s.TokenResponse = &tokenResponse{
				AccessToken:  "access_token",
				IDToken:      "id_token",
				RefreshToken: "refresh_token",
				TokenType:    "token_type",
				ExpiresIn:    3600,
				Scope:        "scope",
			}
			code := "some_code"
			tokens, err := um.exchangeCodeForTokens(ctx, code)
			require.NoError(t, err)
			mapContains(t, s.TokenHeaders, map[string][]string{
				"Accept":        []string{"application/json"},
				"Content-Type":  []string{"application/x-www-form-urlencoded"},
				"Authorization": []string{"Basic " + base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", um.clientID, um.clientSecret)))},
			})
			mapContains(t, s.TokenParameters, map[string][]string{
				"grant_type":   []string{"authorization_code"},
				"code":         []string{code},
				"redirect_uri": []string{um.redirectURI},
			})
			require.NotNil(t, tokens)
			assert.Equal(t, *s.TokenResponse, *tokens)
		},
		"TestExchangeCodeForTokensError": func(ctx context.Context, t *testing.T, um *userManager, s *mockAuthorizationServer) {
			s.TokenResponse = &tokenResponse{
				AccessToken:      "access_token",
				IDToken:          "id_token",
				RefreshToken:     "refresh_token",
				TokenType:        "token_type",
				ExpiresIn:        3600,
				Scope:            "scope",
				ErrorCode:        "error_code",
				ErrorDescription: "error_description",
			}
			code := "some_code"
			tokens, err := um.exchangeCodeForTokens(ctx, code)
			assert.Error(t, err)
			mapContains(t, s.TokenHeaders, map[string][]string{
				"Accept":        []string{"application/json"},
				"Content-Type":  []string{"application/x-www-form-urlencoded"},
				"Authorization": []string{"Basic " + base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", um.clientID, um.clientSecret)))},
			})
			mapContains(t, s.TokenParameters, map[string][]string{
				"grant_type":   []string{"authorization_code"},
				"code":         []string{code},
				"redirect_uri": []string{um.redirectURI},
			})
			require.NotNil(t, tokens)
			assert.Equal(t, *s.TokenResponse, *tokens)
		},
	} {
		t.Run(testName, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			s := &mockAuthorizationServer{}
			port, err := s.startMockServer(ctx)
			require.NoError(t, err)
			opts := mockCreationOptions()
			opts.Issuer = fmt.Sprintf("http://localhost:%d/v1", port)
			um, err := NewUserManager(opts)
			require.NoError(t, err)
			impl, ok := um.(*userManager)
			require.True(t, ok)
			testCase(ctx, t, impl, s)
		})
	}
}

func mockCreationOptions() CreationOptions {
	return CreationOptions{
		ClientID:            "client_id",
		ClientSecret:        "client_secret",
		RedirectURI:         "redirect_uri",
		Issuer:              "issuer",
		UserGroup:           "user_group",
		CookiePath:          "cookie_path",
		CookieDomain:        "example.com",
		LoginCookieName:     "login_cookie",
		LoginCookieTTL:      time.Hour,
		UserCache:           usercache.NewInMemory(context.Background(), time.Minute),
		GetHTTPClient:       func() *http.Client { return &http.Client{} },
		PutHTTPClient:       func(*http.Client) {},
		SkipGroupPopulation: true,
		ReconciliateID:      func(string) string { return "" },
	}
}

func mockCreationOptionsWithExternalCache() CreationOptions {
	opts := mockCreationOptions()
	opts.UserCache = nil
	opts.ExternalCache = mockExternalCacheOptions()
	return opts
}
func mockExternalCacheOptions() *usercache.ExternalOptions {
	return &usercache.ExternalOptions{
		GetUserByToken:  func(string) (gimlet.User, bool, error) { return nil, false, nil },
		GetUserByID:     func(string) (gimlet.User, bool, error) { return nil, false, nil },
		PutUserGetToken: func(gimlet.User) (string, error) { return "", nil },
		ClearUserToken:  func(gimlet.User, bool) error { return nil },
		GetOrCreateUser: func(gimlet.User) (gimlet.User, error) { return nil, nil },
	}
}

func TestMakeUserFromInfo(t *testing.T) {
	for testName, testCase := range map[string]struct {
		info             userInfoResponse
		expectedUsername string
		reconciliateID   func(string) string
		shouldPass       bool
	}{
		"Succeeds": {
			info: userInfoResponse{
				Email:  "foo@bar.com",
				Name:   "foo",
				Groups: []string{"group1"},
			},
			expectedUsername: "foo@bar.com",
			shouldPass:       true,
		},
		"SucceedsWithoutGroups": {
			info: userInfoResponse{
				Email: "foo@bar.com",
				Name:  "foo",
			},
			expectedUsername: "foo@bar.com",
			shouldPass:       true,
		},
		"FailsWithoutEmail": {
			info: userInfoResponse{
				Name: "foo",
			},
			shouldPass: false,
		},
		"FixIDChangesUsername": {
			info: userInfoResponse{
				Name:  "foo",
				Email: "foo@bar.com",
			},
			reconciliateID: func(id string) (newID string) {
				return strings.TrimSuffix(id, "@bar.com")
			},
			expectedUsername: "foo",
			shouldPass:       true,
		},
		"FixIDFailsIfReturnsEmpty": {
			info: userInfoResponse{
				Name:  "foo",
				Email: "foo@bar.com",
			},
			reconciliateID: func(string) string { return "" },
			shouldPass:     false,
		},
	} {
		t.Run(testName, func(t *testing.T) {
			user, err := makeUserFromInfo(&testCase.info, "access_token", "refresh_token", testCase.reconciliateID)
			if testCase.shouldPass {
				require.NoError(t, err)
				require.NotNil(t, user)
				assert.NotEmpty(t, user.Username())
				assert.Equal(t, testCase.info.Name, user.DisplayName())
				assert.Equal(t, testCase.info.Email, user.Email())
				assert.Equal(t, testCase.info.Groups, testCase.info.Groups)
			} else {
				assert.Error(t, err)
				assert.Nil(t, user)
			}
		})
	}
}

func TestMakeUserFromIDToken(t *testing.T) {
	for testName, testCase := range map[string]struct {
		token            jwtverifier.Jwt
		reconciliateID   func(string) string
		expectedUsername string
		shouldPass       bool
	}{
		"Succeeds": {
			token: jwtverifier.Jwt{
				Claims: map[string]interface{}{
					"email": "foo@bar.com",
					"name":  "foo",
				},
			},
			expectedUsername: "foo@bar.com",
			shouldPass:       true,
		},
		"FailsWithoutEmail": {
			token: jwtverifier.Jwt{
				Claims: map[string]interface{}{
					"name": "foo",
				},
			},
			shouldPass: false,
		},
		"FixIDChangesUsername": {
			token: jwtverifier.Jwt{
				Claims: map[string]interface{}{
					"email": "foo@bar.com",
					"name":  "foo",
				},
			},
			reconciliateID: func(id string) (newID string) {
				return strings.TrimSuffix(id, "@bar.com")
			},
			expectedUsername: "foo",
			shouldPass:       true,
		},
		"FixIDFailsIfReturnsEmpty": {
			token: jwtverifier.Jwt{
				Claims: map[string]interface{}{
					"email": "foo@bar.com",
					"name":  "foo",
				},
			},
			expectedUsername: "foo@bar.com",
			reconciliateID:   func(string) string { return "" },
			shouldPass:       false,
		},
	} {
		t.Run(testName, func(t *testing.T) {
			user, err := makeUserFromIDToken(&testCase.token, "access_token", "refresh_token", testCase.reconciliateID)
			if testCase.shouldPass {
				require.NoError(t, err)
				require.NotNil(t, user)
				assert.NotEmpty(t, user.Username())
				assert.Equal(t, testCase.expectedUsername, user.Username())
				assert.Equal(t, testCase.token.Claims["name"].(string), user.DisplayName())
				assert.Equal(t, testCase.token.Claims["email"], user.Email())
				assert.Empty(t, user.Roles())
			} else {
				assert.Error(t, err)
				assert.Nil(t, user)
			}
		})
	}
}

func TestCreateUserToken(t *testing.T) {
	um, err := NewUserManager(mockCreationOptions())
	require.NoError(t, err)
	token, err := um.CreateUserToken("username", "password")
	assert.Error(t, err)
	assert.Empty(t, token)
}

func TestGetUserByID(t *testing.T) {
	expectedUser := gimlet.NewBasicUser("username", "name", "email", "password", "key", "access_token", "refresh_token", nil, false, nil)
	for testName, testCase := range map[string]struct {
		modifyOpts func(CreationOptions) CreationOptions
		shouldPass bool
	}{
		"Succeeds": {
			modifyOpts: func(opts CreationOptions) CreationOptions {
				opts.ExternalCache.GetUserByID = func(string) (gimlet.User, bool, error) { return expectedUser, true, nil }
				return opts
			},
			shouldPass: true,
		},
		"Errors": {
			modifyOpts: func(opts CreationOptions) CreationOptions {
				opts.ExternalCache.GetUserByID = func(string) (gimlet.User, bool, error) { return nil, false, errors.New("fail") }
				return opts
			},
			shouldPass: false,
		},
		"ErrorsForNilUser": {
			modifyOpts: func(opts CreationOptions) CreationOptions {
				opts.ExternalCache.GetUserByID = func(string) (gimlet.User, bool, error) { return nil, false, nil }
				return opts
			},
			shouldPass: false,
		},
		"FailsDueToInvalidUser": {
			modifyOpts: func(opts CreationOptions) CreationOptions {
				opts.ExternalCache.GetUserByID = func(string) (gimlet.User, bool, error) { return expectedUser, false, nil }
				return opts
			},
			shouldPass: false,
		},
	} {
		t.Run(testName, func(t *testing.T) {
			opts := mockCreationOptions()
			opts.UserCache = nil
			um, err := NewUserManager(testCase.modifyOpts(mockCreationOptionsWithExternalCache()))
			require.NoError(t, err)
			user, err := um.GetUserByID(expectedUser.Username())
			if testCase.shouldPass {
				require.NoError(t, err)
				require.NotNil(t, user)

			} else {
				assert.Error(t, err)
				assert.Nil(t, user)
			}
		})
	}

}

func TestGetOrCreateUser(t *testing.T) {
	expectedUser := gimlet.NewBasicUser("username", "name", "email", "password", "key", "access_token", "refresh_token", nil, false, nil)
	for testName, testCase := range map[string]struct {
		modifyOpts func(CreationOptions) CreationOptions
		shouldPass bool
	}{
		"Succeeds": {
			modifyOpts: func(opts CreationOptions) CreationOptions {
				opts.ExternalCache.GetOrCreateUser = func(gimlet.User) (gimlet.User, error) { return expectedUser, nil }
				return opts
			},
			shouldPass: true,
		},
		"Errors": {
			modifyOpts: func(opts CreationOptions) CreationOptions {
				opts.ExternalCache.GetOrCreateUser = func(gimlet.User) (gimlet.User, error) { return nil, errors.New("fail") }
				return opts
			},
			shouldPass: false,
		},
	} {
		t.Run(testName, func(t *testing.T) {
			opts := mockCreationOptions()
			opts.UserCache = nil
			um, err := NewUserManager(testCase.modifyOpts(mockCreationOptionsWithExternalCache()))
			require.NoError(t, err)
			user, err := um.GetOrCreateUser(expectedUser)
			if testCase.shouldPass {
				require.NoError(t, err)
				require.NotNil(t, user)

			} else {
				assert.Error(t, err)
				assert.Nil(t, user)
			}
		})
	}
}

func TestClearUser(t *testing.T) {
	expectedUser := gimlet.NewBasicUser("username", "name", "email", "password", "key", "access_token", "refresh_token", nil, false, nil)
	for testName, testCase := range map[string]struct {
		modifyOpts func(CreationOptions) CreationOptions
		shouldPass bool
	}{
		"Succeeds": {
			modifyOpts: func(opts CreationOptions) CreationOptions {
				opts.ExternalCache.ClearUserToken = func(gimlet.User, bool) error {
					return nil
				}
				return opts
			},
			shouldPass: true,
		},
		"Errors": {
			modifyOpts: func(opts CreationOptions) CreationOptions {
				opts.ExternalCache.ClearUserToken = func(gimlet.User, bool) error {
					return errors.New("fail")
				}
				return opts
			},
			shouldPass: false,
		},
	} {
		t.Run(testName, func(t *testing.T) {
			opts := mockCreationOptions()
			opts.UserCache = nil
			um, err := NewUserManager(testCase.modifyOpts(mockCreationOptionsWithExternalCache()))
			require.NoError(t, err)
			err = um.ClearUser(expectedUser, false)
			if testCase.shouldPass {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func mapContainsKeys(t *testing.T, set map[string]string, subset []string) {
	for _, name := range subset {
		assert.Contains(t, set, name)
	}
}

func cookieMap(cookies []*http.Cookie) map[string]string {
	m := map[string]string{}
	for _, cookie := range cookies {
		m[cookie.Name] = cookie.Value
	}
	return m
}

func TestLoginHandler(t *testing.T) {
	for testName, testCase := range map[string]func(ctx context.Context, t *testing.T, um *userManager, s *mockAuthorizationServer){
		"Succeeds": func(ctx context.Context, t *testing.T, um *userManager, s *mockAuthorizationServer) {
			rw := httptest.NewRecorder()
			req, err := http.NewRequest(http.MethodGet, "/login?redirect=/redirect", nil)
			require.NoError(t, err)
			um.GetLoginHandler("")(rw, req)

			resp := rw.Result()
			assert.NoError(t, resp.Body.Close())

			assert.Equal(t, http.StatusMovedPermanently, resp.StatusCode)

			cookies := cookieMap(resp.Cookies())
			assert.Contains(t, cookies, nonceCookieName)
			assert.Contains(t, cookies, stateCookieName)
			redirectURI, ok := cookies[requestURICookieName]
			assert.True(t, ok)
			assert.Equal(t, "/redirect", redirectURI)

			loc, ok := resp.Header["Location"]
			assert.True(t, ok)
			require.Len(t, loc, 1)
			parsed, err := url.Parse(loc[0])
			require.NoError(t, err)
			q := parsed.Query()
			mapContains(t, q, map[string][]string{
				"client_id":     []string{"client_id"},
				"response_type": []string{"code"},
				"response_mode": []string{"query"},
				"redirect_uri":  []string{"redirect_uri"},
			})
			scope := q.Get("scope")
			assert.Contains(t, scope, "openid")
			assert.Contains(t, scope, "profile")
			assert.Contains(t, scope, "email")
			assert.Contains(t, scope, "groups")
			assert.Contains(t, scope, "offline_access")
		},
		"SucceedsWithoutRedirectURI": func(ctx context.Context, t *testing.T, um *userManager, s *mockAuthorizationServer) {
			rw := httptest.NewRecorder()
			req, err := http.NewRequest(http.MethodGet, "/login", nil)
			require.NoError(t, err)
			um.GetLoginHandler("")(rw, req)

			resp := rw.Result()
			assert.NoError(t, resp.Body.Close())

			assert.Equal(t, http.StatusMovedPermanently, resp.StatusCode)

			cookies := cookieMap(resp.Cookies())
			assert.Contains(t, cookies, nonceCookieName)
			assert.Contains(t, cookies, stateCookieName)
			redirectURI, ok := cookies[requestURICookieName]
			assert.True(t, ok)
			assert.Equal(t, "/", redirectURI)

			loc, ok := resp.Header["Location"]
			assert.True(t, ok)
			require.Len(t, loc, 1)
			parsed, err := url.Parse(loc[0])
			require.NoError(t, err)
			q := parsed.Query()
			mapContains(t, q, map[string][]string{
				"client_id":     []string{"client_id"},
				"response_type": []string{"code"},
				"response_mode": []string{"query"},
				"redirect_uri":  []string{"redirect_uri"},
			})
			scope := q.Get("scope")
			assert.Contains(t, scope, "openid")
			assert.Contains(t, scope, "profile")
			assert.Contains(t, scope, "email")
			assert.Contains(t, scope, "groups")
			assert.Contains(t, scope, "offline_access")
		},
	} {
		t.Run(testName, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			s := &mockAuthorizationServer{}
			port, err := s.startMockServer(ctx)
			require.NoError(t, err)
			opts := mockCreationOptions()
			opts.Issuer = fmt.Sprintf("http://localhost:%d/v1", port)
			um, err := NewUserManager(opts)
			require.NoError(t, err)
			impl, ok := um.(*userManager)
			require.True(t, ok)
			testCase(ctx, t, impl, s)
		})
	}
}

func TestLoginHandlerCallback(t *testing.T) {
	for testName, testCase := range map[string]func(ctx context.Context, t *testing.T, um *userManager, s *mockAuthorizationServer){
		"Succeeds": func(ctx context.Context, t *testing.T, um *userManager, s *mockAuthorizationServer) {
			um.insecureSkipTokenValidation = true

			s.UserInfoResponse = &userInfoResponse{
				Name:   "name",
				Email:  "email",
				Groups: []string{"user_group"},
			}

			state := "some_state"
			nonce := "some_nonce"
			redirect := "/redirect"
			code := "some_code"

			rw := httptest.NewRecorder()
			var cookieHeader []string
			for k, v := range map[string]string{
				nonceCookieName:      nonce,
				stateCookieName:      state,
				requestURICookieName: redirect,
			} {
				cookieHeader = append(cookieHeader, fmt.Sprintf("%s=%s", k, v))
			}

			q := url.Values{}
			q.Add("state", state)
			q.Add("code", code)
			q.Add("nonce", nonce)
			req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("/login/callback?%s", q.Encode()), strings.NewReader(q.Encode()))
			require.NoError(t, err)
			req.Header["Cookie"] = cookieHeader

			um.GetLoginCallbackHandler()(rw, req)

			resp := rw.Result()
			assert.NoError(t, resp.Body.Close())

			assert.Equal(t, http.StatusFound, resp.StatusCode)

			cookies := cookieMap(resp.Cookies())
			loginToken, ok := cookies[um.loginCookieName]
			assert.True(t, ok)
			assert.NotEmpty(t, loginToken)

			user, err := um.GetUserByID("email")
			require.NoError(t, err)
			require.NotNil(t, user)
			assert.Equal(t, "email", user.Email())
			assert.ElementsMatch(t, []string{"group"}, user.Roles())

			checkUser, err := um.GetUserByToken(ctx, loginToken)
			require.NoError(t, err)
			assert.Equal(t, user, checkUser)
		},
	} {
		t.Run(testName, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			s := &mockAuthorizationServer{}
			port, err := s.startMockServer(ctx)
			require.NoError(t, err)
			opts := mockCreationOptions()
			opts.Issuer = fmt.Sprintf("http://localhost:%d/v1", port)
			um, err := NewUserManager(opts)
			require.NoError(t, err)
			impl, ok := um.(*userManager)
			require.True(t, ok)
			testCase(ctx, t, impl, s)
		})
	}
}
