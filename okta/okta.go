package okta

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/evergreen-ci/gimlet"
	"github.com/evergreen-ci/gimlet/usercache"
	"github.com/evergreen-ci/gimlet/util"
	"github.com/mongodb/grip"
	"github.com/mongodb/grip/message"
	"github.com/pkg/errors"
)

// CreationOptions specify the options to create the manager.
type CreationOptions struct {
	ClientID            string
	ClientSecret        string
	RedirectURI         string
	CallbackRedirectURI string
	Issuer              string

	UserGroup string

	CookiePath     string
	CookieDomain   string
	CookieTTL      time.Duration
	SetLoginCookie func(http.ResponseWriter, string)

	UserCache     usercache.Cache
	ExternalCache *usercache.ExternalOptions

	GetHTTPClient func() *http.Client
	PutHTTPClient func(*http.Client)
}

func (opts *CreationOptions) validate() error {
	catcher := grip.NewBasicCatcher()
	catcher.NewWhen(opts.ClientID == "", "must specify client ID")
	catcher.NewWhen(opts.ClientSecret == "", "must specify client secret")
	catcher.NewWhen(opts.RedirectURI == "", "must specify redirect URI")
	catcher.NewWhen(opts.CallbackRedirectURI == "", "must specify callback redirect URI")
	catcher.NewWhen(opts.Issuer == "", "must specify issuer")
	catcher.NewWhen(opts.UserGroup == "", "must specify user group")
	catcher.NewWhen(opts.CookiePath == "", "must specify cookie path")
	catcher.NewWhen(opts.CookieDomain == "", "must specify cookie domain")
	catcher.NewWhen(opts.SetLoginCookie == nil, "must specify function to set login cookie")
	catcher.NewWhen(opts.UserCache == nil && opts.ExternalCache == nil, "must specify user cache")
	catcher.NewWhen(opts.GetHTTPClient == nil, "must specify function to get HTTP clients")
	catcher.NewWhen(opts.PutHTTPClient == nil, "must specify function to put HTTP clients")
	if opts.CookieTTL == time.Duration(0) {
		opts.CookieTTL = time.Hour
	}
	return catcher.Resolve()
}

type userManager struct {
	clientID            string
	clientSecret        string
	callbackRedirectURI string
	redirectURI         string
	issuer              string

	userGroup string

	cookiePath     string
	cookieDomain   string
	cookieTTL      time.Duration
	setLoginCookie func(http.ResponseWriter, string)

	cache usercache.Cache

	getHTTPClient func() *http.Client
	putHTTPClient func(*http.Client)
}

// NewUserManager creates a manager that connects to Okta for user
// management services.
func NewUserManager(opts CreationOptions) (gimlet.UserManager, error) {
	if err := opts.validate(); err != nil {
		return nil, errors.Wrap(err, "invalid Okta manager options")
	}
	var cache usercache.Cache
	if opts.UserCache != nil {
		cache = opts.UserCache
	} else {
		var err error
		cache, err = usercache.NewExternal(*opts.ExternalCache)
		if err != nil {
			return nil, errors.Wrap(err, "problem creating external user cache")
		}
	}
	m := &userManager{
		cache:               cache,
		clientID:            opts.ClientID,
		clientSecret:        opts.ClientSecret,
		redirectURI:         opts.RedirectURI,
		callbackRedirectURI: opts.CallbackRedirectURI,
		issuer:              opts.Issuer,
		userGroup:           opts.UserGroup,
		cookiePath:          opts.CookiePath,
		cookieDomain:        opts.CookieDomain,
		cookieTTL:           opts.CookieTTL,
		getHTTPClient:       opts.GetHTTPClient,
		putHTTPClient:       opts.PutHTTPClient,
	}
	return m, nil
}

func (m *userManager) GetUserByToken(ctx context.Context, token string) (gimlet.User, error) {
	user, valid, err := m.cache.Get(token)
	if err != nil {
		return nil, errors.Wrap(err, "problem getting cached user")
	}
	if user == nil {
		return nil, errors.New("token not found in cache")
	}
	if !valid {
		if err = m.reauthorizeUser(ctx, user); err != nil {
			return nil, errors.Wrap(err, "problem reauthorizing user")
		}
	}
	return user, nil
}

// TODO (kim): handle reauthentication.
func (m *userManager) reauthorizeUser(ctx context.Context, user gimlet.User) error {
	// accessToken := user.GetAccessToken()
	// catcher := grip.NewBasicCatcher()
	// catcher.Wrap(m.validateAccessToken(user.GetAccessToken()), "invalid access token")
	// if !catcher.HasErrors() {
	//     userInfo, err := m.getUserInfo(ctx, accessToken)
	//     catcher.Wrap(err, "could not get user info")
	//     if err == nil {
	//         err := m.validateGroup(userInfo.Groups)
	//         catcher.Wrap(err, "could not authorize user")
	//         if err == nil {
	//             _, err = m.cache.Put(user)
	//             catcher.Wrap(err, "could not add user to cache")
	//             if err == nil {
	//                 return nil
	//             }
	//         }
	//     }
	// }
	// refreshToken := user.GetRefreshToken()
	// tokens, err := m.refreshTokens(ctx, refreshToken)
	// catcher.Wrap(err, "could not refresh authorization tokens")
	// if err == nil {
	//     userInfo, err := m.getUserInfo(ctx, tokens.AccessToken)
	//     catcher.Wrap(err, "could not get user info")
	//     if err == nil {
	//         err := m.validateGroup(userInfo.Groups)
	//         catcher.Wrap(err, "could not authorize user")
	//         if err == nil {
	//             // TODO (kim): update user tokens
	//             user = makeUser(userInfo, accessToken, refreshToken)
	//             _, err = m.cache.Put(user)
	//             catcher.Wrap(err, "could not add user to cache")
	//             if err == nil {
	//                 return nil
	//             }
	//         }
	//     }
	// }
	//
	// // TODO (kim): fallback - reauthenticate user if necessary.
	// return catcher.Resolve()
	return nil
}

// validateGroup checks that the user groups returned for this access token
// contains the expected user group.
func (m *userManager) validateGroup(groups []string) error {
	for _, group := range groups {
		if group == m.userGroup {
			return nil
		}
	}
	return errors.New("user is not in a valid group")
}

func (m *userManager) CreateUserToken(user string, password string) (string, error) {
	return "", errors.New("creating user tokens is not supported for Okta")
}

const (
	nonceCookieName = "okta-nonce"
	stateCookieName = "okta-state"
)

func (m *userManager) GetLoginHandler(callbackURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		nonce, err := util.RandomString()
		if err != nil {
			grip.Error(message.WrapError(err, message.Fields{
				"message": "could not get login handler because nonce could not be generated",
				"auth":    "Okta",
				"op":      "GetLoginHandler",
			}))
			gimlet.WriteResponse(w, gimlet.MakeTextErrorResponder(errors.Wrap(err, "could not get login handler")))
			return
		}
		state, err := util.RandomString()
		if err != nil {
			grip.Error(message.WrapError(err, message.Fields{
				"message": "could not get login handler because state could not be generated",
				"auth":    "Okta",
				"op":      "GetLoginHandler",
			}))
			gimlet.WriteResponse(w, gimlet.MakeTextErrorResponder(errors.Wrap(err, "could not get login handler")))
			return
		}

		q := r.URL.Query()
		q.Add("client_id", m.clientID)
		q.Add("response_type", "code")
		q.Add("response_mode", "query")
		q.Add("scope", "openid profile email groups offline_access")
		q.Add("redirect_uri", m.redirectURI)
		q.Add("state", state)
		q.Add("nonce", nonce)

		http.SetCookie(w, &http.Cookie{
			Name:     nonceCookieName,
			Path:     m.cookiePath,
			Value:    nonce,
			HttpOnly: true,
			Expires:  time.Now().Add(m.cookieTTL),
			Domain:   m.cookieDomain,
		})
		http.SetCookie(w, &http.Cookie{
			Name:     stateCookieName,
			Path:     m.cookiePath,
			Value:    state,
			HttpOnly: true,
			Expires:  time.Now().Add(m.cookieTTL),
			Domain:   m.cookieDomain,
		})

		http.Redirect(w, r, fmt.Sprintf("%s/oauth2/v1/authorize?%s", m.issuer, q.Encode()), http.StatusMovedPermanently)
	}
}

func (m *userManager) GetLoginCallbackHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		nonce, state, err := getNonceAndStateCookies(r.Cookies())
		if err != nil {
			err = errors.Wrap(err, "failed to get Okta nonce and state from cookies")
			grip.Error(err)
			gimlet.WriteResponse(w, gimlet.MakeTextErrorResponder(err))
			return
		}
		checkState := r.URL.Query().Get("state")
		if state != checkState {
			grip.Error(message.Fields{
				"message":        "state check failed because state from cookie did not match state from request",
				"expected_state": state,
				"actual_state":   checkState,
				"op":             "GetLoginCallbackHandler",
				"auth":           "Okta",
			})
			gimlet.WriteResponse(w, gimlet.MakeTextErrorResponder(errors.New("invalid state found during authentication")))
			return
		}

		if errCode := r.URL.Query().Get("error"); errCode != "" {
			desc := r.URL.Query().Get("error_description")
			err := fmt.Errorf("%s: %s", errCode, desc)
			grip.Error(message.WrapError(errors.WithStack(err), message.Fields{
				"message": "request to callback handler redirect contained error",
				"op":      "GetLoginCallbackHandler",
				"auth":    "Okta",
			}))
			gimlet.WriteResponse(w, gimlet.MakeTextErrorResponder(errors.Wrap(err, "could not get login callback handler")))
			return
		}

		tokens, err := m.exchangeCodeForTokens(context.Background(), r.URL.Query().Get("code"))
		if err != nil {
			err = errors.Wrap(err, "could not get authorization tokens")
			gimlet.WriteResponse(w, gimlet.MakeTextErrorResponder(err))
			grip.Error(message.WrapError(err, message.Fields{
				"message":  "failed to redeem authorization code for tokens",
				"endpoint": "/token",
				"op":       "GetLoginCallbackHandler",
				"auth":     "Okta",
			}))
			return
		}
		if err := m.validateIDToken(tokens.IDToken, nonce); err != nil {
			err = errors.Wrap(err, "invalid ID token from Okta")
			gimlet.WriteResponse(w, gimlet.MakeTextErrorResponder(err))
			grip.Error(message.WrapError(err, message.Fields{
				"message": "ID token was invalid",
				"op":      "GetLoginCallbackHandler",
				"auth":    "Okta",
			}))
			return
		}
		if err := m.validateAccessToken(tokens.AccessToken); err != nil {
			err = errors.Wrap(err, "invalid access token from Okta")
			gimlet.WriteResponse(w, gimlet.MakeTextErrorResponder(err))
			grip.Error(message.WrapError(err, message.Fields{
				"message": "access token was invalid",
				"op":      "GetLoginCallbackHandler",
				"auth":    "Okta",
			}))
			return
		}

		userInfo, err := m.getUserInfo(context.Background(), tokens.AccessToken)
		if err != nil {
			err = errors.Wrap(err, "could not retrieve user info from Okta")
			gimlet.WriteResponse(w, gimlet.MakeTextErrorResponder(err))
			grip.Error(message.WrapError(err, message.Fields{
				"message":  "could not authorize user due to failure to get user info",
				"endpoint": "/userinfo",
				"op":       "GetLoginCallbackHandler",
				"auth":     "Okta",
			}))
			return
		}
		if err := m.validateGroup(userInfo.Groups); err != nil {
			err = errors.Wrap(err, "invalid user group")
			gimlet.WriteResponse(w, gimlet.MakeTextErrorResponder(err))
			grip.Error(message.WrapError(err, message.Fields{
				"message":        "could not find user in expected user group",
				"op":             "GetLoginCallbackHandler",
				"expected_group": m.userGroup,
				"actual_groups":  userInfo.Groups,
				"auth":           "Okta",
			}))
			return
		}

		user := makeUser(userInfo, tokens.AccessToken, tokens.RefreshToken)
		loginToken, err := m.cache.Put(user)
		if err != nil {
			err = errors.Wrap(err, "failed to cache user")
			gimlet.WriteResponse(w, gimlet.MakeTextErrorResponder(err))
			grip.Error(message.WrapError(err, message.Fields{
				"message": "user could not be persisted in cache",
				"op":      "GetLoginCallbackHandler",
				"auth":    "Okta",
			}))
			return
		}

		m.setLoginCookie(w, loginToken)

		http.Redirect(w, r, m.callbackRedirectURI, http.StatusFound)
	}
}

// getNonceAndStateCookies gets the nonce and the state required in the redirect
// callback from the cookies attached to the request.
func getNonceAndStateCookies(cookies []*http.Cookie) (nonce, state string, err error) {
	for _, cookie := range cookies {
		var err error
		if cookie.Name == nonceCookieName {
			nonce, err = url.QueryUnescape(cookie.Value)
			if err != nil {
				return "", "", errors.Wrap(err, "found nonce cookie but failed to decode it")
			}
		}
		if cookie.Name == stateCookieName {
			state, err = url.QueryUnescape(cookie.Value)
			if err != nil {
				return "", "", errors.Wrap(err, "found state cookie but failed to decode it")
			}
		}
	}
	catcher := grip.NewBasicCatcher()
	catcher.NewWhen(nonce == "", "could not find nonce cookie")
	catcher.NewWhen(state == "", "could not find state cookie")
	return nonce, state, catcher.Resolve()
}

// refreshTokens exchanges the given refresh token to redeem tokens from the
// token endpoint.
func (m *userManager) refreshTokens(ctx context.Context, refreshToken string) (*tokenResponse, error) {
	q := url.Values{}
	q.Set("grant_type", "refresh_token")
	q.Set("refresh_token", refreshToken)
	return m.redeemTokens(ctx, q.Encode())
}

// exchangeCodeForTokens exchanges the given code to redeem tokens from the
// token endpoint.
func (m *userManager) exchangeCodeForTokens(ctx context.Context, code string) (*tokenResponse, error) {
	q := url.Values{}
	q.Set("grant_type", "authorization_code")
	q.Set("code", code)
	q.Set("redirect_uri", m.redirectURI)
	return m.redeemTokens(ctx, q.Encode())
}

// getUserInfo uses the access token to retrieve user information from the
// userinfo endpoint.
func (m *userManager) getUserInfo(ctx context.Context, accessToken string) (*userInfoResponse, error) {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/oauth2/v1/userinfo", m.issuer), nil)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	req = req.WithContext(ctx)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", fmt.Sprintf("Bearer "+accessToken))
	req.Header.Add("Connection", "close")

	client := m.getHTTPClient()
	defer m.putHTTPClient(client)
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "error during request for user info")
	}
	userInfo := &userInfoResponse{}
	if err := gimlet.GetJSONUnlimited(resp.Body, userInfo); err != nil {
		return nil, errors.WithStack(err)
	}
	if userInfo.ErrorCode != "" {
		return userInfo, errors.Errorf("%s: %s", userInfo.ErrorCode, userInfo.ErrorDescription)
	}
	return userInfo, nil
}

// TODO (kim): implement with fewer network calls (i.e. do not poll
// /.well-known/openid-configuration for the keys endpoint).
func (m *userManager) validateIDToken(token, nonce string) error {
	return nil
}

// TODO (kim): implement with fewer network calls (i.e. cache JWKs from
// authorization server, do not poll /.well-known/openid-configuration for the
// keys endpoint).
func (m *userManager) validateAccessToken(token string) error {
	return nil
}

func (m *userManager) IsRedirect() bool { return true }

func (m *userManager) GetUserByID(id string) (gimlet.User, error) {
	user, valid, err := m.cache.Find(id)
	if err != nil {
		return nil, errors.Wrap(err, "problem getting user by ID")
	}
	if user == nil {
		return nil, errors.New("user not found in DB")
	}
	if !valid {
		if err = m.reauthorizeUser(context.Background(), user); err != nil {
			return nil, errors.WithStack(err)
		}
	}
	return user, nil
}

func (m *userManager) GetOrCreateUser(user gimlet.User) (gimlet.User, error) {
	return m.cache.GetOrCreate(user)
}

func (m *userManager) ClearUser(user gimlet.User, all bool) error {
	return m.cache.Clear(user, all)
}

func (m *userManager) GetGroupsForUser(user string) ([]string, error) {
	return nil, errors.New("not implemented")
}

func (m *userManager) client() (*http.Client, error) {
	// TODO (kim): need to acquire an HTTP client at this point but this should
	// come from the application HTTP client pool.
	return &http.Client{}, nil
}

type tokenResponse struct {
	AccessToken      string `json:"access_token,omitempty"`
	TokenType        string `json:"token_type,omitempty"`
	ExpiresIn        int    `json:"expires_in,omitempty"`
	Scope            string `json:"scope,omitempty"`
	IDToken          string `json:"id_token,omitempty"`
	RefreshToken     string `bson:"refresh_token,omitempty"`
	ErrorCode        string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
}

type userInfoResponse struct {
	Name             string   `json:"name"`
	Profile          string   `json:"profile"`
	Email            string   `json:"email"`
	Groups           []string `json:"groups"`
	ErrorCode        string   `json:"error,omitempty"`
	ErrorDescription string   `json:"error_description,omitempty"`
}

func makeUser(info *userInfoResponse, accessToken, refreshToken string) gimlet.User {
	// TODO (kim): ID must match LDAP ID (i.e. firstname.lastname), so we
	// probably have to do some hack to get the same ID.
	return gimlet.NewBasicUser(info.Email, info.Name, info.Email, "", "", accessToken, refreshToken, info.Groups, false, nil)
}

// redeemTokens sends the request to redeem tokens with the required client
// credentials.
func (m *userManager) redeemTokens(ctx context.Context, query string) (*tokenResponse, error) {
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/oauth2/v1/token?%s", m.issuer, query), nil)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	req = req.WithContext(ctx)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Accept", "application/json")
	authHeader := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", m.clientID, m.clientSecret)))
	req.Header.Add("Authorization", fmt.Sprintf("Basic "+authHeader))
	req.Header.Add("Connection", "close")

	client := m.getHTTPClient()
	defer m.putHTTPClient(client)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "token request returned error")
	}
	tokens := &tokenResponse{}
	if err := gimlet.GetJSONUnlimited(resp.Body, tokens); err != nil {
		return nil, errors.WithStack(err)
	}
	if tokens.ErrorCode != "" {
		return tokens, errors.Errorf("%s: %s", tokens.ErrorCode, tokens.ErrorDescription)
	}
	return tokens, nil
}
