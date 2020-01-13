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
	verifier "github.com/okta/okta-jwt-verifier-golang"
	"github.com/pkg/errors"
)

// CreationOptions specify the options to create the manager.
type CreationOptions struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
	Issuer       string
	Audience     string

	UserGroup string

	CookiePath   string
	CookieDomain string
	CookieTTL    time.Duration

	LoginCookieName string
	LoginCookieTTL  time.Duration

	UserCache     usercache.Cache
	ExternalCache *usercache.ExternalOptions
}

func (opts *CreationOptions) validate() error {
	catcher := grip.NewBasicCatcher()
	catcher.NewWhen(opts.ClientID == "", "must specify client ID")
	catcher.NewWhen(opts.ClientSecret == "", "must specify client secret")
	catcher.NewWhen(opts.RedirectURI == "", "must specify redirect URI")
	catcher.NewWhen(opts.Issuer == "", "must specify issuer")
	catcher.NewWhen(opts.Audience == "", "must specify audience")
	catcher.NewWhen(opts.CookiePath == "", "must specify cookie path")
	catcher.NewWhen(opts.CookieDomain == "", "must specify cookie domain")
	catcher.NewWhen(opts.UserCache == nil && opts.ExternalCache == nil, "must specify user cache")
	if opts.CookieTTL == time.Duration(0) {
		opts.CookieTTL = time.Hour
	}
	if opts.LoginCookieTTL == time.Duration(0) {
		opts.LoginCookieTTL = 365 * 24 * time.Hour
	}
	return catcher.Resolve()
}

type userManager struct {
	clientID     string
	clientSecret string
	redirectURI  string
	issuer       string
	audience     string

	userGroup string

	loginCookieName string
	loginCookieTTL  time.Duration

	cookiePath   string
	cookieDomain string
	cookieTTL    time.Duration

	cache usercache.Cache
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
		cache:           cache,
		clientID:        opts.ClientID,
		clientSecret:    opts.ClientSecret,
		audience:        opts.Audience,
		redirectURI:     opts.RedirectURI,
		issuer:          opts.Issuer,
		cookiePath:      opts.CookiePath,
		cookieDomain:    opts.CookieDomain,
		cookieTTL:       opts.CookieTTL,
		loginCookieName: opts.LoginCookieName,
		loginCookieTTL:  opts.LoginCookieTTL,
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
	accessToken := user.GetAccessToken()
	catcher := grip.NewBasicCatcher()
	catcher.Wrap(m.validateAccessToken(user.GetAccessToken()), "invalid access token")
	if !catcher.HasErrors() {
		userInfo, err := m.getUserInfo(ctx, accessToken)
		catcher.Wrap(err, "could not get user info")
		if err == nil {
			err := m.validateGroup(userInfo.Groups)
			catcher.Wrap(err, "could not validate user group")
			if err == nil {
				_, err = m.cache.Put(user)
				catcher.Wrap(err, "could not add user to cache")
				if err == nil {
					return nil
				}
			}
		}
	}
	refreshToken := user.GetRefreshToken()
	tokens, err := m.refreshTokens(ctx, refreshToken)
	catcher.Wrap(err, "could not refresh authorization tokens")
	if err == nil {
		userInfo, err := m.getUserInfo(ctx, tokens.AccessToken)
		catcher.Wrap(err, "could not get user info")
		if err == nil {
			err := m.validateGroup(userInfo.Groups)
			catcher.Wrap(err, "could not validate user group")
			if err == nil {
				// TODO (kim): update user tokens
				user = makeUser(userInfo, accessToken, refreshToken)
				_, err = m.cache.Put(user)
				catcher.Wrap(err, "could not add user to cache")
				if err == nil {
					return nil
				}
			}
		}
	}

	// TODO (kim): fallback - reauthenticate user.
	return catcher.Resolve()
}

// validateGroup checks that the user groups returned for this access token
// contains the expected user group.
func (m *userManager) validateGroup(groups []string) error {
	for _, group := range groups {
		if group == m.userGroup {
			return nil
		}
	}
	return errors.New("user is not in user group")
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
				"message": "could not get login handler",
			}))
			gimlet.WriteResponse(w, gimlet.MakeTextErrorResponder(errors.Wrap(err, "could not get login handler")))
			return
		}
		state, err := util.RandomString()
		if err != nil {
			grip.Error(message.WrapError(err, message.Fields{
				"message": "could not get login handler",
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
		// TODO (kim): set temporary cookie that will redirect user to the
		// original page they requested, if redirect callback succeeds.

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
				"message":        "mismatched states during authentication",
				"context":        "Okta",
				"expected_state": state,
				"actual_state":   checkState,
			})
			gimlet.WriteResponse(w, gimlet.MakeTextErrorResponder(errors.New("mismatched states during authentication")))
			return
		}

		if errCode := r.URL.Query().Get("error"); errCode != "" {
			desc := r.URL.Query().Get("error_description")
			err := fmt.Errorf("%s: %s", errCode, desc)
			grip.Error(message.WrapError(errors.WithStack(err), message.Fields{
				"message": "failure in callback handler redirect",
				"op":      "GetLoginCallbackHandler",
				"auth":    "Okta",
			}))
			gimlet.WriteResponse(w, gimlet.MakeTextErrorResponder(errors.Wrap(err, "could not get login callback handler")))
			return
		}

		tokens, err := m.exchangeCodeForTokens(context.Background(), r.URL.Query().Get("code"))
		if err != nil {
			err = errors.Wrap(err, "could not get ID token")
			gimlet.WriteResponse(w, gimlet.MakeTextErrorResponder(err))
			grip.Error(message.WrapError(err, message.Fields{
				"message": "failed to get token from Okta",
				"op":      "GetLoginCallbackHandler",
				"auth":    "Okta",
			}))
			return
		}
		if err := m.validateIDToken(tokens.IDToken, nonce); err != nil {
			err = errors.Wrap(err, "could not validate ID token from Okta")
			gimlet.WriteResponse(w, gimlet.MakeTextErrorResponder(err))
			grip.Error(message.WrapError(err, message.Fields{
				"message": "failed to validate ID token",
				"op":      "GetLoginCallbackHandler",
				"auth":    "Okta",
			}))
			return
		}
		if err := m.validateAccessToken(tokens.AccessToken); err != nil {
			err = errors.Wrap(err, "could not validate access token from Okta")
			gimlet.WriteResponse(w, gimlet.MakeTextErrorResponder(err))
			grip.Error(message.WrapError(err, message.Fields{
				"message": "failed to validate access token",
				"op":      "GetLoginCallbackHandler",
				"auth":    "Okta",
			}))
			return
		}

		userInfo, err := m.getUserInfo(context.Background(), tokens.AccessToken)
		if err != nil {
			err = errors.Wrap(err, "could not get user info from Okta")
			gimlet.WriteResponse(w, gimlet.MakeTextErrorResponder(err))
			grip.Error(message.WrapError(err, message.Fields{
				"message": "failed to validate access token",
				"op":      "GetLoginCallbackHandler",
				"auth":    "Okta",
			}))
			return
		}
		if err := m.validateGroup(userInfo.Groups); err != nil {
			err = errors.Wrap(err, "could not validate user groups")
			gimlet.WriteResponse(w, gimlet.MakeTextErrorResponder(err))
			grip.Error(message.WrapError(err, message.Fields{
				"message": "failed to validate user groups",
				"op":      "GetLoginCallbackHandler",
				"auth":    "Okta",
			}))
			return
		}

		user := makeUser(userInfo, tokens.AccessToken, tokens.RefreshToken)
		token, err := m.cache.Put(user)
		if err != nil {
			err = errors.Wrap(err, "error putting user in cache")
			gimlet.WriteResponse(w, gimlet.MakeTextErrorResponder(err))
			grip.Error(message.WrapError(err, message.Fields{
				"message": "failed to cache user",
				"op":      "GetLoginCallbackHandler",
				"auth":    "Okta",
			}))
			return
		}

		grip.Info(message.Fields{
			"message":   "successfully authenticated user and validated tokens",
			"op":        "GetLoginCallbackHandler",
			"context":   "Okta",
			"tokens":    fmt.Sprintf("%+v", *tokens),
			"user_info": fmt.Sprintf("%+v", *userInfo),
		})
		http.SetCookie(w, &http.Cookie{
			Name:     m.loginCookieName,
			Path:     m.cookiePath,
			Value:    token,
			HttpOnly: true,
			Expires:  time.Now().Add(m.loginCookieTTL),
			Domain:   m.cookieDomain,
		})

		http.Redirect(w, r, m.redirectURI, http.StatusFound)
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
				return "", "", errors.Wrap(err, "problem reading nonce cookie")
			}
		}
		if cookie.Name == stateCookieName {
			state, err = url.QueryUnescape(cookie.Value)
			if err != nil {
				return "", "", errors.Wrap(err, "problem reading state cookie")
			}
		}
	}
	catcher := grip.NewBasicCatcher()
	catcher.NewWhen(nonce == "", "could not get cookie for nonce")
	catcher.NewWhen(state == "", "could not get cookie for state")
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

	client, err := m.client()
	if err != nil {
		return nil, errors.WithStack(err)
	}

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

func (m *userManager) validateIDToken(token, nonce string) error {
	validator := verifier.JwtVerifier{
		Issuer: m.issuer,
		ClaimsToValidate: map[string]string{
			"nonce": nonce,
			"aud":   m.clientID,
		},
	}
	res, err := validator.New().VerifyIdToken(token)
	if err != nil {
		return errors.Wrap(err, "could not verify ID token")
	}
	if res == nil {
		return errors.New("id token validation returned empty result")
	}
	return nil
}

func (m *userManager) validateAccessToken(token string) error {
	// validator := verifier.JwtVerifier{
	//     Issuer: m.issuer,
	//     ClaimsToValidate: map[string]string{
	//         "cid": m.clientID,
	//         "aud": m.audience,
	//     },
	// }
	// res, err := validator.New().VerifyAccessToken(token)
	// if err != nil {
	//     return errors.Wrap(err, "could not verify access token")
	// }
	// if res == nil {
	//     return errors.New("access token validation returned empty result")
	// }
	return nil
}

func (m *userManager) IsRedirect() bool { return true }

func (m *userManager) GetUserByID(user string) (gimlet.User, error) {
	return nil, errors.New("not implemented")
}

func (m *userManager) GetOrCreateUser(user gimlet.User) (gimlet.User, error) {
	return nil, errors.New("not implemented")
}

func (m *userManager) ClearUser(user gimlet.User, all bool) error {
	return errors.New("not implemented")
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

	client, err := m.client()
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
