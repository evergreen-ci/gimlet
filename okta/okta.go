package okta

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/evergreen-ci/gimlet"
	"github.com/evergreen-ci/gimlet/usercache"
	"github.com/evergreen-ci/gimlet/util"
	"github.com/mongodb/grip"
	"github.com/mongodb/grip/message"
	jwtverifier "github.com/okta/okta-jwt-verifier-golang"
	"github.com/pkg/errors"
)

// CreationOptions specify the options to create the manager.
type CreationOptions struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
	Issuer       string

	UserGroup string

	CookiePath   string
	CookieDomain string
	CookieTTL    time.Duration

	LoginCookieName string
	LoginCookieTTL  time.Duration

	UserCache     usercache.Cache
	ExternalCache *usercache.ExternalOptions

	GetHTTPClient func() *http.Client
	PutHTTPClient func(*http.Client)

	// If set, user authentication will not attempt to populate the user's
	// groups.
	SkipGroupPopulation bool

	// ReconciliateID is only used for the purposes of reconciliating existing
	// user IDs with their Okta IDs.
	ReconciliateID func(id string) (newID string)
}

func (opts *CreationOptions) Validate() error {
	catcher := grip.NewBasicCatcher()
	catcher.NewWhen(opts.ClientID == "", "must specify client ID")
	catcher.NewWhen(opts.ClientSecret == "", "must specify client secret")
	catcher.NewWhen(opts.RedirectURI == "", "must specify redirect URI")
	catcher.NewWhen(opts.Issuer == "", "must specify issuer")
	catcher.NewWhen(opts.UserGroup == "", "must specify user group")
	catcher.NewWhen(opts.CookiePath == "", "must specify cookie path")
	catcher.NewWhen(opts.LoginCookieName == "", "must specify login cookie name")
	if opts.LoginCookieTTL == time.Duration(0) {
		opts.LoginCookieTTL = time.Hour
	}
	catcher.NewWhen(opts.UserCache == nil && opts.ExternalCache == nil, "must specify one user cache")
	catcher.NewWhen(opts.UserCache != nil && opts.ExternalCache != nil, "must specify exactly one user cache")
	catcher.NewWhen(opts.GetHTTPClient == nil, "must specify function to get HTTP clients")
	catcher.NewWhen(opts.PutHTTPClient == nil, "must specify function to put HTTP clients")
	if opts.CookieTTL == time.Duration(0) {
		opts.CookieTTL = time.Hour
	}
	if opts.ReconciliateID == nil {
		opts.ReconciliateID = func(id string) string { return id }
	}
	return catcher.Resolve()
}

type userManager struct {
	clientID     string
	clientSecret string
	redirectURI  string
	issuer       string

	userGroup string

	cookiePath   string
	cookieDomain string
	cookieTTL    time.Duration

	loginCookieName string
	loginCookieTTL  time.Duration

	cache usercache.Cache

	getHTTPClient func() *http.Client
	putHTTPClient func(*http.Client)

	skipGroupPopulation bool
	reconciliateID      func(id string) (newID string)

	// This is used only for testing purposes.
	insecureSkipTokenValidation bool
}

// NewUserManager creates a manager that connects to Okta for user
// management services.
func NewUserManager(opts CreationOptions) (gimlet.UserManager, error) {
	if err := opts.Validate(); err != nil {
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
		issuer:              opts.Issuer,
		userGroup:           opts.UserGroup,
		cookiePath:          opts.CookiePath,
		cookieDomain:        opts.CookieDomain,
		cookieTTL:           opts.CookieTTL,
		loginCookieName:     opts.LoginCookieName,
		loginCookieTTL:      opts.LoginCookieTTL,
		getHTTPClient:       opts.GetHTTPClient,
		putHTTPClient:       opts.PutHTTPClient,
		skipGroupPopulation: opts.SkipGroupPopulation,
		reconciliateID:      opts.ReconciliateID,
	}
	return m, nil
}

// ErrNeedsReauthentication indicates that the user needs to be reauthenticated.
var ErrNeedsReauthentication = errors.New("user needs to be reauthenticated externally")

func (m *userManager) GetUserByToken(ctx context.Context, token string) (gimlet.User, error) {
	user, valid, err := m.cache.Get(token)
	if err != nil {
		return nil, errors.Wrap(err, "problem getting cached user")
	}
	if user == nil {
		return nil, errors.New("user not found in cache")
	}
	if !valid {
		return nil, errors.Wrapf(ErrNeedsReauthentication, "could not get user %s", user.Username())
		// if err = m.reauthorizeUser(ctx, user); err != nil {
		//     return nil, errors.Wrap(err, "problem reauthorizing user")
		// }
	}
	return user, nil
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
	nonceCookieName      = "okta-nonce"
	stateCookieName      = "okta-state"
	requestURICookieName = "okta-original-request-uri"
)

func (m *userManager) GetLoginHandler(_ string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		nonce, err := util.RandomString()
		if err != nil {
			err = errors.Wrap(err, "could not get login handler")
			grip.Critical(message.WrapError(err, message.Fields{
				"reason": "nonce could not be generated",
			}))
			writeError(w, err)
			return
		}
		state, err := util.RandomString()
		if err != nil {
			err = errors.Wrap(err, "could not get login handler")
			grip.Critical(message.WrapError(err, message.Fields{
				"reason": "state could not be generated",
			}))
			writeError(w, err)
			return
		}

		q := r.URL.Query()
		redirectURI := q.Get("redirect")
		if redirectURI == "" {
			redirectURI = "/"
		}

		m.setTemporaryCookie(w, nonceCookieName, nonce)
		m.setTemporaryCookie(w, stateCookieName, state)
		m.setTemporaryCookie(w, requestURICookieName, redirectURI)

		q.Add("client_id", m.clientID)
		q.Add("response_type", "code")
		q.Add("response_mode", "query")
		q.Add("scope", "openid email profile offline_access groups")
		q.Add("prompt", "login consent")
		q.Add("redirect_uri", m.redirectURI)
		q.Add("state", state)
		q.Add("nonce", nonce)

		http.Redirect(w, r, fmt.Sprintf("%s/oauth2/v1/authorize?%s", m.issuer, q.Encode()), http.StatusMovedPermanently)
	}
}

func (m *userManager) setLoginCookie(w http.ResponseWriter, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     m.loginCookieName,
		Path:     m.cookiePath,
		Value:    url.QueryEscape(value),
		HttpOnly: true,
		Expires:  time.Now().Add(m.loginCookieTTL),
		Domain:   m.cookieDomain,
	})
}

// setTemporaryCookie sets a short-lived cookie that is required for login to
// succeed via Okta.
func (m *userManager) setTemporaryCookie(w http.ResponseWriter, name, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Path:     m.cookiePath,
		Value:    url.QueryEscape(value),
		HttpOnly: true,
		Expires:  time.Now().Add(m.cookieTTL),
		Domain:   m.cookieDomain,
	})
}

func writeError(w http.ResponseWriter, err error) {
	gimlet.WriteResponse(w, gimlet.MakeTextErrorResponder(gimlet.ErrorResponse{
		StatusCode: http.StatusInternalServerError,
		Message:    err.Error(),
	}))
}

func (m *userManager) GetLoginCallbackHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if errCode := r.URL.Query().Get("error"); errCode != "" {
			desc := r.URL.Query().Get("error_description")
			err := fmt.Errorf("%s: %s", errCode, desc)
			err = errors.Wrap(err, "callback handler received error from Okta")
			grip.Error(err)
			writeError(w, err)
			return
		}

		nonce, state, requestURI, err := getCookies(r)
		if err != nil {
			err = errors.Wrap(err, "failed to get Okta nonce and state from cookies")
			grip.Error(err)
			writeError(w, err)
			return
		}
		checkState := r.URL.Query().Get("state")
		if state != checkState {
			err = errors.New("state value received from Okta did not match expected state")
			grip.Error(message.WrapError(err, message.Fields{
				"expected_state": state,
				"actual_state":   checkState,
			}))
			writeError(w, err)
			return
		}

		tokens, idToken, err := m.getUserTokens(r.URL.Query().Get("code"), nonce)
		if err != nil {
			writeError(w, err)
			return
		}

		var user gimlet.User
		if m.skipGroupPopulation && !m.insecureSkipTokenValidation {
			user, err = m.generateUserFromIDToken(tokens, idToken)
			if err != nil {
				grip.Error(err)
				writeError(w, err)
				return
			}
		} else {
			user, err = m.generateUserFromInfo(tokens)
			if err != nil {
				grip.Error(err)
				writeError(w, err)
				return
			}
		}

		user, err = m.GetOrCreateUser(user)
		if err != nil {
			err = errors.Wrap(err, "failed to get or create cached user")
			grip.Error(err)
			gimlet.MakeTextErrorResponder(err)
			return
		}

		loginToken, err := m.cache.Put(user)
		if err != nil {
			err = errors.Wrapf(err, "failed to cache user %s", user.Username())
			grip.Error(err)
			writeError(w, err)
			return
		}

		m.setLoginCookie(w, loginToken)

		http.Redirect(w, r, requestURI, http.StatusFound)
	}
}

// getUserTokens redeems the authorization code for tokens and validates the
// received tokens.
func (m *userManager) getUserTokens(code, nonce string) (*tokenResponse, *jwtverifier.Jwt, error) {
	tokens, err := m.exchangeCodeForTokens(context.Background(), code)
	if err != nil {
		return nil, nil, errors.Wrap(err, "could not redeem authorization code for tokens")
	}

	if m.insecureSkipTokenValidation {
		return tokens, nil, nil
	}

	idToken, err := m.validateIDToken(tokens.IDToken, nonce)
	if err != nil {
		return nil, nil, errors.Wrap(err, "invalid ID token from Okta")
	}
	if err := m.validateAccessToken(tokens.AccessToken); err != nil {
		return nil, nil, errors.Wrap(err, "invalid access token from Okta")
	}
	return tokens, idToken, nil
}

// generateUserFromInfo creates a user based on information from the userinfo
// endpoint.
func (m *userManager) generateUserFromInfo(tokens *tokenResponse) (gimlet.User, error) {
	userInfo, err := m.getUserInfo(context.Background(), tokens.AccessToken)
	if err != nil {
		err = errors.Wrap(err, "could not retrieve user info from Okta")
		grip.Error(message.WrapError(err, message.Fields{
			"message":  "could not authorize user due to failure to get user info",
			"endpoint": "userinfo",
		}))
		return nil, err
	}
	if err := m.validateGroup(userInfo.Groups); err != nil {
		err = errors.Wrap(err, "user is not in a valid group for the organization")
		grip.Error(message.WrapError(err, message.Fields{
			"expected_group": m.userGroup,
			"actual_groups":  userInfo.Groups,
		}))
		return nil, err
	}
	return makeUserFromInfo(userInfo, tokens.AccessToken, tokens.RefreshToken, m.reconciliateID)
}

// generateUserFromIDToken creates a user based on claims in their ID token.
func (m *userManager) generateUserFromIDToken(tokens *tokenResponse, idToken *jwtverifier.Jwt) (gimlet.User, error) {
	user, err := makeUserFromIDToken(idToken, tokens.AccessToken, tokens.RefreshToken, m.reconciliateID)
	if err != nil {
		err = errors.Wrap(err, "could not generate user from user info received from Okta")
		grip.Error(err)
		return nil, err
	}

	return user, nil
}

// getCookies gets the nonce and the state required in the redirect callback as
// well as the originally requested URI from the cookies.
func getCookies(r *http.Request) (nonce, state, requestURI string, err error) {
	for _, cookie := range r.Cookies() {
		var err error
		if cookie.Name == nonceCookieName {
			nonce, err = url.QueryUnescape(cookie.Value)
			if err != nil {
				return "", "", "", errors.Wrap(err, "found nonce cookie but failed to decode it")
			}
		}
		if cookie.Name == stateCookieName {
			state, err = url.QueryUnescape(cookie.Value)
			if err != nil {
				return "", "", "", errors.Wrap(err, "found state cookie but failed to decode it")
			}
		}
		if cookie.Name == requestURICookieName {
			requestURI, err = url.QueryUnescape(cookie.Value)
			if err != nil {
				grip.Error(errors.Wrap(err, "found original request URI cokoie but failed to decode it"))
			}
		}
	}
	catcher := grip.NewBasicCatcher()
	catcher.NewWhen(nonce == "", "could not find nonce cookie")
	catcher.NewWhen(state == "", "could not find state cookie")
	if requestURI == "" {
		requestURI = "/"
	}
	return nonce, state, requestURI, catcher.Resolve()
}

func (m *userManager) IsRedirect() bool { return true }

func (m *userManager) GetUserByID(id string) (gimlet.User, error) {
	user, valid, err := m.cache.Find(id)
	if err != nil {
		return nil, errors.Wrap(err, "problem getting user by ID")
	}
	if user == nil {
		return nil, errors.New("user not found in cache")
	}
	if !valid {
		return nil, errors.Wrapf(ErrNeedsReauthentication, "could not get user %s", id)
		// if err = m.reauthorizeUser(context.Background(), user); err != nil {
		//     return nil, errors.WithStack(err)
		// }
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

func (m *userManager) addAuthHeader(r *http.Request) {
	r.Header.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", m.clientID, m.clientSecret))))
}

// validateIDToken verifies that the ID token is valid and returns it.
func (m *userManager) validateIDToken(token, nonce string) (*jwtverifier.Jwt, error) {
	verifier := jwtverifier.JwtVerifier{
		Issuer: m.issuer,
		ClaimsToValidate: map[string]string{
			"aud":   m.clientID,
			"nonce": nonce,
		},
	}
	return verifier.New().VerifyIdToken(token)
}

// validateAccessToken verifies that the access token is valid.
// TODO (kim): figure out why this does not validate with the same jwt verifier
// library as used for the ID token.
func (m *userManager) validateAccessToken(token string) error {
	info, err := m.getTokenInfo(context.Background(), token, "access_token")
	if err != nil {
		return errors.Wrap(err, "could not check if token is valid")
	}
	if !info.Active {
		return errors.New("access token is inactive, so authorization is not possible")
	}
	return nil
}

// refreshTokens exchanges the given refresh token to redeem tokens from the
// token endpoint.
func (m *userManager) refreshTokens(ctx context.Context, refreshToken string) (*tokenResponse, error) {
	q := url.Values{}
	q.Set("grant_type", "refresh_token")
	q.Set("refresh_token", refreshToken)
	q.Set("scope", "openid email profile offline_access groups")
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

// tokenResponse represents a response received from the token endpoint.
type tokenResponse struct {
	AccessToken      string `json:"access_token,omitempty"`
	IDToken          string `json:"id_token,omitempty"`
	RefreshToken     string `json:"refresh_token,omitempty"`
	TokenType        string `json:"token_type,omitempty"`
	ExpiresIn        int    `json:"expires_in,omitempty"`
	Scope            string `json:"scope,omitempty"`
	ErrorCode        string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// redeemTokens sends the request to redeem tokens with the required client
// credentials.
func (m *userManager) redeemTokens(ctx context.Context, query string) (*tokenResponse, error) {
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/oauth2/v1/token", m.issuer), bytes.NewBufferString(query))
	if err != nil {
		return nil, errors.WithStack(err)
	}
	req = req.WithContext(ctx)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Connection", "close")
	m.addAuthHeader(req)

	client := m.getHTTPClient()
	defer m.putHTTPClient(client)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	start := time.Now()
	resp, err := client.Do(req)
	grip.Info(message.Fields{
		"endpoint":    "token",
		"duration_ms": int64(time.Since(start) / time.Millisecond),
		"context":     "Okta user manager",
	})
	if err != nil {
		return nil, errors.Wrap(err, "request to redeem token returned error")
	}
	if resp.StatusCode != http.StatusOK {
		catcher := grip.NewBasicCatcher()
		catcher.Errorf("received unexpected status code %d", resp.StatusCode)
		catcher.Wrap(resp.Body.Close(), "error closing response body")
		return nil, catcher.Resolve()
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

// userInfo represents a response received from the userinfo endpoint.
type userInfoResponse struct {
	Name             string   `json:"name"`
	Email            string   `json:"email"`
	Groups           []string `json:"groups"`
	ErrorCode        string   `json:"error,omitempty"`
	ErrorDescription string   `json:"error_description,omitempty"`
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
	start := time.Now()
	resp, err := client.Do(req)
	grip.Info(message.Fields{
		"endpoint":    "userinfo",
		"duration_ms": int64(time.Since(start) / time.Millisecond),
		"context":     "Okta user manager",
	})
	if err != nil {
		return nil, errors.Wrap(err, "error during request for user info")
	}
	if resp.StatusCode != http.StatusOK {
		catcher := grip.NewBasicCatcher()
		catcher.Errorf("received unexpected status code %d", resp.StatusCode)
		catcher.Wrap(resp.Body.Close(), "error closing response body")
		return nil, catcher.Resolve()
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

// introspectResponse represents a response received from the introspect
// endpoint.
type introspectResponse struct {
	Active           bool   `json:"active,omitempty"`
	Audience         string `json:"aud,omitempty"`
	ClientID         string `json:"client_id"`
	DeviceID         string `json:"device_id"`
	ExpiresUnix      int    `json:"exp"`
	IssuedAtUnix     int    `json:"iat"`
	Issuer           string `json:"iss"`
	TokenIdentifier  string `json:"jti"`
	NotBeforeUnix    int    `json:"nbf"`
	Scopes           string `json:"scope"`
	Subject          string `json:"sub"`
	TokenType        string `json:"token_type"`
	UserID           string `json:"uid"`
	UserName         string `json:"username"`
	ErrorCode        string `json:"error_code,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// getTokenInfo information about the given token.
func (m *userManager) getTokenInfo(ctx context.Context, token, tokenType string) (*introspectResponse, error) {
	q := url.Values{}
	q.Add("token", token)
	q.Add("token_type_hint", tokenType)
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/oauth2/v1/introspect", m.issuer), strings.NewReader(q.Encode()))
	if err != nil {
		return nil, errors.WithStack(err)
	}
	req = req.WithContext(ctx)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Connection", "close")
	m.addAuthHeader(req)

	client := m.getHTTPClient()
	defer m.putHTTPClient(client)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	start := time.Now()
	resp, err := client.Do(req)
	grip.Info(message.Fields{
		"endpoint":    "introspect",
		"duration_ms": int64(time.Since(start) / time.Millisecond),
		"context":     "Okta user manager",
	})
	if err != nil {
		return nil, errors.Wrap(err, "request to introspect token returned error")
	}
	if resp.StatusCode != http.StatusOK {
		catcher := grip.NewBasicCatcher()
		catcher.Errorf("received unexpected status code %d", resp.StatusCode)
		catcher.Wrap(resp.Body.Close(), "error closing response body")
		return nil, catcher.Resolve()
	}

	tokenInfo := &introspectResponse{}
	if err := gimlet.GetJSONUnlimited(resp.Body, tokenInfo); err != nil {
		return nil, errors.WithStack(err)
	}
	if tokenInfo.ErrorCode != "" {
		return tokenInfo, errors.Errorf("%s: %s", tokenInfo.ErrorCode, tokenInfo.ErrorDescription)
	}
	return tokenInfo, nil
}

// makeUserFromInfo returns a user based on information from a userinfo request.
func makeUserFromInfo(info *userInfoResponse, accessToken, refreshToken string, reconciliateID func(string) string) (gimlet.User, error) {
	id := info.Email
	if reconciliateID != nil {
		id = reconciliateID(id)
	}
	if id == "" {
		return nil, errors.New("could not create user ID from email")
	}
	return gimlet.NewBasicUser(id, info.Name, info.Email, "", "", accessToken, refreshToken, info.Groups, false, nil), nil
}

// makeUserFromIDToken returns a user based on information from an ID token.
func makeUserFromIDToken(jwt *jwtverifier.Jwt, accessToken, refreshToken string, reconciliateID func(string) string) (gimlet.User, error) {
	email, ok := jwt.Claims["email"].(string)
	if !ok {
		return nil, errors.New("user is missing email")
	}
	id := email
	if reconciliateID != nil {
		id = reconciliateID(id)
	}
	if id == "" {
		return nil, errors.New("could not create user ID from email")
	}
	name, ok := jwt.Claims["name"].(string)
	if !ok {
		return nil, errors.New("user is missing name")
	}
	return gimlet.NewBasicUser(id, name, email, "", "", accessToken, refreshToken, []string{}, false, nil), nil
}
