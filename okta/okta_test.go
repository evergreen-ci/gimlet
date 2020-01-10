package okta

import (
	"context"
	"net/http"
	"testing"

	"github.com/evergreen-ci/gimlet"
	"github.com/stretchr/testify/require"
)

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
	AuthorizeParameters map[string][]string
	// AuthorizeResponse is returned from the userinfo endpoint.
	AuthorizeResponse map[string]interface{}
	// TokenParameters are parameters sent to the token endpoint.
	TokenParameters map[string][]string
	// TokenResponse is returned from the token endpoint.
	TokenResponse map[string]interface{}
	// UserInfoParameters are parameters sent to the userinfo endpoint.
	UserInfoParameters map[string][]string
	// UserInfoResponse isre returned from the userinfo endpoint.
	UserInfoResponse map[string]interface{}
}

func (s *mockAuthorizationServer) startMockServer(t *testing.T, ctx context.Context, port int) error {
	app := gimlet.NewApp()
	require.NoError(t, app.SetHost("localhost"))
	require.NoError(t, app.SetPort(port))

	app.AddRoute("/oauth2/v1/authorize").Version(1).Get().Handler(s.authorize)
	// app.AddRoute("/oauth2/v1/authorize/echo").Version(1).Get().Handler(s.echoAuthorize)
	app.AddRoute("/oauth2/v1/token").Version(1).Get().Handler(s.token)
	app.AddRoute("/oauth2/v1/userinfo").Version(1).Get().Handler(s.userinfo)

	return nil
}

func (s *mockAuthorizationServer) authorize(rw http.ResponseWriter, r *http.Request) {
	s.AuthorizeParameters = r.URL.Query()
	gimlet.WriteJSON(rw, s.AuthorizeResponse)
}

// func (s *mockAuthorizationServer) authorizeEcho(rw http.ResponseWriter, r *http.Request) {
//     doEcho(rw, s.AuthorizeParameters)
// }

func (s *mockAuthorizationServer) token(rw http.ResponseWriter, r *http.Request) {
	s.TokenParameters = r.URL.Query()
	gimlet.WriteJSON(rw, s.TokenResponse)
}

// func (s *mockAuthorizationServer) tokenEcho(rw http.ResponseWriter, r *http.Request) {
//     doEcho(rw, s.TokenParameters)
// }

func (s *mockAuthorizationServer) userinfo(rw http.ResponseWriter, r *http.Request) {
	s.UserInfoParameters = r.URL.Query()
	gimlet.WriteJSON(rw, s.UserInfoResponse)
}

// func doEcho(rw http.ResponseWriter, data interface{}) {
//     b, err := json.Marshal(data)
//     if err != nil {
//         gimlet.WriteJSONResponse(rw, http.StatusInternalServerError, gimlet.ErrorResponse{
//             StatusCode: http.StatusInternalServerError,
//             Message:    errors.Wrap(err, "could not serialize echo parameters").Error(),
//         })
//         return
//     }
//     gimlet.WriteJSON(rw, b)
// }

func TestRequestHelpers(t *testing.T) {

}
