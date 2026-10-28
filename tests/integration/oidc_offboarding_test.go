package integration

import (
	auth_model "code.gitea.io/gitea/models/auth"
	"code.gitea.io/gitea/models/db"
	user_model "code.gitea.io/gitea/models/user"
	"code.gitea.io/gitea/modules/setting"
	"code.gitea.io/gitea/services/auth/source/oauth2"
	"code.gitea.io/gitea/tests"
	"crypto/rand"
	"crypto/rsa"

	"encoding/base64"
	"encoding/json"

	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
	"math/big"

	"net/http"
	"net/http/httptest"
	"net/url"

	"testing"
	"time"
)

func TestOIDCOffboardingBrowserAndToken(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	session := loginUser(t, "user2")
	secondSession := loginUser(t, "user2")
	otherSession := loginUser(t, "user4")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeReadUser, auth_model.AccessTokenScopeReadRepository)
	req := NewRequest(t, "GET", "/api/v1/user").AddTokenAuth(token)
	MakeRequest(t, req, http.StatusOK)
	sshKeyReq := NewRequest(t, "GET", "/api/internal/serv/none/1").SetHeader("X-Gitea-Internal-Auth", "Bearer "+setting.InternalToken)
	MakeRequest(t, sshKeyReq, http.StatusOK)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	enc := base64.RawURLEncoding.EncodeToString
	var issuer string
	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/discovery":
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "jwks_uri": issuer + "/keys"})
		case "/keys":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]string{"kid": "fixture", "kty": "RSA", "n": enc(key.N.Bytes()), "e": enc(big.NewInt(int64(key.E)).Bytes())}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer provider.Close()
	issuer = provider.URL
	oldTransport := http.DefaultTransport
	http.DefaultTransport = provider.Client().Transport
	defer func() { http.DefaultTransport = oldTransport }()
	source := &auth_model.Source{Name: "offboarding-integration", Type: auth_model.OAuth2, IsActive: true, Cfg: &oauth2.Source{Provider: "openidConnect", ClientID: "fixture-client", OpenIDConnectAutoDiscoveryURL: issuer + "/discovery"}}
	_, err = db.GetEngine(db.DefaultContext).Insert(source)
	require.NoError(t, err)
	oldConfig := setting.CfgProvider
	defer func() { setting.CfgProvider = oldConfig }()
	cfg, err := setting.NewConfigProviderFromData(fmt.Sprintf("[oidc_backchannel]\nAUTH_SOURCE_ID=%d\n", source.ID))
	require.NoError(t, err)
	setting.CfgProvider = cfg
	_, err = db.GetEngine(db.DefaultContext).Insert(&user_model.ExternalLoginUser{ExternalID: "fixture-subject", UserID: 2, LoginSourceID: source.ID, Provider: "openidConnect"})
	require.NoError(t, err)
	now := time.Now().Unix()
	signed := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"iss": issuer, "sub": "fixture-subject", "aud": "fixture-client", "iat": now, "exp": now + 300, "jti": "event-fixture", "events": map[string]any{"http://schemas.openid.net/event/backchannel-logout": map[string]any{}}})
	signed.Header["kid"] = "fixture"
	raw, err := signed.SignedString(key)
	require.NoError(t, err)
	req = NewRequestWithURLValues(t, "POST", "/-/oidc-backchannel-logout", url.Values{"logout_token": {raw}})
	MakeRequest(t, req, http.StatusOK)
	req = NewRequest(t, "GET", "/api/v1/user").AddTokenAuth(token)
	MakeRequest(t, req, http.StatusOK)
	sshKeyReq = NewRequest(t, "GET", "/api/internal/serv/none/1").SetHeader("X-Gitea-Internal-Auth", "Bearer "+setting.InternalToken)
	MakeRequest(t, sshKeyReq, http.StatusOK)
	session.MakeRequest(t, NewRequest(t, "GET", "/user/settings"), http.StatusSeeOther)
	secondSession.MakeRequest(t, NewRequest(t, "GET", "/user/settings"), http.StatusSeeOther)
	otherSession.MakeRequest(t, NewRequest(t, "GET", "/user/settings"), http.StatusOK)
	// A fresh login works and a replay of the same logout cannot revoke it.
	fresh := loginUser(t, "user2")
	MakeRequest(t, NewRequestWithURLValues(t, "POST", "/-/oidc-backchannel-logout", url.Values{"logout_token": {raw}}), http.StatusOK)
	fresh.MakeRequest(t, NewRequest(t, "GET", "/user/settings"), http.StatusOK)
}
