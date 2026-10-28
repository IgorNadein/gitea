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
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func TestOIDCOffboardingBrowserAndToken(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	session := loginUser(t, "user2")
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
	MakeRequest(t, req, http.StatusForbidden)
	sshKeyReq = NewRequest(t, "GET", "/api/internal/serv/none/1").SetHeader("X-Gitea-Internal-Auth", "Bearer "+setting.InternalToken)
	MakeRequest(t, sshKeyReq, http.StatusForbidden)
	resp := session.MakeRequest(t, NewRequest(t, "GET", "/user/settings"), http.StatusOK)
	require.True(t, strings.Contains(resp.Body.String(), "prohibit") || strings.Contains(resp.Body.String(), "prohibited") || strings.Contains(resp.Body.String(), "Р·Р°РїСЂРµС‰"), "blocked web session must show prohibit page")
}
func TestRealCorpDismissalOnGiteaFixture(t *testing.T) {
	if os.Getenv("GITEA_CORP_ACCEPTANCE") != "1" {
		t.Skip("isolated acceptance fixture only")
	}
	defer tests.PrepareTestEnv(t)()
	dir := os.Getenv("GITEA_CORP_ACCEPTANCE_DIR")
	require.NotEmpty(t, dir)
	session := loginUser(t, "user2")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeReadUser)
	MakeRequest(t, NewRequest(t, "GET", "/api/v1/user").AddTokenAuth(token), http.StatusOK)
	MakeRequest(t, NewRequest(t, "GET", "/api/internal/serv/none/1").SetHeader("X-Gitea-Internal-Auth", "Bearer "+setting.InternalToken), http.StatusOK)
	publicPEM, err := os.ReadFile(dir + "/gitea-corp-test-public.pem")
	require.NoError(t, err)
	block, _ := pem.Decode(publicPEM)
	require.NotNil(t, block)
	pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err)
	pub, ok := pubAny.(*rsa.PublicKey)
	require.True(t, ok)
	kidBytes, err := os.ReadFile(dir + "/gitea-corp-test-kid")
	require.NoError(t, err)
	kid := strings.TrimSpace(string(kidBytes))
	const issuer = "https://corp.example.test/o"
	var fakeBase string
	enc := base64.RawURLEncoding.EncodeToString
	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/discovery":
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "jwks_uri": fakeBase + "/keys"})
		case "/keys":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]string{"kid": kid, "kty": "RSA", "n": enc(pub.N.Bytes()), "e": enc(big.NewInt(int64(pub.E)).Bytes())}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer provider.Close()
	fakeBase = provider.URL
	oldTransport := http.DefaultTransport
	http.DefaultTransport = provider.Client().Transport
	defer func() { http.DefaultTransport = oldTransport }()
	source := &auth_model.Source{Name: "real-corp-isolated", Type: auth_model.OAuth2, IsActive: true, Cfg: &oauth2.Source{Provider: "openidConnect", ClientID: "gitea-test-client", OpenIDConnectAutoDiscoveryURL: fakeBase + "/discovery"}}
	_, err = db.GetEngine(db.DefaultContext).Insert(source)
	require.NoError(t, err)
	oldCfg := setting.CfgProvider
	defer func() { setting.CfgProvider = oldCfg }()
	cfg, err := setting.NewConfigProviderFromData(fmt.Sprintf("[oidc_backchannel]\nAUTH_SOURCE_ID=%d\n", source.ID))
	require.NoError(t, err)
	setting.CfgProvider = cfg
	_, err = db.GetEngine(db.DefaultContext).Insert(&user_model.ExternalLoginUser{ExternalID: "1", UserID: 2, LoginSourceID: source.ID, Provider: "openidConnect"})
	require.NoError(t, err)
	cert, err := tls.LoadX509KeyPair(dir+"/callback-cert.pem", dir+"/callback-key.pem")
	require.NoError(t, err)
	srv := httptest.NewUnstartedServer(testWebRoutes)
	srv.Listener.Close()
	srv.Listener, err = net.Listen("tcp", "127.0.0.1:18444")
	require.NoError(t, err)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	defer srv.Close()
	require.NoError(t, os.WriteFile(dir+"/ready", []byte("ready"), 0600))
	t.Cleanup(func() { os.Remove(dir + "/ready") })
	require.Eventually(t, func() bool { u, e := user_model.GetUserByID(db.DefaultContext, 2); return e == nil && u.ProhibitLogin }, 2*time.Minute, 300*time.Millisecond, "CORP dismissal not delivered")
	MakeRequest(t, NewRequest(t, "GET", "/api/v1/user").AddTokenAuth(token), http.StatusForbidden)
	MakeRequest(t, NewRequest(t, "GET", "/api/internal/serv/none/1").SetHeader("X-Gitea-Internal-Auth", "Bearer "+setting.InternalToken), http.StatusForbidden)
	resp := session.MakeRequest(t, NewRequest(t, "GET", "/user/settings"), http.StatusOK)
	require.Contains(t, strings.ToLower(resp.Body.String()), "prohibit")
	t.Log("REAL_CORP_DISMISSAL_GITEA_WEB_API_SSH_BLOCKED")
}
