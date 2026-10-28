package auth

import (
	auth_model "code.gitea.io/gitea/models/auth"
	"code.gitea.io/gitea/models/db"
	"code.gitea.io/gitea/models/system"
	"code.gitea.io/gitea/models/unittest"
	user_model "code.gitea.io/gitea/models/user"
	"code.gitea.io/gitea/modules/setting"
	"code.gitea.io/gitea/services/auth/source/oauth2"
	gitea_context "code.gitea.io/gitea/services/context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestBackchannelTokenValidation(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	jwksJSON, _ := json.Marshal(map[string]any{"keys": []any{map[string]string{"kid": "fixture", "kty": "RSA", "alg": "RS256", "n": enc(key.N.Bytes()), "e": enc(big.NewInt(int64(key.E)).Bytes())}}})
	var keys oidcJWKS
	if err = json.Unmarshal(jwksJSON, &keys); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	cases := []struct {
		name   string
		mutate func(jwt.MapClaims)
		good   bool
	}{
		{"valid", func(jwt.MapClaims) {}, true},
		{"wrong issuer", func(c jwt.MapClaims) { c["iss"] = "https://evil.example" }, false},
		{"wrong audience", func(c jwt.MapClaims) { c["aud"] = "another-client" }, false},
		{"expired", func(c jwt.MapClaims) { c["exp"] = now - 1 }, false},
		{"future issuance", func(c jwt.MapClaims) { c["iat"] = now + 120 }, false},
		{"nonce", func(c jwt.MapClaims) { c["nonce"] = "abc" }, false},
		{"sid", func(c jwt.MapClaims) { c["sid"] = "abc" }, false},
		{"missing event", func(c jwt.MapClaims) { delete(c, "events") }, false},
		{"missing subject", func(c jwt.MapClaims) { delete(c, "sub") }, false},
		{"missing id", func(c jwt.MapClaims) { delete(c, "jti") }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claims := jwt.MapClaims{"iss": "https://provider.example", "sub": "123", "aud": "client", "iat": now, "exp": now + 300, "jti": "event", "events": map[string]any{logoutEvent: map[string]any{}}}
			tc.mutate(claims)
			tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
			tok.Header["kid"] = "fixture"
			signed, err := tok.SignedString(key)
			if err != nil {
				t.Fatal(err)
			}
			_, err = verifyLogout(signed, "https://provider.example", "client", &keys)
			if (err == nil) != tc.good {
				t.Fatalf("success = %v, error = %v", err == nil, err)
			}
		})
	}
	attacker, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	forged := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"iss": "https://provider.example", "sub": "123", "aud": "client", "iat": now, "exp": now + 300, "jti": "event", "events": map[string]any{logoutEvent: map[string]any{}}})
	forged.Header["kid"] = "fixture"
	signed, err := forged.SignedString(attacker)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = verifyLogout(signed, "https://provider.example", "client", &keys); err == nil {
		t.Fatal("forged signature accepted")
	}

}

func TestBackchannelRevokesSessionsAndRejectsReplay(t *testing.T) {
	if err := unittest.PrepareTestDatabase(); err != nil {
		t.Fatal(err)
	}
	ctx := db.DefaultContext
	u, err := user_model.GetUserByID(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	other, err := user_model.GetUserByID(ctx, 2)
	if err != nil {
		t.Fatal(err)
	}
	link := &user_model.ExternalLoginUser{ExternalID: "subject", UserID: u.ID, LoginSourceID: 987654, Provider: "fixture"}
	if _, err = db.GetEngine(ctx).Insert(link); err != nil {
		t.Fatal(err)
	}
	if err = auth_model.InsertAuthToken(ctx, &auth_model.AuthToken{ID: "remember-fixture", UserID: u.ID}); err != nil {
		t.Fatal(err)
	}
	claims := &logoutClaims{RegisteredClaims: jwt.RegisteredClaims{Subject: link.ExternalID, ID: "event-fixture", ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute))}}
	if err = logoutSubject(ctx, "https://provider.example", link.LoginSourceID, claims); err != nil {
		t.Fatal(err)
	}
	if _, err = auth_model.GetAuthTokenByID(ctx, "remember-fixture"); err == nil {
		t.Fatal("remember-me token remained active")
	}
	generation, err := system.SessionGeneration(ctx, u.ID)
	if err != nil || generation == "" {
		t.Fatalf("session generation missing: %v", err)
	}
	got, err := user_model.GetUserByID(ctx, u.ID)
	if err != nil || got.ProhibitLogin != u.ProhibitLogin {
		t.Fatalf("account status changed: %v", err)
	}
	otherGeneration, err := system.SessionGeneration(ctx, other.ID)
	if err != nil || otherGeneration != "" {
		t.Fatalf("other user affected: %v", err)
	}
	if err = system.SetSessionGeneration(ctx, u.ID, "subsequent-session"); err != nil {
		t.Fatal(err)
	}
	if err = logoutSubject(ctx, "https://provider.example", link.LoginSourceID, claims); err != nil {
		t.Fatal(err)
	}
	generation, err = system.SessionGeneration(ctx, u.ID)
	if err != nil || generation != "subsequent-session" {
		t.Fatalf("replay revoked later session: %v", err)
	}
	other.ProhibitLogin = true
	if err = user_model.UpdateUserCols(ctx, other, "prohibit_login"); err != nil {
		t.Fatal(err)
	}
	second := &user_model.ExternalLoginUser{ExternalID: "banned-subject", UserID: other.ID, LoginSourceID: link.LoginSourceID, Provider: "fixture"}
	if _, err = db.GetEngine(ctx).Insert(second); err != nil {
		t.Fatal(err)
	}
	secondClaims := &logoutClaims{RegisteredClaims: jwt.RegisteredClaims{Subject: second.ExternalID, ID: "separate-event", ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute))}}
	if err = logoutSubject(ctx, "https://provider.example", second.LoginSourceID, secondClaims); err != nil {
		t.Fatal(err)
	}
	banned, err := user_model.GetUserByID(ctx, other.ID)
	if err != nil || !banned.ProhibitLogin {
		t.Fatalf("existing ban was removed: %v", err)
	}

}

func TestBackchannelHTTPLogout(t *testing.T) {
	if err := unittest.PrepareTestDatabase(); err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	var issuer string
	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/discovery":
			json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "jwks_uri": issuer + "/keys"})
		case "/keys":
			json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]string{"kid": "fixture", "kty": "RSA", "n": enc(key.N.Bytes()), "e": enc(big.NewInt(int64(key.E)).Bytes())}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer provider.Close()
	issuer = provider.URL
	oldHTTP := backchannelHTTP
	backchannelHTTP = provider.Client()
	defer func() { backchannelHTTP = oldHTTP }()
	source := &auth_model.Source{Name: "backchannel-fixture", Type: auth_model.OAuth2, IsActive: true, Cfg: &oauth2.Source{Provider: "openidConnect", ClientID: "test-client", OpenIDConnectAutoDiscoveryURL: issuer + "/discovery"}}
	if _, err = db.GetEngine(db.DefaultContext).Insert(source); err != nil {
		t.Fatal(err)
	}
	oldConfig := setting.CfgProvider
	defer func() { setting.CfgProvider = oldConfig }()
	setting.CfgProvider, err = setting.NewConfigProviderFromData(fmt.Sprintf("[oidc_backchannel]\nAUTH_SOURCE_ID=%d\n", source.ID))
	if err != nil {
		t.Fatal(err)
	}
	user, err := user_model.GetUserByID(db.DefaultContext, 1)
	if err != nil {
		t.Fatal(err)
	}
	user.ProhibitLogin = false
	if err = user_model.UpdateUserCols(db.DefaultContext, user, "prohibit_login"); err != nil {
		t.Fatal(err)
	}
	if _, err = db.GetEngine(db.DefaultContext).Insert(&user_model.ExternalLoginUser{ExternalID: "subject-fixture", UserID: user.ID, LoginSourceID: source.ID, Provider: "openidConnect"}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"iss": issuer, "sub": "subject-fixture", "aud": "test-client", "iat": now, "exp": now + 300, "jti": "http-fixture", "events": map[string]any{logoutEvent: map[string]any{}}})
	token.Header["kid"] = "fixture"
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	body := url.Values{"logout_token": {signed}}.Encode()
	req := httptest.NewRequest("POST", "/-/oidc-backchannel-logout", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := httptest.NewRecorder()
	base, done := gitea_context.NewBaseContext(resp, req)
	defer done()
	BackchannelLogout(&gitea_context.Context{Base: base})
	if resp.Code != http.StatusOK {
		t.Fatalf("response %d: %s", resp.Code, resp.Body.String())
	}
	result, err := user_model.GetUserByID(db.DefaultContext, user.ID)
	if err != nil || result.ProhibitLogin {
		t.Fatalf("account status changed: %v", err)
	}
}
