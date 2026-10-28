// Copyright 2026. SPDX-License-Identifier: MIT
package auth

import (
	stdcontext "context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"mime"
	"net/http"
	"net/url"
	"sync"
	"time"

	auth_model "code.gitea.io/gitea/models/auth"
	"code.gitea.io/gitea/models/db"
	"code.gitea.io/gitea/models/system"
	user_model "code.gitea.io/gitea/models/user"
	"code.gitea.io/gitea/modules/setting"
	"code.gitea.io/gitea/services/auth/source/oauth2"
	"code.gitea.io/gitea/services/context"
	"github.com/golang-jwt/jwt/v5"
)

const logoutEvent = "http://schemas.openid.net/event/backchannel-logout"
const logoutStatePrefix = "oidc-logout:"

type logoutClaims struct {
	jwt.RegisteredClaims
	Events map[string]json.RawMessage `json:"events"`
	Nonce  json.RawMessage            `json:"nonce"`
	SID    json.RawMessage            `json:"sid"`
}
type oidcDiscovery struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}
type oidcJWKS struct {
	Keys []struct {
		Kid string `json:"kid"`
		Kty string `json:"kty"`
		Use string `json:"use"`
		Alg string `json:"alg"`
		N   string `json:"n"`
		E   string `json:"e"`
	} `json:"keys"`
}

var errUnknownOIDCKey = errors.New("unknown signing key")

var backchannelHTTP = &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

func readOIDCJSON(uri string, result any) error {
	u, err := url.Parse(uri)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
		return errors.New("invalid OIDC URL")
	}
	resp, err := backchannelHTTP.Get(uri)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.New("OIDC endpoint unavailable")
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(result)
}

type oidcKeyCacheEntry struct {
	discovery oidcDiscovery
	keys      oidcJWKS
	refreshed time.Time
}

var oidcKeyCache = struct {
	sync.Mutex
	entries map[string]oidcKeyCacheEntry
}{entries: make(map[string]oidcKeyCacheEntry)}

func loadBackchannelKeys(discoveryURL string, force bool) (oidcDiscovery, oidcJWKS, error) {
	oidcKeyCache.Lock()
	defer oidcKeyCache.Unlock()
	now := time.Now()
	entry, found := oidcKeyCache.entries[discoveryURL]
	if found && ((!force && now.Sub(entry.refreshed) < 5*time.Minute) || (force && now.Sub(entry.refreshed) < 30*time.Second)) {
		return entry.discovery, entry.keys, nil
	}
	var discovery oidcDiscovery
	if err := readOIDCJSON(discoveryURL, &discovery); err != nil || discovery.Issuer == "" {
		return oidcDiscovery{}, oidcJWKS{}, errors.New("discovery unavailable")
	}
	var keys oidcJWKS
	if err := readOIDCJSON(discovery.JWKSURI, &keys); err != nil {
		return oidcDiscovery{}, oidcJWKS{}, err
	}
	oidcKeyCache.entries[discoveryURL] = oidcKeyCacheEntry{discovery: discovery, keys: keys, refreshed: now}
	return discovery, keys, nil
}

func oidcPublicKey(jwks *oidcJWKS, kid string) (*rsa.PublicKey, error) {
	for _, k := range jwks.Keys {
		if k.Kid != kid || k.Kty != "RSA" || (k.Use != "" && k.Use != "sig") || (k.Alg != "" && k.Alg != "RS256") {
			continue
		}
		n, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil || len(n) < 256 || len(n) > 1024 {
			return nil, errors.New("invalid key")
		}
		e, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil || len(e) == 0 || len(e) > 4 {
			return nil, errors.New("invalid exponent")
		}
		exponent := 0
		for _, b := range e {
			exponent = exponent<<8 | int(b)
		}
		if exponent < 3 || exponent%2 == 0 {
			return nil, errors.New("invalid exponent")
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: exponent}, nil
	}
	return nil, errUnknownOIDCKey
}

func verifyLogout(raw, issuer, clientID string, keys *oidcJWKS) (*logoutClaims, error) {
	claims := new(logoutClaims)
	token, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		kid, ok := t.Header["kid"].(string)
		if !ok || kid == "" || len(kid) > 256 {
			return nil, errors.New("invalid kid")
		}
		return oidcPublicKey(keys, kid)
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(issuer), jwt.WithAudience(clientID), jwt.WithExpirationRequired(), jwt.WithIssuedAt(), jwt.WithLeeway(time.Minute))
	if errors.Is(err, errUnknownOIDCKey) {
		return nil, errUnknownOIDCKey
	}
	if err != nil || !token.Valid || claims.Subject == "" || len(claims.Subject) > 255 || claims.ID == "" || len(claims.ID) > 255 || claims.IssuedAt == nil || claims.ExpiresAt == nil || claims.Nonce != nil || claims.SID != nil || claims.IssuedAt.After(time.Now().Add(time.Minute)) || !claims.ExpiresAt.After(time.Now()) || claims.ExpiresAt.After(time.Now().Add(24*time.Hour)) || !claims.ExpiresAt.After(claims.IssuedAt.Time) {
		return nil, errors.New("invalid logout token")
	}
	var event map[string]json.RawMessage
	e, exists := claims.Events[logoutEvent]
	if !exists || json.Unmarshal(e, &event) != nil || event == nil {
		return nil, errors.New("invalid logout token")
	}
	return claims, nil
}

func logoutSubject(parent stdcontext.Context, issuer string, sourceID int64, claims *logoutClaims) error {
	sum := sha256.Sum256([]byte(issuer + "\x00" + claims.ID))
	key := logoutStatePrefix + hex.EncodeToString(sum[:])
	return db.WithTx(parent, func(txctx stdcontext.Context) error {
		engine := db.GetEngine(txctx)
		if _, err := engine.Exec("DELETE FROM app_state WHERE id LIKE ? AND content < ?", logoutStatePrefix+"%", fmt.Sprintf("%020d", time.Now().Unix())); err != nil {
			return err
		}
		state := &system.AppState{ID: key}
		exists, err := engine.Get(state)
		if err != nil || exists {
			return err
		}
		link := &user_model.ExternalLoginUser{ExternalID: claims.Subject, LoginSourceID: sourceID}
		exists, err = user_model.GetExternalLogin(txctx, link)
		if err != nil {
			return err
		}
		if exists {
			user, err := user_model.GetUserByID(txctx, link.UserID)
			if err != nil {
				return err
			}
			if err = system.SetSessionGeneration(txctx, user.ID, key); err != nil {
				return err
			}
			// Remember-me tokens can otherwise recreate a browser session.
			if err = auth_model.DeleteAuthTokensByUserID(txctx, user.ID); err != nil {
				return err
			}
		}
		_, err = engine.Insert(&system.AppState{ID: key, Content: fmt.Sprintf("%020d", claims.ExpiresAt.Unix())})
		return err
	})
}

// BackchannelLogout revokes browser sessions for the linked subject.
func BackchannelLogout(ctx *context.Context) {
	ctx.Resp.Header().Set("Cache-Control", "no-store")
	sourceID := setting.CfgProvider.Section("oidc_backchannel").Key("AUTH_SOURCE_ID").MustInt64(0)
	if sourceID <= 0 {
		ctx.Status(http.StatusNotFound)
		return
	}
	source, err := auth_model.GetSourceByID(ctx, sourceID)
	if err != nil || !source.IsActive || !source.IsOAuth2() {
		ctx.Status(http.StatusServiceUnavailable)
		return
	}
	provider, ok := source.Cfg.(*oauth2.Source)
	if !ok || provider.Provider != "openidConnect" || provider.ClientID == "" {
		ctx.Status(http.StatusServiceUnavailable)
		return
	}
	mediaType, _, err := mime.ParseMediaType(ctx.Req.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/x-www-form-urlencoded" {
		ctx.Status(http.StatusBadRequest)
		return
	}
	ctx.Req.Body = http.MaxBytesReader(ctx.Resp, ctx.Req.Body, 32768)
	if ctx.Req.ParseForm() != nil || len(ctx.Req.PostForm["logout_token"]) != 1 {
		ctx.Status(http.StatusBadRequest)
		return
	}
	raw := ctx.Req.PostForm.Get("logout_token")
	if len(raw) > 16384 {
		ctx.Status(http.StatusBadRequest)
		return
	}
	discovery, keys, err := loadBackchannelKeys(provider.OpenIDConnectAutoDiscoveryURL, false)
	if err != nil {
		ctx.Status(http.StatusServiceUnavailable)
		return
	}
	claims, err := verifyLogout(raw, discovery.Issuer, provider.ClientID, &keys)
	if errors.Is(err, errUnknownOIDCKey) {
		discovery, keys, err = loadBackchannelKeys(provider.OpenIDConnectAutoDiscoveryURL, true)
		if err == nil {
			claims, err = verifyLogout(raw, discovery.Issuer, provider.ClientID, &keys)
		}
		if err != nil {
			ctx.Status(http.StatusServiceUnavailable)
			return
		}
	} else if err != nil {
		ctx.Status(http.StatusBadRequest)
		return
	}
	err = logoutSubject(ctx, discovery.Issuer, sourceID, claims)
	if err != nil {
		ctx.Status(http.StatusServiceUnavailable)
		return
	}
	ctx.Status(http.StatusOK)
}
