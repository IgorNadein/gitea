# OIDC account deactivation notifications

This optional integration accepts subject-wide OpenID Connect Back-Channel Logout tokens from one explicitly selected OIDC authentication source. The identity provider must send these notifications only when access to the account is to be disabled. OIDC Back-Channel Logout also covers ordinary logout; do not enable account blocking for a provider that sends ordinary logout events.

Configure the OIDC source and set:

```ini
[oidc_backchannel]
AUTH_SOURCE_ID = 2
```

Register `https://<gitea-host>/-/oidc-backchannel-logout` with the provider. Omit the setting to disable this endpoint. The source supplies the OIDC discovery URL and client ID; the integration does not depend on a particular provider.

The handler validates RS256 signatures against the discovered keys, issuer, audience, expiry, issue time, event and subject. It rejects nonce and session-specific `sid` tokens because provider sessions are not tracked. A matching external-login link is required; unknown subjects do not create accounts. The linked account receives Gitea's `prohibit_login` flag, which prevents web, API-token and SSH access. Token identifiers are recorded transactionally to make retries safe; expired records are pruned during later deliveries.

This is an account ban rather than a normal web-session logout. Rehiring does not automatically remove the ban: an administrator must confirm eligibility and enable the account. The provider handles status checks, reliable delivery and retries. Deploy keys, runner credentials, shared accounts and other independent credentials are outside the user's OIDC account.
