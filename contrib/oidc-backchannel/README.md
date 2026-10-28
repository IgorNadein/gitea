# OIDC Back-Channel Logout

This optional integration accepts subject-wide OpenID Connect Back-Channel Logout tokens from a configured OIDC authentication source.

```ini
[oidc_backchannel]
AUTH_SOURCE_ID = 2
```

Register `https://<gitea-host>/-/oidc-backchannel-logout` with the provider. Omit the setting to disable the endpoint. The source supplies discovery URL and client ID.

The handler validates RS256 signature, issuer, audience, expiry, issue time, event and subject. Nonce and session-scoped `sid` tokens are rejected because provider sessions are not tracked. The subject must match an existing external-login link. Successful logout ends the linked account's browser sessions and invalidates remember-me login tokens. It does not block the account, remove SSH keys, revoke API tokens or change local passwords. Existing administrative bans are not modified.

Login sessions use a per-user generation stored in the existing app-state table. Logout atomically changes that generation and records the event ID; replay of the same unexpired event does not invalidate newer sessions. An affected user may log in again if their configured authentication provider permits it.

OpenID logout controls sessions only; employee status, access to Git via SSH and API, and service authorization need a separate solution.

> **Deferred — SSH access on employee offboarding:** Personal SSH keys are not revoked by this integration. An isolated OpenSSH `RevokedKeys` test blocked a personal key while preserving its public key for signature verification, but this is not enabled in production. Before adopting it, test integration with actual Gitea deploy keys and offboarding events, protect service accounts, and ensure the revocation file is always readable and updated atomically: an unavailable file blocks other SSH keys too. API tokens and local password access also need separate handling.
