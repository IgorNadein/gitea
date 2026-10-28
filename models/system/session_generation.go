// Copyright 2026. SPDX-License-Identifier: MIT
package system

import (
	"context"
	"fmt"
)

// SessionGenerationKey identifies the current generation of browser sessions.
const SessionGenerationKey = "oidc_logout_generation"

// SessionGeneration returns an opaque value which changes when sessions are revoked.
func SessionGeneration(ctx context.Context, userID int64) (string, error) {
	return GetAppStateContent(ctx, fmt.Sprintf("oidc-session-generation:%d", userID))
}

// SetSessionGeneration invalidates sessions with a previous generation.
func SetSessionGeneration(ctx context.Context, userID int64, generation string) error {
	return SaveAppStateContent(ctx, fmt.Sprintf("oidc-session-generation:%d", userID), generation)
}
