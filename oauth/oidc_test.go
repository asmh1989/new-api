package oauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/QuantumNous/new-api/i18n"
	"github.com/QuantumNous/new-api/setting/system_setting"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOIDCProvider_GetName(t *testing.T) {
	settings := system_setting.GetOIDCSettings()
	originalDisplayName := settings.DisplayName
	defer func() { settings.DisplayName = originalDisplayName }()

	p := &OIDCProvider{}

	settings.DisplayName = ""
	assert.Equal(t, "OIDC", p.GetName())

	settings.DisplayName = "  Acme SSO  "
	assert.Equal(t, "Acme SSO", p.GetName())
}

// The token endpoint of a real OIDC provider answers a rejected exchange with
// RFC 6749 §5.2 error JSON, and that JSON is the only place the actual cause
// appears. Historically this code decoded the body straight into
// oidcOAuthResponse (which has no error fields), saw an empty access_token,
// and reported the generic "check your settings" message — throwing the
// provider's explanation away. These tests pin the reason through to the
// returned OAuthError.
func TestOIDCProvider_ExchangeTokenSurfacesProviderReason(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
		wantReason string
	}{
		{
			name:       "error_description wins over the bare error code",
			statusCode: http.StatusBadRequest,
			body:       `{"error":"invalid_grant","error_description":"Invalid or expired code parameter."}`,
			wantReason: "Invalid or expired code parameter. (invalid_grant)",
		},
		{
			name:       "error code alone is still reported",
			statusCode: http.StatusBadRequest,
			body:       `{"error":"invalid_client"}`,
			wantReason: "invalid_client",
		},
		{
			name:       "non-JSON body falls back to the HTTP status",
			statusCode: http.StatusBadGateway,
			body:       `<html>upstream proxy error</html>`,
			wantReason: "HTTP 502",
		},
		{
			name:       "empty JSON object falls back to the HTTP status",
			statusCode: http.StatusInternalServerError,
			body:       `{}`,
			wantReason: "HTTP 500",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.statusCode)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer srv.Close()

			settings := system_setting.GetOIDCSettings()
			originalEndpoint := settings.TokenEndpoint
			t.Cleanup(func() { settings.TokenEndpoint = originalEndpoint })
			settings.TokenEndpoint = srv.URL

			_, err := (&OIDCProvider{}).ExchangeToken(context.Background(), "some-code", nil)
			require.Error(t, err, "a rejected exchange must not look like success")

			oauthErr, ok := err.(*OAuthError)
			require.True(t, ok, "want *OAuthError so the handler can translate it, got %T", err)
			assert.Equal(t, i18n.MsgOAuthTokenFailedWithReason, oauthErr.MsgKey,
				"must use the reason-bearing key, not the generic one")
			assert.Equal(t, "OIDC", oauthErr.Params["Provider"])
			assert.Equal(t, tt.wantReason, oauthErr.Params["Reason"],
				"the provider's own explanation is the whole point of this fix")
			assert.Equal(t, tt.wantReason, oauthErr.RawError)
		})
	}
}

// A successful exchange must keep working, and must not be affected by the
// switch from streaming-decode to read-then-parse.
func TestOIDCProvider_ExchangeTokenSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))
		assert.NoError(t, r.ParseForm())
		assert.Equal(t, "authorization_code", r.PostForm.Get("grant_type"))
		assert.Equal(t, "some-code", r.PostForm.Get("code"))

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"access_token": "at-123",
			"token_type": "Bearer",
			"refresh_token": "rt-456",
			"expires_in": 3600,
			"scope": "openid profile email",
			"id_token": "id-789"
		}`))
	}))
	defer srv.Close()

	settings := system_setting.GetOIDCSettings()
	originalEndpoint := settings.TokenEndpoint
	t.Cleanup(func() { settings.TokenEndpoint = originalEndpoint })
	settings.TokenEndpoint = srv.URL

	token, err := (&OIDCProvider{}).ExchangeToken(context.Background(), "some-code", nil)
	require.NoError(t, err)
	require.NotNil(t, token)
	assert.Equal(t, "at-123", token.AccessToken)
	assert.Equal(t, "Bearer", token.TokenType)
	assert.Equal(t, "rt-456", token.RefreshToken)
	assert.Equal(t, 3600, token.ExpiresIn)
	assert.Equal(t, "id-789", token.IDToken)
}
