package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/i18n"
	"github.com/QuantumNous/new-api/logger"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/setting/system_setting"
	"github.com/gin-gonic/gin"
)

func init() {
	Register("oidc", &OIDCProvider{})
}

// OIDCProvider implements OAuth for OIDC
type OIDCProvider struct{}

type oidcOAuthResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
}

type oidcUser struct {
	OpenID            string `json:"sub"`
	Email             string `json:"email"`
	Name              string `json:"name"`
	PreferredUsername string `json:"preferred_username"`
	Picture           string `json:"picture"`
}

func (p *OIDCProvider) GetName() string {
	return system_setting.GetOIDCSettings().GetEffectiveDisplayName()
}

func (p *OIDCProvider) IsEnabled() bool {
	return system_setting.GetOIDCSettings().Enabled
}

func (p *OIDCProvider) ExchangeToken(ctx context.Context, code string, c *gin.Context) (*OAuthToken, error) {
	if code == "" {
		return nil, NewOAuthError(i18n.MsgOAuthInvalidCode, nil)
	}

	settings := system_setting.GetOIDCSettings()
	redirectUri := fmt.Sprintf("%s/oauth/oidc", system_setting.ServerAddress)
	values := url.Values{}
	values.Set("client_id", settings.ClientId)
	values.Set("client_secret", settings.ClientSecret)
	values.Set("code", code)
	values.Set("grant_type", "authorization_code")
	values.Set("redirect_uri", redirectUri)

	logger.LogDebug(ctx, "[OAuth-OIDC] ExchangeToken: token_endpoint=%s, redirect_uri=%s", settings.TokenEndpoint, redirectUri)

	req, err := http.NewRequestWithContext(ctx, "POST", settings.TokenEndpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	client := http.Client{
		Timeout: 5 * time.Second,
	}
	res, err := client.Do(req)
	if err != nil {
		logger.LogError(ctx, fmt.Sprintf("[OAuth-OIDC] ExchangeToken error: %s", err.Error()))
		return nil, NewOAuthErrorWithRaw(i18n.MsgOAuthConnectFailed, map[string]any{"Provider": "OIDC"}, err.Error())
	}
	defer res.Body.Close()

	logger.LogDebug(ctx, "[OAuth-OIDC] ExchangeToken response status: %d", res.StatusCode)

	// 必须是**先读原始 body 再解析**，不能直接把 Body 喂给 Decoder。
	//
	// 原因：OAuth 服务器在换 token 失败时返回的是
	//     {"error":"invalid_grant","error_description":"..."}
	// 而 oidcOAuthResponse 里没有这两个字段，解码「成功」但结构体全空 ——
	// 于是失败点落到下面那句 access_token == "" 上，用户只看到
	// 「OIDC 获取 Token 失败，请检查设置」，**真正的原因被彻底丢掉**。
	// 实测踩过：redirect_uri 与授权请求不一致（Dex 返回 invalid_grant），
	// 排查了半天才发现错误信息明明一直在响应里。
	// 同类实现见 generic.go 的 ExchangeToken。
	body, err := io.ReadAll(res.Body)
	if err != nil {
		logger.LogError(ctx, fmt.Sprintf("[OAuth-OIDC] ExchangeToken read body error: %s", err.Error()))
		return nil, err
	}

	var oidcResponse oidcOAuthResponse
	if err := common.Unmarshal(body, &oidcResponse); err != nil {
		logger.LogError(ctx, fmt.Sprintf("[OAuth-OIDC] ExchangeToken decode error: %s (status=%d)", err.Error(), res.StatusCode))
		reason := fmt.Sprintf("HTTP %d", res.StatusCode)
		return nil, NewOAuthErrorWithRaw(
			i18n.MsgOAuthTokenFailedWithReason,
			map[string]any{"Provider": "OIDC", "Reason": reason},
			reason,
		)
	}

	if oidcResponse.AccessToken == "" {
		reason := oidcTokenErrorReason(body, res.StatusCode)
		logger.LogError(ctx, fmt.Sprintf("[OAuth-OIDC] ExchangeToken failed: %s (status=%d)", reason, res.StatusCode))
		return nil, NewOAuthErrorWithRaw(
			i18n.MsgOAuthTokenFailedWithReason,
			map[string]any{"Provider": "OIDC", "Reason": reason},
			reason,
		)
	}

	logger.LogDebug(ctx, "[OAuth-OIDC] ExchangeToken success: scope=%s", oidcResponse.Scope)

	return &OAuthToken{
		AccessToken:  oidcResponse.AccessToken,
		TokenType:    oidcResponse.TokenType,
		RefreshToken: oidcResponse.RefreshToken,
		ExpiresIn:    oidcResponse.ExpiresIn,
		Scope:        oidcResponse.Scope,
		IDToken:      oidcResponse.IDToken,
	}, nil
}

// oidcTokenErrorReason turns a failed token-endpoint response into a short,
// human-readable reason for both the log and the user-facing message.
//
// RFC 6749 §5.2 defines the error response shape:
//
//	{"error":"invalid_grant","error_description":"...","error_uri":"..."}
//
// Providers differ in detail: some omit error_description, some return plain
// text or HTML (a proxy error page, for instance). Never surface the raw body —
// fall back to the HTTP status so we always say something true.
func oidcTokenErrorReason(body []byte, statusCode int) string {
	var payload struct {
		Error     string `json:"error"`
		ErrorDesc string `json:"error_description"`
		ErrorURI  string `json:"error_uri"`
	}
	if err := common.Unmarshal(body, &payload); err == nil {
		switch {
		case payload.ErrorDesc != "" && payload.Error != "":
			return fmt.Sprintf("%s (%s)", payload.ErrorDesc, payload.Error)
		case payload.ErrorDesc != "":
			return payload.ErrorDesc
		case payload.Error != "":
			return payload.Error
		}
	}
	return fmt.Sprintf("HTTP %d", statusCode)
}

func (p *OIDCProvider) GetUserInfo(ctx context.Context, token *OAuthToken) (*OAuthUser, error) {
	settings := system_setting.GetOIDCSettings()

	logger.LogDebug(ctx, "[OAuth-OIDC] GetUserInfo: userinfo_endpoint=%s", settings.UserInfoEndpoint)

	req, err := http.NewRequestWithContext(ctx, "GET", settings.UserInfoEndpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)

	client := http.Client{
		Timeout: 5 * time.Second,
	}
	res, err := client.Do(req)
	if err != nil {
		logger.LogError(ctx, fmt.Sprintf("[OAuth-OIDC] GetUserInfo error: %s", err.Error()))
		return nil, NewOAuthErrorWithRaw(i18n.MsgOAuthConnectFailed, map[string]any{"Provider": "OIDC"}, err.Error())
	}
	defer res.Body.Close()

	logger.LogDebug(ctx, "[OAuth-OIDC] GetUserInfo response status: %d", res.StatusCode)

	if res.StatusCode != http.StatusOK {
		logger.LogError(ctx, fmt.Sprintf("[OAuth-OIDC] GetUserInfo failed: status=%d", res.StatusCode))
		return nil, NewOAuthError(i18n.MsgOAuthGetUserErr, nil)
	}

	var oidcUser oidcUser
	err = json.NewDecoder(res.Body).Decode(&oidcUser)
	if err != nil {
		logger.LogError(ctx, fmt.Sprintf("[OAuth-OIDC] GetUserInfo decode error: %s", err.Error()))
		return nil, err
	}

	if oidcUser.OpenID == "" || oidcUser.Email == "" {
		logger.LogError(ctx, fmt.Sprintf("[OAuth-OIDC] GetUserInfo failed: empty fields (sub=%s, email=%s)", oidcUser.OpenID, oidcUser.Email))
		return nil, NewOAuthError(i18n.MsgOAuthUserInfoEmpty, map[string]any{"Provider": "OIDC"})
	}

	logger.LogDebug(ctx, "[OAuth-OIDC] GetUserInfo success: sub=%s, username=%s, name=%s, email=%s", oidcUser.OpenID, oidcUser.PreferredUsername, oidcUser.Name, oidcUser.Email)

	return &OAuthUser{
		ProviderUserID: oidcUser.OpenID,
		Username:       oidcUser.PreferredUsername,
		DisplayName:    oidcUser.Name,
		Email:          oidcUser.Email,
	}, nil
}

func (p *OIDCProvider) IsUserIDTaken(providerUserID string) bool {
	return model.IsOidcIdAlreadyTaken(providerUserID)
}

func (p *OIDCProvider) FillUserByProviderID(user *model.User, providerUserID string) error {
	user.OidcId = providerUserID
	return user.FillUserByOidcId()
}

func (p *OIDCProvider) SetProviderUserID(user *model.User, providerUserID string) {
	user.OidcId = providerUserID
}

func (p *OIDCProvider) GetProviderPrefix() string {
	return "oidc_"
}

// ProviderUserIDColumn returns the users-table column storing this provider's user ID.
func (p *OIDCProvider) ProviderUserIDColumn() string {
	return "oidc_id"
}
