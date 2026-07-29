// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

type preLoginRequest struct {
	Email string `json:"email"`
}

type preLoginResponse struct {
	KDF            int
	KDFIterations  int
	KDFMemory      int
	KDFParallelism int
}

type tokLoginResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	Key          string `json:"key"`
}

const (
	// deviceName should probably be like "Linux", "Android", etc, but this
	// helps the human user differentiate bitw logins from those made by the
	// official clients.
	deviceName       = "bitw"
	loginScope       = "api offline_access"
	loginApiKeyScope = "api"
)

// deviceTypeNum returns the numeric device type as an int, matching the
// upstream device-type.enum.ts values. Single source of truth for both the
// Device-Type header (api.go) and the deviceType body form field.
func deviceTypeNum() int {
	// The enum values come from https://github.com/bitwarden/clients/blob/main/libs/common/src/platform/enums/device-type.enum.ts.
	switch runtime.GOOS {
	case "linux":
		return 25 // LinuxCLI — matches the `bw` CLI client_type
	case "darwin":
		return 7 // MacOS Desktop
	case "windows":
		return 6 // Windows Desktop
	default:
		return 14 // Unknown Browser, since we don't have a better fallback
	}
}

func deviceType() string {
	return strconv.Itoa(deviceTypeNum())
}

func login(ctx context.Context, retryWithApiKey bool) error {
	// Try client_credentials first when API key env vars are present,
	// or when retrying after a captcha. Fall back to password grant
	// otherwise, or if client_credentials fails.
	useApiKey := retryWithApiKey || os.Getenv("BW_CLIENTID") != ""

	// Email + /accounts/prelogin are only required for the password grant.
	// client_credentials is a machine-to-machine OAuth flow that needs
	// neither (ADR-0003 §Context). Skipping these here lets client_credentials
	// users log in without configuring $EMAIL or a synced profile email.
	var email string
	var preLogin preLoginResponse
	if !useApiKey {
		email = secrets.email()
		if email == "" {
			return fmt.Errorf("need a configured email or $EMAIL to log in")
		}
		if err := jsonPOST(ctx, idtURL+"/accounts/prelogin", &preLogin, preLoginRequest{
			Email: email,
		}); err != nil {
			return fmt.Errorf("could not pre-login: %v", err)
		}
		globalData.KDF = KDFType(preLogin.KDF)
		globalData.KDFIterations = preLogin.KDFIterations
		globalData.KDFMemory = preLogin.KDFMemory
		globalData.KDFParallelism = preLogin.KDFParallelism
		saveData = true
	}

	var values url.Values
	var grantErr error
	if useApiKey {
		values, grantErr = buildApiKeyGrant()
	} else {
		values, grantErr = buildPasswordGrant(email, preLogin)
	}
	if grantErr != nil {
		return grantErr
	}

	now := time.Now().UTC()
	var tokLogin tokLoginResponse
	err := jsonPOST(ctx, idtURL+"/connect/token", &tokLogin, values)
	errsc, ok := err.(*errStatusCode)
	if ok && bytes.Contains(errsc.body, []byte("TwoFactor")) {
		var twoFactor twoFactorResponse
		if err := json.Unmarshal(errsc.body, &twoFactor); err != nil {
			return err
		}
		provider, token, err := twoFactorPrompt(&twoFactor)
		if err != nil {
			return fmt.Errorf("could not obtain two-factor auth token: %v", err)
		}
		values.Set("twoFactorProvider", strconv.Itoa(int(provider)))
		values.Set("twoFactorToken", string(token))
		values.Set("twoFactorRemember", "1") // TODO: probably make this configurable
		tokLogin = tokLoginResponse{}
		if err := jsonPOST(ctx, idtURL+"/connect/token", &tokLogin, values); err != nil {
			return fmt.Errorf("could not login via two-factor: %v", err)
		}
	} else if err != nil && strings.Contains(err.Error(), "Captcha required.") {
		fmt.Fprintln(os.Stderr, "The server presented us with a captcha.")
		fmt.Fprintln(os.Stderr, "The best way to prevent future captcha is by login at least one time via api-key.")
		fmt.Fprintln(os.Stderr, "You can read on how to obtain the keys at: https://bitwarden.com/help/personal-api-key/")
		return login(ctx, true)
	} else if err != nil {
		// If client_credentials was attempted due to env vars (not an
		// explicit captcha retry), fall back to password grant.
		if useApiKey && !retryWithApiKey {
			// Lazily fetch email + preLogin only if we skipped them at
			// the top (because useApiKey was true). Preserves the
			// original fallback semantics for users who have an email
			// configured but whose API key was rejected for a
			// non-captcha reason (e.g. revoked key).
			if email == "" {
				email = secrets.email()
				if email == "" {
					return fmt.Errorf("need a configured email or $EMAIL to log in (password fallback)")
				}
				if err := jsonPOST(ctx, idtURL+"/accounts/prelogin", &preLogin, preLoginRequest{
					Email: email,
				}); err != nil {
					return fmt.Errorf("could not pre-login (password fallback): %v", err)
				}
				globalData.KDF = KDFType(preLogin.KDF)
				globalData.KDFIterations = preLogin.KDFIterations
				globalData.KDFMemory = preLogin.KDFMemory
				globalData.KDFParallelism = preLogin.KDFParallelism
				saveData = true
			}
			values, grantErr = buildPasswordGrant(email, preLogin)
			if grantErr != nil {
				return grantErr
			}
			tokLogin = tokLoginResponse{}
			if err := jsonPOST(ctx, idtURL+"/connect/token", &tokLogin, values); err != nil {
				return fmt.Errorf("could not login via password: %v", err)
			}
		} else {
			return fmt.Errorf("could not login: %v", err)
		}
	}
	globalData.AccessToken = tokLogin.AccessToken
	globalData.RefreshToken = tokLogin.RefreshToken
	globalData.TokenExpiry = now.Add(time.Duration(tokLogin.ExpiresIn) * time.Second)
	saveData = true
	return nil
}

func buildApiKeyGrant() (url.Values, error) {
	// Env-first per ADR-0003 §Context (crypto.go:111,127); libsecret is the
	// dual-storage mirror (secrets-refresh:97-101) and only consulted when
	// the env vars are absent. Without this priority, users with creds
	// only in env get a silent fallthrough to password grant.
	clientId := os.Getenv("BW_CLIENTID")
	clientSecret := os.Getenv("BW_CLIENTSECRET")
	if clientId == "" || clientSecret == "" {
		var err error
		clientIdBytes, err := secrets.clientId()
		if err != nil {
			return nil, err
		}
		clientSecretBytes, err := secrets.clientSecret()
		if err != nil {
			return nil, err
		}
		clientId = string(clientIdBytes[:])
		clientSecret = string(clientSecretBytes[:])
	}
	return urlValues(
		"client_id", clientId,
		"client_secret", clientSecret,
		"scope", loginApiKeyScope,
		"grant_type", "client_credentials",
		"deviceType", deviceType(),
		"deviceName", deviceName,
		"deviceIdentifier", globalData.DeviceID,
	), nil
}

func buildPasswordGrant(email string, preLogin preLoginResponse) (url.Values, error) {
	password, err := secrets.password()
	if err != nil {
		return nil, err
	}
	masterKey, err := deriveMasterKey(password, email, KDFType(preLogin.KDF), preLogin.KDFIterations, preLogin.KDFMemory, preLogin.KDFParallelism)
	if err != nil {
		return nil, err
	}
	hashedPassword := b64enc.EncodeToString(pbkdf2.Key(masterKey, password,
		1, 32, sha256.New))
	return urlValues(
		"grant_type", "password",
		"username", email,
		"password", string(hashedPassword),
		"scope", loginScope,
		"client_id", "connector", // seen in bitwarden/jslib
		"deviceType", deviceType(),
		"deviceName", deviceName,
		"deviceIdentifier", globalData.DeviceID,
	), nil
}

type TwoFactorProvider int

// Enum values copied from https://github.com/bitwarden/server/blob/f311f40d9333442a727eb8b77f3859597de199da/src/Core/Enums/TwoFactorProviderType.cs.
// Do not use iota, to clarify that these integer values are defined elsewhere.
const (
	Authenticator         TwoFactorProvider = 0
	Email                 TwoFactorProvider = 1
	Duo                   TwoFactorProvider = 2
	YubiKey               TwoFactorProvider = 3
	U2f                   TwoFactorProvider = 4
	Remember              TwoFactorProvider = 5
	OrganizationDuo       TwoFactorProvider = 6
	WebAuthn              TwoFactorProvider = 7
	_TwoFactorProviderMax                   = 8
)

func (t *TwoFactorProvider) UnmarshalText(text []byte) error {
	i, err := strconv.Atoi(string(text))
	if err != nil || i < 0 || i >= _TwoFactorProviderMax {
		return fmt.Errorf("invalid two-factor auth provider: %q", text)
	}
	*t = TwoFactorProvider(i)
	return nil
}

func (t TwoFactorProvider) Line(extra map[string]interface{}) string {
	switch t {
	case Authenticator:
		return "Six-digit authenticator token"
	case Email:
		emailHint := extra["Email"].(string)
		return fmt.Sprintf("Six-digit email token (%s)", emailHint)
	}
	return fmt.Sprintf("unsupported two factor auth provider %d", t)
}

type twoFactorResponse struct {
	TwoFactorProviders2 map[TwoFactorProvider]map[string]interface{}
}

func twoFactorPrompt(resp *twoFactorResponse) (TwoFactorProvider, []byte, error) {
	var selected TwoFactorProvider
	switch len(resp.TwoFactorProviders2) {
	case 0:
		return -1, nil, fmt.Errorf("API requested 2fa but has no available providers")
	case 1:
		// Use the single available provider.
		for provider := range resp.TwoFactorProviders2 {
			selected = provider
			break
		}
	default:
		// List all available providers, and make the user choose.
		// Don't range over the map directly, as the order wouldn't be stable.
		var available []TwoFactorProvider
		for pv := TwoFactorProvider(0); pv < _TwoFactorProviderMax; pv++ {
			extra, ok := resp.TwoFactorProviders2[pv]
			if !ok {
				continue
			}
			available = append(available, pv)
			fmt.Fprintf(os.Stderr, "%d) %s\n", len(available), pv.Line(extra))
		}
		input, err := readLine(fmt.Sprintf("Select a two-factor auth provider [1-%d]", len(available)))
		if err != nil {
			return -1, nil, err
		}
		i, err := strconv.Atoi(string(input))
		if err != nil {
			return -1, nil, err
		}
		if i <= 0 || i > len(available) {
			return -1, nil, fmt.Errorf("selected option %d is not within the range [1-%d]", i, len(available))
		}
		selected = available[i-1]
	}
	token, err := passwordPrompt(selected.Line(resp.TwoFactorProviders2[selected]))
	if err != nil {
		return -1, nil, err
	}
	return selected, token, nil
}

func refreshToken(ctx context.Context) error {
	if globalData.RefreshToken == "" {
		return fmt.Errorf("no refresh token available; re-login required")
	}

	clientId, err := secrets.clientId()
	if err != nil {
		return fmt.Errorf("could not obtain client id for refresh: %v", err)
	}

	clientSecret, err := secrets.clientSecret()
	if err != nil {
		return fmt.Errorf("could not obtain client secret for refresh: %v", err)
	}

	values := urlValues(
		"grant_type", "refresh_token",
		"client_id", string(clientId[:]),
		"client_secret", string(clientSecret[:]),
		"refresh_token", globalData.RefreshToken,
		"scope", loginApiKeyScope,
	)

	var tokLogin tokLoginResponse
	if err := jsonPOST(ctx, idtURL+"/connect/token", &tokLogin, values); err != nil {
		return fmt.Errorf("could not refresh token: %v", err)
	}

	globalData.AccessToken = tokLogin.AccessToken
	globalData.RefreshToken = tokLogin.RefreshToken
	globalData.TokenExpiry = time.Now().UTC().Add(time.Duration(tokLogin.ExpiresIn) * time.Second)
	saveData = true
	return nil
}

func urlValues(pairs ...string) url.Values {
	if len(pairs)%2 != 0 {
		panic("pairs must be of even length")
	}
	vals := make(url.Values)
	for i := 0; i < len(pairs); i += 2 {
		vals.Set(pairs[i], pairs[i+1])
	}
	return vals
}

var b64enc = base64.StdEncoding.Strict()
