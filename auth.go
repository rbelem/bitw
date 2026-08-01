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
	"golang.org/x/term"
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

// emailFromAccessToken extracts the email claim from a Bitwarden JWT access
// token. Returns "" if the token is not a JWT, is malformed, or lacks the
// claim. Used as the 4th fallback in secrets.email() (crypto.go) so that
// client_credentials users can decrypt without configuring $EMAIL, a config
// file entry, or relying on /sync populating the profile email.
//
// We do NOT verify the JWT signature — same approach as upstream
// bitwarden/clients (decode-jwt-token-to-json.utility.ts). The token came
// from our own /connect/token response (we trust it); the server already
// validated it. We only read the email claim, which is non-security-critical
// for our use (we'll re-validate it by deriving a key and checking MAC).
func emailFromAccessToken(token string) string {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Email string `json:"email"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	return claims.Email
}

// refreshKDF fetches /accounts/prelogin and writes the KDF block to
// globalData. Non-fatal when a KDF is already cached (a flaky identity
// endpoint must not break an otherwise-working sync); fatal when no KDF is
// cached, since decryption is impossible without it.
//
// Called from sync() so the KDF block stays in lockstep with the cipher
// blob fetched by /sync. Without this, client_credentials logins (which
// skip prelogin per Phase 3a) leave a stale KDF in data.json after any
// vault re-key, and initKeys derives the wrong symmetric key — producing
// "decrypt: MAC mismatch" (crypto.go:308) on every get.
func refreshKDF(ctx context.Context) error {
	email := secrets.email()
	if email == "" {
		// Org-only / pre-profile state: leave any existing KDF untouched.
		return nil
	}
	var preLogin preLoginResponse
	err := jsonPOST(ctx, idtURL+"/accounts/prelogin", &preLogin, preLoginRequest{Email: email})
	if err != nil {
		if globalData.KDFIterations != 0 {
			fmt.Fprintf(os.Stderr, "warning: could not refresh KDF params: %v\n", err)
			return nil
		}
		return fmt.Errorf("could not pre-login to fetch KDF params: %w", err)
	}
	globalData.KDF = KDFType(preLogin.KDF)
	globalData.KDFIterations = preLogin.KDFIterations
	globalData.KDFMemory = preLogin.KDFMemory
	globalData.KDFParallelism = preLogin.KDFParallelism
	return nil
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

// passwordPromptFunc and readLineFunc are overridable for tests.
var (
	passwordPromptFunc = promptWithAskpass
	readLineFunc       = readLine
)

const (
	defaultApiURL = "https://api.bitwarden.com"
	defaultIdtURL = "https://identity.bitwarden.com"
)

// login is the top-level dispatcher for `bitw login`.
// Skips everything if client credentials are available (env OR config).
// Otherwise, interactive flow: server selection, email, master password,
// 2FA (if enabled), libsecret storage.
func login(ctx context.Context) error {
	clientId, _ := secrets.clientId()
	clientSecret, _ := secrets.clientSecret()
	hasId := clientId != nil
	hasSecret := clientSecret != nil

	switch {
	case hasId && hasSecret:
		return loginApiKey(ctx)
	case hasId != hasSecret:
		return fmt.Errorf(
			"client id and client secret must both be set or both be empty; "+
				"got id=%t, secret=%t. "+
				"Set both (via BW_CLIENTID/BW_CLIENTSECRET env vars or "+
				"clientid/clientsecret in the bitw config) for API key login, "+
				"or unset both for interactive login",
			hasId, hasSecret)
	default:
		return loginInteractive(ctx)
	}
}

func loginApiKey(ctx context.Context) error {
	values, err := buildApiKeyGrant()
	if err != nil {
		return err
	}
	var tok tokLoginResponse
	if err := jsonPOST(ctx, idtURL+"/connect/token", &tok, values); err != nil {
		return fmt.Errorf("client_credentials login failed: %w", err)
	}
	storeToken(tok)
	return nil
}

// passwordPromptInteractive prompts for a password, checking libsecret first.
// Used by the interactive login flow where clear feedback about the password
// source is important — the user needs to know whether they're being prompted
// or whether the password is being read silently from the keyring (e.g.,
// stored by a prior `bitw login`). The former `bin/secrets-setup` bash
// script that did the same store was removed in Phase 5.
//
// If libsecret has a stored password, returns it with a stderr note. If not,
// falls through to passwordPromptFunc (the overridable var, defaulting to
// promptWithAskpass — the GUI / SSH_ASKPASS / terminal priority chain).
func passwordPromptInteractive(prompt string) ([]byte, error) {
	if pw, err := readLibsecretPassword(); err == nil && len(pw) > 0 {
		fmt.Fprintln(os.Stderr, "(using stored master password from libsecret)")
		return pw, nil
	}
	return passwordPromptFunc(prompt)
}

func loginInteractive(ctx context.Context) error {
	// TTY gate
	if !term.IsTerminal(int(os.Stdin.Fd())) && os.Getenv("FORCE_STDIN_PROMPTS") != "true" {
		return fmt.Errorf("interactive login requires a terminal (stdin is not a TTY); " +
			"set BW_CLIENTID + BW_CLIENTSECRET for non-interactive login, " +
			"or set FORCE_STDIN_PROMPTS=true")
	}
	// 1. Server selection
	fmt.Fprintln(os.Stderr, "[1/4] Server selection (cloud or self-hosted)")
	if err := selectServer(); err != nil {
		return err
	}
	// 2. Email
	fmt.Fprintln(os.Stderr, "[2/4] Bitwarden account email")
	email := secrets.email()
	if email == "" {
		line, err := readLineFunc("Bitwarden account email: ")
		if err != nil {
			return err
		}
		email = strings.TrimSpace(string(line))
		if email == "" {
			return fmt.Errorf("no email provided")
		}
	}
	// 3. Prelogin → KDF params
	var preLogin preLoginResponse
	if err := jsonPOST(ctx, idtURL+"/accounts/prelogin", &preLogin,
		preLoginRequest{Email: email}); err != nil {
		return fmt.Errorf("could not pre-login: %w", err)
	}
	globalData.KDF = KDFType(preLogin.KDF)
	globalData.KDFIterations = preLogin.KDFIterations
	globalData.KDFMemory = preLogin.KDFMemory
	globalData.KDFParallelism = preLogin.KDFParallelism
	saveData = true
	// 4. Master password (libsecret first if present, otherwise prompted)
	fmt.Fprintln(os.Stderr, "[3/4] Master password")
	password, err := passwordPromptInteractive("Master password: ")
	if err != nil {
		return err
	}
	password = bytes.TrimSpace(password)
	// 5. Password grant (compute hashed password, send to /connect/token)
	values, err := buildPasswordGrant(email, preLogin, password)
	if err != nil {
		return err
	}
	var tok tokLoginResponse
	err = jsonPOST(ctx, idtURL+"/connect/token", &tok, values)
	// 6. 2FA handling (reuse existing twoFactorPrompt)
	if errsc, ok := err.(*errStatusCode); ok && bytes.Contains(errsc.body, []byte("TwoFactor")) {
		var tf twoFactorResponse
		if err := json.Unmarshal(errsc.body, &tf); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "[4/4] Two-factor authentication (TOTP / email / etc.)")
		provider, token, err := twoFactorPrompt(&tf)
		if err != nil {
			return fmt.Errorf("could not obtain two-factor auth token: %w", err)
		}
		values.Set("twoFactorProvider", strconv.Itoa(int(provider)))
		values.Set("twoFactorToken", string(token))
		values.Set("twoFactorRemember", "1")
		tok = tokLoginResponse{}
		if err := jsonPOST(ctx, idtURL+"/connect/token", &tok, values); err != nil {
			return fmt.Errorf("could not login via two-factor: %w", err)
		}
	} else if err != nil && strings.Contains(err.Error(), "Captcha required.") {
		return fmt.Errorf("server requires captcha; " +
			"use API key login instead: set BW_CLIENTID and BW_CLIENTSECRET " +
			"(see https://bitwarden.com/help/personal-api-key/)")
	} else if err != nil {
		return fmt.Errorf("could not login: %w", err)
	}
	storeToken(tok)
	// 7. Best-effort libsecret storage
	storePasswordLibsecret(password)
	return nil
}

func selectServer() error {
	if apiURL != defaultApiURL || idtURL != defaultIdtURL {
		return nil // config file or env already set them
	}
	line, err := readLineFunc("Server [cloud/self] (default: cloud)")
	if err != nil {
		return err
	}
	choice := strings.TrimSpace(strings.ToLower(string(line)))
	switch choice {
	case "", "cloud", "c":
		// defaults already set
	case "self", "self-hosted", "s":
		baseLine, err := readLineFunc("Base URL (e.g. https://bw.example.com)")
		if err != nil {
			return err
		}
		base := strings.TrimRight(strings.TrimSpace(string(baseLine)), "/")
		if base == "" {
			return fmt.Errorf("no base URL provided")
		}
		apiURL = base + "/api"
		idtURL = base + "/identity"
	default:
		return fmt.Errorf("unknown server choice %q (use cloud or self)", choice)
	}
	return nil
}

func storeToken(tok tokLoginResponse) {
	globalData.AccessToken = tok.AccessToken
	globalData.RefreshToken = tok.RefreshToken
	globalData.TokenExpiry = time.Now().UTC().Add(
		time.Duration(tok.ExpiresIn) * time.Second)
	saveData = true
}

func storePasswordLibsecret(password []byte) {
	if _, err := shell.LookPath("secret-tool"); err != nil {
		fmt.Fprintf(os.Stderr,
			"warning: secret-tool not found; master password not stored in keyring. "+
				"bitw get will prompt for it.\n")
		return
	}
	if out, err := shell.CombinedOutput(append(password, '\n'), "secret-tool", "store",
		"--label=Bitwarden", "bitwarden", "master-password"); err != nil {
		fmt.Fprintf(os.Stderr,
			"warning: could not store master password in keyring: %v %s\n",
			err, bytes.TrimSpace(out))
	}
}

func buildApiKeyGrant() (url.Values, error) {
	// Resolution order: env vars first, then bitw config file.
	// Never prompts interactively. If neither source provides both values,
	// the caller should fall back to password-grant login.
	clientId, err := secrets.clientId()
	if err != nil {
		return nil, err
	}
	clientSecret, err := secrets.clientSecret()
	if err != nil {
		return nil, err
	}
	if clientId == nil || clientSecret == nil {
		return nil, fmt.Errorf("client_credentials requires BW_CLIENTID/BW_CLIENTSECRET env vars or clientid/clientsecret in the bitw config")
	}
	return urlValues(
		"client_id", string(clientId),
		"client_secret", string(clientSecret),
		"scope", loginApiKeyScope,
		"grant_type", "client_credentials",
		"deviceType", deviceType(),
		"deviceName", deviceName,
		"deviceIdentifier", globalData.DeviceID,
	), nil
}

func buildPasswordGrant(email string, preLogin preLoginResponse, password []byte) (url.Values, error) {
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
		input, err := readLineFunc(fmt.Sprintf("Select a two-factor auth provider [1-%d]", len(available)))
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
	// Make the prompt explicit: the user must know this is the 2FA code,
	// not the master password (which was already asked in step 3).
	tokenLabel := fmt.Sprintf("Two-factor code (%s)", selected.Line(resp.TwoFactorProviders2[selected]))
	token, err := passwordPromptFunc(tokenLabel)
	if err != nil {
		return -1, nil, err
	}
	return selected, token, nil
}

func refreshToken(ctx context.Context) error {
	if globalData.RefreshToken == "" {
		return fmt.Errorf("no refresh token available; re-login required")
	}

	// If client credentials are available (from env OR config), use the
	// refresh_token grant with client_credentials.
	clientId, _ := secrets.clientId()
	clientSecret, _ := secrets.clientSecret()
	if clientId != nil && clientSecret != nil {
		return refreshTokenWithClientCreds(ctx)
	}

	// No client credentials available → fall back to password-grant re-login.
	// This uses the cached email + master password (from libsecret or
	// PASSWORD env) and prompts for TOTP if the server requires 2FA.
	return reloginPasswordGrant(ctx)
}

// refreshTokenWithClientCreds performs a refresh_token grant using
// BW_CLIENTID/BW_CLIENTSECRET from env.
func refreshTokenWithClientCreds(ctx context.Context) error {
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

// reloginPasswordGrant performs a full password-grant login using cached
// email and master password (from libsecret or PASSWORD env). Used as a
// fallback when refresh_token grant is not possible (no BW_CLIENTID/
// BW_CLIENTSECRET in env). Prompts for TOTP if the server requires 2FA.
func reloginPasswordGrant(ctx context.Context) error {
	email := secrets.email()
	if email == "" {
		return fmt.Errorf("no email available for password-grant re-login; " +
			"set BW_CLIENTID + BW_CLIENTSECRET for non-interactive login")
	}

	// Get master password from libsecret or PASSWORD env (no interactive
	// prompt — if not available, error out).
	password, err := secrets.password()
	if err != nil {
		return fmt.Errorf("could not obtain master password for re-login: %v", err)
	}

	// Prelogin to get KDF params.
	var preLogin preLoginResponse
	if err := jsonPOST(ctx, idtURL+"/accounts/prelogin", &preLogin,
		preLoginRequest{Email: email}); err != nil {
		return fmt.Errorf("could not pre-login for re-login: %w", err)
	}

	// Build password grant.
	values, err := buildPasswordGrant(email, preLogin, password)
	if err != nil {
		return fmt.Errorf("could not build password grant: %w", err)
	}

	var tok tokLoginResponse
	err = jsonPOST(ctx, idtURL+"/connect/token", &tok, values)
	// Handle 2FA if needed.
	if errsc, ok := err.(*errStatusCode); ok && bytes.Contains(errsc.body, []byte("TwoFactor")) {
		var tf twoFactorResponse
		if err := json.Unmarshal(errsc.body, &tf); err != nil {
			return err
		}
		provider, token, err := twoFactorPrompt(&tf)
		if err != nil {
			return fmt.Errorf("could not obtain two-factor auth token: %w", err)
		}
		values.Set("twoFactorProvider", strconv.Itoa(int(provider)))
		values.Set("twoFactorToken", string(token))
		values.Set("twoFactorRemember", "1")
		tok = tokLoginResponse{}
		if err := jsonPOST(ctx, idtURL+"/connect/token", &tok, values); err != nil {
			return fmt.Errorf("could not login via two-factor: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("could not re-login: %w", err)
	}

	storeToken(tok)
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
