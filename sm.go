// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/crypto/hkdf"
)

// smAccessToken holds the parsed components of a Bitwarden Secrets Manager
// access token. Format: "<version>.<clientID>.<clientSecret>:<encKeyB64>"
// where version must be "0" and encKeyB64 decodes to exactly 16 bytes.
type smAccessToken struct {
	Version      string
	ClientID     string
	ClientSecret string
	EncKey       []byte // 16 bytes
}

// parseSMAccessToken parses a Bitwarden Secrets Manager access token.
// The token format is: "<version>.<clientID>.<clientSecret>:<encKeyB64>"
// Split on the LAST ':' to separate head from encKeyB64, then split head
// on '.' to get [version, clientID, clientSecret].
func parseSMAccessToken(token string) (*smAccessToken, error) {
	if token == "" {
		return nil, fmt.Errorf("malformed SM_ACCESS_TOKEN: empty token")
	}

	// Split on the LAST ':'
	lastColon := strings.LastIndex(token, ":")
	if lastColon < 0 {
		return nil, fmt.Errorf("malformed SM_ACCESS_TOKEN: missing colon separator")
	}

	head := token[:lastColon]
	encKeyB64 := token[lastColon+1:]

	// Split head on '.'
	parts := strings.SplitN(head, ".", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed SM_ACCESS_TOKEN: expected 3 dot-separated parts, got %d", len(parts))
	}

	version := parts[0]
	if version != "0" {
		return nil, fmt.Errorf("malformed SM_ACCESS_TOKEN: unsupported version %q (expected \"0\")", version)
	}

	clientID := parts[1]
	clientSecret := parts[2]

	// Decode encKeyB64
	encKey, err := base64.StdEncoding.DecodeString(encKeyB64)
	if err != nil {
		return nil, fmt.Errorf("malformed SM_ACCESS_TOKEN: invalid base64 in enc key: %w", err)
	}

	if len(encKey) != 16 {
		return nil, fmt.Errorf("malformed SM_ACCESS_TOKEN: enc key must be exactly 16 bytes, got %d", len(encKey))
	}

	return &smAccessToken{
		Version:      version,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		EncKey:       encKey,
	}, nil
}

// deriveSMKey derives the 64-byte key from the 16-byte encKey using HKDF.
// HKDF-Extract(salt="bitwarden-accesstoken", ikm=encKey) → prk
// HKDF-Expand(prk, info="sm-access-token") → 64 bytes
// First 32 bytes = encKey, last 32 bytes = macKey
func deriveSMKey(encKey []byte) ([]byte, error) {
	r := hkdf.New(sha256.New, encKey, []byte("bitwarden-accesstoken"), []byte("sm-access-token"))
	derived := make([]byte, 64)
	if _, err := io.ReadFull(r, derived); err != nil {
		return nil, fmt.Errorf("HKDF derive failed: %w", err)
	}
	return derived, nil
}

// smTokenExchangeResponse is the response from /connect/token for SM.
// The SM machine-account exchange returns encrypted_payload exclusively;
// the vault login's "Key" field is a different response type never present
// here, so we do not accept it as a fallback.
type smTokenExchangeResponse struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        int    `json:"expires_in"`
	TokenType        string `json:"token_type"`
	EncryptedPayload string `json:"encrypted_payload"`
}

// smEncryptedPayload is the decrypted structure of the encrypted_payload field.
type smEncryptedPayload struct {
	EncryptionKey string `json:"encryptionKey"`
}

// exchangeSMAccessToken exchanges the SM access token for an API token
// and the encrypted org key.
func exchangeSMAccessToken(ctx context.Context, idtURL string, token *smAccessToken) (apiToken string, orgKeyEnc string, err error) {
	values := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {token.ClientID},
		"client_secret": {token.ClientSecret},
		"scope":         {"api.secrets"},
	}

	req, err := http.NewRequest("POST", idtURL+"/connect/token", strings.NewReader(values.Encode()))
	if err != nil {
		return "", "", fmt.Errorf("could not create token exchange request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var resp smTokenExchangeResponse
	if err := httpDoWithToken(ctx, req, "", &resp); err != nil {
		// Route 401/403 through smError so the most common SM failure
		// (bad token) says "SM authentication failed" rather than the
		// generic "token exchange failed".
		if errsc, ok := err.(*errStatusCode); ok && (errsc.code == 401 || errsc.code == 403) {
			return "", "", smError(err, "token exchange")
		}
		return "", "", fmt.Errorf("token exchange failed: %w", err)
	}

	orgKeyEnc = resp.EncryptedPayload
	if orgKeyEnc == "" {
		return "", "", fmt.Errorf("token exchange response missing encrypted_payload")
	}

	return resp.AccessToken, orgKeyEnc, nil
}

// smListResponse is the response from /organizations/{orgID}/secrets
type smListResponse struct {
	Object   string          `json:"object"`
	Secrets  []smListSecret  `json:"secrets"`
	Projects []smListProject `json:"projects"`
}

type smListSecret struct {
	ID             string          `json:"id"`
	OrganizationID string          `json:"organizationId"`
	Key            string          `json:"key"`
	CreationDate   string          `json:"creationDate"`
	RevisionDate   string          `json:"revisionDate"`
	Projects       []smListProject `json:"projects"`
	Read           bool            `json:"read"`
	Write          bool            `json:"write"`
}

type smListProject struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// smSecretResponse is the response from /secrets/{id}
type smSecretResponse struct {
	ID             string `json:"id"`
	OrganizationID string `json:"organizationId"`
	Key            string `json:"key"`
	Value          string `json:"value"`
	Note           string `json:"note"`
	CreationDate   string `json:"creationDate"`
	RevisionDate   string `json:"revisionDate"`
}

// smClient holds the state for a Secrets Manager session.
type smClient struct {
	apiToken string
	orgKey   []byte // 64 bytes (first 32 = enc, last 32 = mac)
	orgID    string
}

// newSMClient creates a new SM client by parsing the token, deriving keys,
// and exchanging for an API token.
func newSMClient(ctx context.Context, rawToken string) (*smClient, error) {
	// Defense in depth: trim whitespace even if the caller already did.
	rawToken = strings.TrimSpace(rawToken)
	if rawToken == "" {
		return nil, fmt.Errorf("SM_ACCESS_TOKEN environment variable is not set")
	}

	token, err := parseSMAccessToken(rawToken)
	if err != nil {
		return nil, err
	}

	// Derive 64-byte key
	derivedKey, err := deriveSMKey(token.EncKey)
	if err != nil {
		return nil, err
	}

	// Exchange token
	apiToken, orgKeyEnc, err := exchangeSMAccessToken(ctx, idtURL, token)
	if err != nil {
		return nil, err
	}

	// Decrypt org key
	var orgKeyCS CipherString
	if err := orgKeyCS.UnmarshalText([]byte(orgKeyEnc)); err != nil {
		return nil, fmt.Errorf("could not parse encrypted org key: %w", err)
	}

	orgKeyPlaintext, err := decryptWith(orgKeyCS, derivedKey[:32], derivedKey[32:])
	if err != nil {
		return nil, fmt.Errorf("could not decrypt org key: %w", err)
	}

	// The decrypted payload is JSON with an encryptionKey field
	var payload smEncryptedPayload
	if err := json.Unmarshal(orgKeyPlaintext, &payload); err != nil {
		return nil, fmt.Errorf("could not parse org key JSON: %w", err)
	}

	orgKey, err := base64.StdEncoding.DecodeString(payload.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("could not decode org key base64: %w", err)
	}

	if len(orgKey) != 64 {
		return nil, fmt.Errorf("org key must be 64 bytes, got %d", len(orgKey))
	}

	// Extract org ID from JWT
	orgID := claimFromAccessToken(apiToken, "organization")
	if orgID == "" {
		return nil, fmt.Errorf("API token missing organization claim")
	}

	return &smClient{
		apiToken: apiToken,
		orgKey:   orgKey,
		orgID:    orgID,
	}, nil
}

// decryptSMField decrypts a CipherString with the org key.
func (c *smClient) decryptSMField(encStr string) (string, error) {
	if encStr == "" {
		return "", nil
	}
	var cs CipherString
	if err := cs.UnmarshalText([]byte(encStr)); err != nil {
		return "", fmt.Errorf("could not parse cipher string: %w", err)
	}
	dec, err := decryptWith(cs, c.orgKey[:32], c.orgKey[32:])
	if err != nil {
		return "", err
	}
	return string(dec), nil
}

// decryptProjectName defensively decrypts a project name. If it looks like
// an EncString (has a "|"), decrypt it; otherwise use as-is. If decryption
// fails, the raw name is returned (the only caller discards the error).
func (c *smClient) decryptProjectName(name string) string {
	if strings.Contains(name, "|") {
		dec, err := c.decryptSMField(name)
		if err != nil {
			return name
		}
		return dec
	}
	return name
}

// smList lists all secrets in the organization.
func (c *smClient) smList(ctx context.Context) error {
	url := fmt.Sprintf("%s/organizations/%s/secrets", apiURL, c.orgID)

	var resp smListResponse
	if err := jsonGETWithToken(ctx, url, c.apiToken, &resp); err != nil {
		return smError(err, "list secrets")
	}

	// Decrypt and collect results
	type smEntry struct {
		key      string
		projects string
	}
	var entries []smEntry

	for _, s := range resp.Secrets {
		key, err := c.decryptSMField(s.Key)
		if err != nil {
			return fmt.Errorf("could not decrypt secret key: %w", err)
		}

		// Decrypt project names defensively
		var projNames []string
		for _, p := range s.Projects {
			projNames = append(projNames, c.decryptProjectName(p.Name))
		}

		projStr := "-"
		if len(projNames) > 0 {
			projStr = strings.Join(projNames, ",")
		}

		entries = append(entries, smEntry{key: key, projects: projStr})
	}

	// Sort by decrypted key (stable for deterministic rows with duplicate keys)
	sort.SliceStable(entries, func(i, j int) bool {
		return entries[i].key < entries[j].key
	})

	// Print TSV
	for _, e := range entries {
		fmt.Printf("%s\t%s\n", e.key, e.projects)
	}

	return nil
}

// smGet retrieves a secret by key or ID.
func (c *smClient) smGet(ctx context.Context, keyOrID string) error {
	var secretID string

	// Try to parse as UUID
	if _, err := uuid.Parse(keyOrID); err == nil {
		// Try direct UUID fetch first
		url := fmt.Sprintf("%s/secrets/%s", apiURL, keyOrID)
		var resp smSecretResponse
		if err := jsonGETWithToken(ctx, url, c.apiToken, &resp); err != nil {
			// On 404, fall through to key/fuzzy search — the key
			// might be a valid UUID format but not an actual secret ID.
			if errsc, ok := err.(*errStatusCode); ok && errsc.code == 404 {
				secretID = ""
			} else {
				return smError(err, "get secret")
			}
		} else {
			// Decrypt value
			value, err := c.decryptSMField(resp.Value)
			if err != nil {
				return fmt.Errorf("could not decrypt secret value: %w", err)
			}
			fmt.Println(value)
			return nil
		}
	}

	if secretID == "" {
		// List and find by exact key match
		var err error
		secretID, err = c.findSecretByKey(ctx, keyOrID)
		if err != nil {
			return err
		}
		if secretID == "" {
			// Try fuzzy match
			secretID = c.findSecretByFuzzy(ctx, keyOrID)
			if secretID == "" {
				return fmt.Errorf("secret %q not found", keyOrID)
			}
		}
	}

	// Fetch the secret
	url := fmt.Sprintf("%s/secrets/%s", apiURL, secretID)
	var resp smSecretResponse
	if err := jsonGETWithToken(ctx, url, c.apiToken, &resp); err != nil {
		return smError(err, "get secret")
	}

	// Decrypt value
	value, err := c.decryptSMField(resp.Value)
	if err != nil {
		return fmt.Errorf("could not decrypt secret value: %w", err)
	}

	fmt.Println(value)
	return nil
}

// findSecretByKey lists secrets and returns the ID of the one with exact key match.
// If multiple secrets share the same key, returns an error listing the duplicates.
func (c *smClient) findSecretByKey(ctx context.Context, key string) (string, error) {
	url := fmt.Sprintf("%s/organizations/%s/secrets", apiURL, c.orgID)

	var resp smListResponse
	if err := jsonGETWithToken(ctx, url, c.apiToken, &resp); err != nil {
		return "", nil
	}

	var matches []smListSecret
	for _, s := range resp.Secrets {
		decKey, err := c.decryptSMField(s.Key)
		if err != nil {
			continue
		}
		if decKey == key {
			matches = append(matches, s)
		}
	}

	if len(matches) == 0 {
		return "", nil
	}
	if len(matches) > 1 {
		// Collect IDs and project info for the error message
		ids := make([]string, len(matches))
		for i, m := range matches {
			ids[i] = m.ID
		}
		return "", fmt.Errorf("secret key %q is ambiguous: %d secrets match (ids: %s); use the secret id instead",
			key, len(matches), strings.Join(ids, ", "))
	}
	return matches[0].ID, nil
}

// findSecretByFuzzy lists secrets and returns the ID of the best fuzzy match.
func (c *smClient) findSecretByFuzzy(ctx context.Context, query string) string {
	url := fmt.Sprintf("%s/organizations/%s/secrets", apiURL, c.orgID)

	var resp smListResponse
	if err := jsonGETWithToken(ctx, url, c.apiToken, &resp); err != nil {
		return ""
	}

	// Build name list
	type secretEntry struct {
		id  string
		key string
	}
	var entries []secretEntry
	var names []string

	for _, s := range resp.Secrets {
		decKey, err := c.decryptSMField(s.Key)
		if err != nil {
			continue
		}
		entries = append(entries, secretEntry{id: s.ID, key: decKey})
		names = append(names, decKey)
	}

	// Use the same fuzzy logic as get.go
	ranked := fuzzyRank(query, names)
	if auto := autoSelectCandidate(ranked); auto != nil {
		// Find the entry with this name
		for _, e := range entries {
			if e.key == auto.name {
				return e.id
			}
		}
	}
	return ""
}

// smError converts HTTP errors to user-friendly messages.
func smError(err error, context string) error {
	if errsc, ok := err.(*errStatusCode); ok {
		switch errsc.code {
		case 401, 403:
			return fmt.Errorf("SM authentication failed (%d): %s", errsc.code, string(errsc.body))
		case 404:
			// For list endpoints, include context so a 404 on the
			// wrong/deleted org is not confused with a missing secret.
			if strings.Contains(context, "list") {
				return fmt.Errorf("%s: not found", context)
			}
			return fmt.Errorf("secret not found")
		}
	}
	return fmt.Errorf("%s: %w", context, err)
}

// cmdSM is the entry point for `bitw sm` commands.
func cmdSM(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: bitw sm <list|get> [args]")
	}

	// Trim whitespace to tolerate trailing newlines/spaces from env vars.
	rawToken := strings.TrimSpace(os.Getenv("SM_ACCESS_TOKEN"))
	if rawToken == "" {
		return fmt.Errorf("SM_ACCESS_TOKEN environment variable is not set")
	}

	client, err := newSMClient(ctx, rawToken)
	if err != nil {
		return err
	}

	switch args[0] {
	case "list":
		return client.smList(ctx)
	case "get":
		if len(args) < 2 {
			return fmt.Errorf("usage: bitw sm get <key-or-id>")
		}
		return client.smGet(ctx, args[1])
	default:
		return fmt.Errorf("unknown sm command: %q (use list or get)", args[0])
	}
}
