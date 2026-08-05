// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
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
	ID             string          `json:"id"`
	OrganizationID string          `json:"organizationId"`
	Key            string          `json:"key"`
	Value          string          `json:"value"`
	Note           string          `json:"note"`
	Projects       []smListProject `json:"projects"`
	CreationDate   string          `json:"creationDate"`
	RevisionDate   string          `json:"revisionDate"`
}

// smClient holds the state for a Secrets Manager session.
type smClient struct {
	apiToken string
	orgKey   []byte // 64 bytes (first 32 = enc, last 32 = mac)
	orgID    string

	// listCache holds the /organizations/{orgID}/secrets response so
	// resolveProjectID, findSecretByKey, and findSecretByFuzzy each
	// make at most one HTTP call per command.
	listCache *smListResponse
}

// listSecrets fetches (or returns cached) the list of secrets and projects
// for the organization. All SM sub-commands that need the full list should
// call this method instead of issuing their own GET.
func (c *smClient) listSecrets(ctx context.Context) (*smListResponse, error) {
	if c.listCache != nil {
		return c.listCache, nil
	}
	url := fmt.Sprintf("%s/organizations/%s/secrets", apiURL, c.orgID)
	var resp smListResponse
	if err := jsonGETWithToken(ctx, url, c.apiToken, &resp); err != nil {
		return nil, err
	}
	c.listCache = &resp
	return &resp, nil
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

// encryptSMField encrypts a plaintext string with the org key and returns
// a serialized CipherString suitable for the SM API wire format.
func (c *smClient) encryptSMField(plain string) (string, error) {
	// Always encrypt, even empty plaintext: the SM API requires all
	// fields (key, value, note) to be valid EncStrings and rejects ""
	// with "The Note field is required" / "not a valid encrypted string".
	cs, err := encryptWith([]byte(plain), AesCbc256_HmacSha256_B64, c.orgKey[:32], c.orgKey[32:])
	if err != nil {
		return "", fmt.Errorf("could not encrypt field: %w", err)
	}
	b, err := cs.MarshalText()
	if err != nil {
		return "", fmt.Errorf("could not serialize cipher string: %w", err)
	}
	return string(b), nil
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
	resp, err := c.listSecrets(ctx)
	if err != nil {
		return smListError(err, "list secrets")
	}

	// Decrypt and collect results
	type smEntry struct {
		key      string
		projects string
	}
	var entries []smEntry

	for _, s := range resp.Secrets {
		key, decryptErr := c.decryptSMField(s.Key)
		if decryptErr != nil {
			fmt.Fprintf(os.Stderr, "warning: skipping secret %s: could not decrypt key: %v\n", s.ID, decryptErr)
			continue
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
func (c *smClient) smGet(ctx context.Context, keyOrID, projectName string) error {
	secretID, err := c.resolveSecretID(ctx, keyOrID, projectName)
	if err != nil {
		return err
	}
	resp, err := c.fetchSecret(ctx, secretID)
	if err != nil {
		return err
	}
	value, err := c.decryptSMField(resp.Value)
	if err != nil {
		return fmt.Errorf("could not decrypt secret value: %w", err)
	}
	fmt.Println(value)
	return nil
}

// secretInProject reports whether a secret belongs to a project with the
// given name. Project names may be encrypted or plaintext; we decrypt
// defensively before comparing.
func (c *smClient) secretInProject(s smListSecret, projectName string) bool {
	for _, p := range s.Projects {
		if c.decryptProjectName(p.Name) == projectName {
			return true
		}
	}
	return false
}

// resolveProjectID resolves a project name to its UUID by listing projects
// from the organization and matching the name (decrypting defensively).
func (c *smClient) resolveProjectID(ctx context.Context, projectName string) (string, error) {
	resp, err := c.listSecrets(ctx)
	if err != nil {
		return "", smListError(err, "list projects")
	}

	var matched []smListProject
	for _, p := range resp.Projects {
		decName := c.decryptProjectName(p.Name)
		if decName == projectName {
			matched = append(matched, p)
		}
	}

	if len(matched) == 0 {
		return "", fmt.Errorf("project %q not found", projectName)
	}
	if len(matched) > 1 {
		return "", fmt.Errorf("project name %q is ambiguous: %d projects match; use the project id instead",
			projectName, len(matched))
	}
	return matched[0].ID, nil
}

// findSecretByKey lists secrets and returns the ID of the one with exact key match.
// If multiple secrets share the same key, returns an error listing the duplicates.
func (c *smClient) findSecretByKey(ctx context.Context, key, projectName string) (string, error) {
	resp, err := c.listSecrets(ctx)
	if err != nil {
		return "", err
	}

	var matches []smListSecret
	for _, s := range resp.Secrets {
		// Apply project filter if specified
		if projectName != "" && !c.secretInProject(s, projectName) {
			continue
		}
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
func (c *smClient) findSecretByFuzzy(ctx context.Context, query, projectName string) (string, error) {
	resp, err := c.listSecrets(ctx)
	if err != nil {
		return "", err
	}

	// Build name list
	type secretEntry struct {
		id  string
		key string
	}
	var entries []secretEntry
	var names []string

	for _, s := range resp.Secrets {
		// Apply project filter if specified
		if projectName != "" && !c.secretInProject(s, projectName) {
			continue
		}
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
				return e.id, nil
			}
		}
	}
	return "", nil
}

// resolveSecretID resolves a key-or-ID to a secret ID. If keyOrID looks like
// a UUID, it tries a direct GET first; if that 404s (or it isn't a UUID), it
// falls through to exact-key match, then fuzzy match. When projectName is
// non-empty, only secrets in that project are considered.
//
// Note: when a UUID is provided and the lookup succeeds, projectName is
// ignored (the exact ID is unambiguous). A warning is printed to stderr
// when both are given.
func (c *smClient) resolveSecretID(ctx context.Context, keyOrID, projectName string) (string, error) {
	// Try to parse as UUID
	if _, err := uuid.Parse(keyOrID); err == nil {
		// Check if it's a valid secret ID
		url := fmt.Sprintf("%s/secrets/%s", apiURL, keyOrID)
		var scratch smSecretResponse
		if fetchErr := jsonGETWithToken(ctx, url, c.apiToken, &scratch); fetchErr == nil {
			if projectName != "" {
				fmt.Fprintf(os.Stderr, "warning: --project %q is ignored when using a secret ID (UUID)\n", projectName)
			}
			return keyOrID, nil
		} else if errsc, ok := fetchErr.(*errStatusCode); !ok || errsc.code != 404 {
			return "", smError(fetchErr, "get secret")
		}
		// 404 — fall through to key/fuzzy search
	}

	// Try exact key match
	secretID, err := c.findSecretByKey(ctx, keyOrID, projectName)
	if err != nil {
		return "", err
	}
	if secretID == "" {
		// Try fuzzy match
		secretID, err = c.findSecretByFuzzy(ctx, keyOrID, projectName)
		if err != nil {
			return "", err
		}
		if secretID == "" {
			return "", fmt.Errorf("secret %q not found", keyOrID)
		}
	}
	return secretID, nil
}

// fetchSecret fetches a secret by its ID and returns the raw response.
// The caller must decrypt the Key, Value, and Note fields.
func (c *smClient) fetchSecret(ctx context.Context, secretID string) (*smSecretResponse, error) {
	url := fmt.Sprintf("%s/secrets/%s", apiURL, secretID)
	var resp smSecretResponse
	if err := jsonGETWithToken(ctx, url, c.apiToken, &resp); err != nil {
		return nil, smError(err, "get secret")
	}
	return &resp, nil
}

// smError converts HTTP errors to user-friendly messages.
// isListOp indicates whether the error comes from a list endpoint (affects 404 wording).
func smError(err error, context string) error {
	return smErrorKind(err, context, false)
}

// smListError is like smError but for list endpoints — a 404 means the org
// is wrong/deleted rather than a specific resource being missing.
func smListError(err error, context string) error {
	return smErrorKind(err, context, true)
}

func smErrorKind(err error, context string, isList bool) error {
	if errsc, ok := err.(*errStatusCode); ok {
		switch errsc.code {
		case 401, 403:
			return fmt.Errorf("SM authentication failed (%d): %s", errsc.code, string(errsc.body))
		case 404:
			if isList {
				return fmt.Errorf("%s: not found", context)
			}
			if len(errsc.body) > 0 {
				return fmt.Errorf("secret not found: %s", string(errsc.body))
			}
			return fmt.Errorf("secret not found")
		}
	}
	return fmt.Errorf("%s: %w", context, err)
}

// resolveSMAccessToken returns the SM access token from env or config.
// Env takes precedence over config. Returns empty string if neither is set.
func resolveSMAccessToken() string {
	rawToken := strings.TrimSpace(os.Getenv("SM_ACCESS_TOKEN"))
	if rawToken == "" {
		rawToken = strings.TrimSpace(secrets._configSMAccessToken)
	}
	return rawToken
}

// smCreateResponse is the response from POST /secrets
type smCreateResponse struct {
	ID             string `json:"id"`
	OrganizationID string `json:"organizationId"`
	Key            string `json:"key"`
	Value          string `json:"value"`
	Note           string `json:"note"`
	CreationDate   string `json:"creationDate"`
	RevisionDate   string `json:"revisionDate"`
}

// smCreate creates a new secret in the organization. If projectID is non-empty,
// the secret is associated with that project. All fields are encrypted with
// the org key before transmission (zero-knowledge wire format).
func (c *smClient) smCreate(ctx context.Context, key, value, projectID string) error {
	encKey, err := c.encryptSMField(key)
	if err != nil {
		return err
	}
	encValue, err := c.encryptSMField(value)
	if err != nil {
		return err
	}
	encNote, err := c.encryptSMField("")
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/organizations/%s/secrets", apiURL, c.orgID)
	body := map[string]interface{}{
		"organizationId": c.orgID,
		"key":            encKey,
		"value":          encValue,
		"note":           encNote,
	}
	if projectID != "" {
		body["projectIds"] = []string{projectID}
	}

	var resp smCreateResponse
	if err := jsonPOSTWithToken(ctx, url, c.apiToken, &resp, body); err != nil {
		return smError(err, "create secret")
	}

	// Print TSV: id\tkey (matches list output style)
	fmt.Printf("%s\t%s\n", resp.ID, resp.Key)
	return nil
}

// smCreateValue creates a new secret, reading the value from the provided reader.
// This is a testable helper that separates stdin reading from the create logic.
func (c *smClient) smCreateValue(ctx context.Context, key string, valueReader io.Reader, projectID string) error {
	data, err := io.ReadAll(valueReader)
	if err != nil {
		return fmt.Errorf("failed to read value: %w", err)
	}
	return c.smCreate(ctx, key, string(data), projectID)
}

// smEdit updates an existing secret by ID. It fetches the current secret,
// decrypts its fields, merges with the caller's changes (empty = keep current),
// encrypts all fields with the org key, and PUTs the result to /secrets/{id}.
// Project membership is preserved from the fetched secret.
func (c *smClient) smEdit(ctx context.Context, secretID, newKey, newValue, newNote string) error {
	// Fetch current secret to merge unchanged fields
	resp, err := c.fetchSecret(ctx, secretID)
	if err != nil {
		return err
	}

	// Decrypt current values
	curKey, err := c.decryptSMField(resp.Key)
	if err != nil {
		return fmt.Errorf("could not decrypt secret key: %w", err)
	}
	curValue, err := c.decryptSMField(resp.Value)
	if err != nil {
		return fmt.Errorf("could not decrypt secret value: %w", err)
	}
	curNote, err := c.decryptSMField(resp.Note)
	if err != nil {
		return fmt.Errorf("could not decrypt secret note: %w", err)
	}

	// Merge: keep current value when caller provides an empty string.
	if newKey == "" {
		newKey = curKey
	}
	if newValue == "" {
		newValue = curValue
	}
	if newNote == "" {
		newNote = curNote
	}

	// Encrypt all fields with the org key
	encKey, err := c.encryptSMField(newKey)
	if err != nil {
		return err
	}
	encValue, err := c.encryptSMField(newValue)
	if err != nil {
		return err
	}
	encNote, err := c.encryptSMField(newNote)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/secrets/%s", apiURL, secretID)
	body := map[string]interface{}{
		"key":   encKey,
		"value": encValue,
		"note":  encNote,
	}

	// Preserve project membership from the fetched secret
	if len(resp.Projects) > 0 {
		projIDs := make([]string, len(resp.Projects))
		for i, p := range resp.Projects {
			projIDs[i] = p.ID
		}
		body["projectIds"] = projIDs
	}

	var updateResp smCreateResponse
	if err := jsonPUTWithToken(ctx, url, c.apiToken, &updateResp, body); err != nil {
		return smError(err, "update secret")
	}

	fmt.Printf("%s\t%s\n", updateResp.ID, updateResp.Key)
	return nil
}

// cmdSM is the entry point for `bitw sm` commands.
func cmdSM(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: bitw sm <list|get|create|edit> [args]")
	}

	// Check args early to avoid unnecessary token validation/network calls.
	switch args[0] {
	case "get":
		if len(args) < 2 {
			return fmt.Errorf("usage: bitw sm get <key-or-id> [--project NAME]")
		}
	case "create":
		if len(args) < 2 {
			return fmt.Errorf("usage: bitw sm create <key> [value | --stdin] [--project NAME]")
		}
		// Quick scan for at least a key arg or --stdin (the value check
		// happens during flag parse below).
	case "edit":
		if len(args) < 2 {
			return fmt.Errorf("usage: bitw sm edit <key-or-id> [--key KEY] [--value VAL | --stdin] [--note NOTE] [--project NAME]")
		}
		// Quick scan for at least one modifier flag before any I/O.
		hasModifier := false
		for _, a := range args[1:] {
			if a == "--key" || a == "--value" || a == "--stdin" || a == "--note" ||
				strings.HasPrefix(a, "--key=") || strings.HasPrefix(a, "--value=") ||
				strings.HasPrefix(a, "--note=") {
				hasModifier = true
				break
			}
		}
		if !hasModifier {
			return fmt.Errorf("at least one of --key, --value, --stdin, or --note is required")
		}
	}

	// Resolve token with env-first, config-fallback precedence.
	rawToken := resolveSMAccessToken()
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
		fs := flag.NewFlagSet("get", flag.ContinueOnError)
		var getProject string
		fs.StringVar(&getProject, "project", "", "filter by project name")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		nonFlag := fs.Args()
		if len(nonFlag) < 1 {
			return fmt.Errorf("usage: bitw sm get <key-or-id> [--project NAME]")
		}
		return client.smGet(ctx, nonFlag[0], getProject)
	case "create":
		fs := flag.NewFlagSet("create", flag.ContinueOnError)
		var createProjectName string
		var createStdin bool
		fs.BoolVar(&createStdin, "stdin", false, "read value from stdin")
		fs.StringVar(&createProjectName, "project", "", "project to associate the secret with")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		nonFlag := fs.Args()
		if len(nonFlag) < 1 {
			return fmt.Errorf("usage: bitw sm create <key> [value | --stdin] [--project NAME]")
		}
		createKey := nonFlag[0]

		// --stdin and a positional value are contradictory.
		if createStdin && len(nonFlag) > 1 {
			return fmt.Errorf("cannot specify both a value argument and --stdin")
		}

		// Resolve project name to ID if specified
		var createProjectID string
		if createProjectName != "" {
			var err error
			createProjectID, err = client.resolveProjectID(ctx, createProjectName)
			if err != nil {
				return err
			}
		}

		if createStdin {
			return client.smCreateValue(ctx, createKey, os.Stdin, createProjectID)
		}

		if len(nonFlag) < 2 {
			return fmt.Errorf("usage: bitw sm create <key> <value> or bitw sm create <key> --stdin [--project NAME]")
		}
		return client.smCreate(ctx, createKey, nonFlag[1], createProjectID)
	case "edit":
		// Parse flags for edit subcommand. We use flag.FlagSet so the
		// args after the subcommand name can be parsed independently.
		fs := flag.NewFlagSet("edit", flag.ContinueOnError)
		var editKey, editValue, editNote, editProject string
		var editStdin bool
		fs.StringVar(&editKey, "key", "", "new key/name for the secret")
		fs.StringVar(&editValue, "value", "", "new value for the secret")
		fs.StringVar(&editNote, "note", "", "new note for the secret")
		fs.StringVar(&editProject, "project", "", "filter by project name")
		fs.BoolVar(&editStdin, "stdin", false, "read new value from stdin")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}

		// Resolve the secret ID from the remaining positional arg (the
		// key-or-id). After Parse, the first non-flag arg is the target.
		nonFlag := fs.Args()
		var keyOrID string
		if len(nonFlag) > 0 {
			keyOrID = nonFlag[0]
		}
		if keyOrID == "" {
			// Should not happen because args check above requires >= 2.
			return fmt.Errorf("usage: bitw sm edit <key-or-id> [--key KEY] [--value VAL | --stdin] [--note NOTE] [--project NAME]")
		}

		secretID, err := client.resolveSecretID(ctx, keyOrID, editProject)
		if err != nil {
			return err
		}

		// If --stdin, read value from stdin
		if editStdin {
			data, err := io.ReadAll(os.Stdin)
			if err != nil {
				return fmt.Errorf("failed to read value from stdin: %w", err)
			}
			editValue = string(data)
		}

		return client.smEdit(ctx, secretID, editKey, editValue, editNote)
	default:
		return fmt.Errorf("unknown sm command: %q (use list, get, create, or edit)", args[0])
	}
}
