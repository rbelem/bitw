// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	qt "github.com/frankban/quicktest"
)

// makeTestJWT creates a JWT with the given claims for testing.
func makeTestJWT(claims map[string]interface{}) string {
	payload, _ := json.Marshal(claims)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)
	return "header." + payloadB64 + ".signature"
}

// TestSM_KAT is the mandatory Known Answer Test for SM crypto derivation.
// Uses the real Bitwarden fixture from sdk-internal client_secrets.rs.
func TestSM_KAT(t *testing.T) {
	// Load golden fixture
	data, err := os.ReadFile("testdata/sm-kat.json")
	qt.Assert(t, err, qt.IsNil)

	var kat struct {
		AccessToken      string `json:"access_token"`
		ExpectedKey      string `json:"expected_derived_key"`
		EncryptedPayload string `json:"encrypted_payload"`
		SecretKey        string `json:"secret_key"`
		SecretValue      string `json:"secret_value"`
		SecretNote       string `json:"secret_note"`
		ExpectedPlain    struct {
			Key   string `json:"key"`
			Value string `json:"value"`
			Note  string `json:"note"`
		} `json:"expected_plaintexts"`
	}
	qt.Assert(t, json.Unmarshal(data, &kat), qt.IsNil)

	// Parse token
	token, err := parseSMAccessToken(kat.AccessToken)
	qt.Assert(t, err, qt.IsNil)

	// Derive key
	derivedKey, err := deriveSMKey(token.EncKey)
	qt.Assert(t, err, qt.IsNil)

	// Assert derived key matches expected
	expectedKey, err := base64.StdEncoding.DecodeString(kat.ExpectedKey)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, derivedKey, qt.DeepEquals, expectedKey,
		qt.Commentf("HKDF derivation mismatch - fix the derivation, not the fixture"))

	// Decrypt org key
	var orgKeyCS CipherString
	qt.Assert(t, orgKeyCS.UnmarshalText([]byte(kat.EncryptedPayload)), qt.IsNil)
	orgKeyPlaintext, err := decryptWith(orgKeyCS, derivedKey[:32], derivedKey[32:])
	qt.Assert(t, err, qt.IsNil)

	// Parse JSON to extract encryptionKey
	var payload smEncryptedPayload
	qt.Assert(t, json.Unmarshal(orgKeyPlaintext, &payload), qt.IsNil)
	orgKey, err := base64.StdEncoding.DecodeString(payload.EncryptionKey)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, len(orgKey), qt.Equals, 64)

	// Decrypt secret fields
	decKey, err := func() (string, error) {
		var cs CipherString
		if err := cs.UnmarshalText([]byte(kat.SecretKey)); err != nil {
			return "", err
		}
		dec, err := decryptWith(cs, orgKey[:32], orgKey[32:])
		if err != nil {
			return "", err
		}
		return string(dec), nil
	}()
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, decKey, qt.Equals, kat.ExpectedPlain.Key)

	decValue, err := func() (string, error) {
		var cs CipherString
		if err := cs.UnmarshalText([]byte(kat.SecretValue)); err != nil {
			return "", err
		}
		dec, err := decryptWith(cs, orgKey[:32], orgKey[32:])
		if err != nil {
			return "", err
		}
		return string(dec), nil
	}()
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, decValue, qt.Equals, kat.ExpectedPlain.Value)

	decNote, err := func() (string, error) {
		var cs CipherString
		if err := cs.UnmarshalText([]byte(kat.SecretNote)); err != nil {
			return "", err
		}
		dec, err := decryptWith(cs, orgKey[:32], orgKey[32:])
		if err != nil {
			return "", err
		}
		return string(dec), nil
	}()
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, decNote, qt.Equals, kat.ExpectedPlain.Note)
}

// TestSM_ParseToken tests token parsing error cases.
func TestSM_ParseToken(t *testing.T) {
	tests := []struct {
		name    string
		token   string
		wantErr string
	}{
		{
			name:    "empty",
			token:   "",
			wantErr: "empty token",
		},
		{
			name:    "missing colon",
			token:   "0.client.secret",
			wantErr: "missing colon",
		},
		{
			name:    "wrong part count",
			token:   "0.client:enc",
			wantErr: "expected 3 dot-separated parts",
		},
		{
			name:    "bad version",
			token:   "1.client.secret:enc",
			wantErr: "unsupported version",
		},
		{
			name:    "enc key not 16 bytes",
			token:   "0.client.secret:c2hvcnQ=", // "short" = 5 bytes
			wantErr: "must be exactly 16 bytes",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseSMAccessToken(tc.token)
			qt.Assert(t, err, qt.IsNotNil)
			qt.Assert(t, err.Error(), qt.Contains, tc.wantErr)
		})
	}
}

// TestSM_ClaimFromAccessToken tests the generalized JWT claim extraction.
func TestSM_ClaimFromAccessToken(t *testing.T) {
	// Construct a JWT with organization claim
	payload := map[string]interface{}{
		"email":        "test@example.com",
		"organization": "f4e44a7f-1190-432a-9d4a-af96013127cb",
	}
	payloadJSON, _ := json.Marshal(payload)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	jwt := "header." + payloadB64 + ".signature"

	// Test organization claim
	org := claimFromAccessToken(jwt, "organization")
	qt.Assert(t, org, qt.Equals, "f4e44a7f-1190-432a-9d4a-af96013127cb")

	// Test email claim (backward compatibility)
	email := claimFromAccessToken(jwt, "email")
	qt.Assert(t, email, qt.Equals, "test@example.com")

	// Test missing claim
	missing := claimFromAccessToken(jwt, "nonexistent")
	qt.Assert(t, missing, qt.Equals, "")

	// Test malformed JWT
	malformed := claimFromAccessToken("not-a-jwt", "email")
	qt.Assert(t, malformed, qt.Equals, "")
}

// TestSM_ExchangeRequestShape tests the token exchange request format.
func TestSM_ExchangeRequestShape(t *testing.T) {
	var receivedForm url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/connect/token" {
			_ = r.ParseForm()
			receivedForm = r.Form
			_ = json.NewEncoder(w).Encode(smTokenExchangeResponse{
				AccessToken: makeTestJWT(map[string]interface{}{
					"organization": "f4e44a7f-1190-432a-9d4a-af96013127cb",
				}),
				ExpiresIn:        3600,
				TokenType:        "Bearer",
				EncryptedPayload: "2.test|test|test",
			})
		}
	}))
	defer server.Close()

	origIdtURL := idtURL
	idtURL = server.URL
	defer func() { idtURL = origIdtURL }()

	token := &smAccessToken{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		EncKey:       make([]byte, 16),
	}

	_, _, err := exchangeSMAccessToken(context.Background(), idtURL, token)
	qt.Assert(t, err, qt.IsNil)

	// Assert form values
	qt.Assert(t, receivedForm.Get("grant_type"), qt.Equals, "client_credentials")
	qt.Assert(t, receivedForm.Get("client_id"), qt.Equals, "test-client-id")
	qt.Assert(t, receivedForm.Get("client_secret"), qt.Equals, "test-client-secret")
	qt.Assert(t, receivedForm.Get("scope"), qt.Equals, "api.secrets")
}

// TestSM_ListDecoding tests list response decryption and formatting.
func TestSM_ListDecoding(t *testing.T) {
	// Load KAT fixture to get valid encrypted values
	data, err := os.ReadFile("testdata/sm-kat.json")
	qt.Assert(t, err, qt.IsNil)

	var kat struct {
		AccessToken      string `json:"access_token"`
		EncryptedPayload string `json:"encrypted_payload"`
		SecretKey        string `json:"secret_key"`
	}
	qt.Assert(t, json.Unmarshal(data, &kat), qt.IsNil)

	// Parse and derive keys
	token, err := parseSMAccessToken(kat.AccessToken)
	qt.Assert(t, err, qt.IsNil)
	derivedKey, err := deriveSMKey(token.EncKey)
	qt.Assert(t, err, qt.IsNil)

	// Decrypt org key (verify it works)
	var orgKeyCS CipherString
	qt.Assert(t, orgKeyCS.UnmarshalText([]byte(kat.EncryptedPayload)), qt.IsNil)
	_, err = decryptWith(orgKeyCS, derivedKey[:32], derivedKey[32:])
	qt.Assert(t, err, qt.IsNil)

	// Create a mock API server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/connect/token":
			jwt := makeTestJWT(map[string]interface{}{
				"organization": "f4e44a7f-1190-432a-9d4a-af96013127cb",
			})
			_ = json.NewEncoder(w).Encode(smTokenExchangeResponse{
				AccessToken:      jwt,
				ExpiresIn:        3600,
				TokenType:        "Bearer",
				EncryptedPayload: kat.EncryptedPayload,
			})
		case strings.HasPrefix(r.URL.Path, "/organizations/") && strings.HasSuffix(r.URL.Path, "/secrets"):
			// Return list with the fixture secret
			resp := smListResponse{
				Object: "SecretsWithProjectsList",
				Secrets: []smListSecret{
					{
						ID:             "15744a66-341a-4c62-af50-af960166b6bc",
						OrganizationID: "f4e44a7f-1190-432a-9d4a-af96013127cb",
						Key:            kat.SecretKey,
						Projects:       []smListProject{},
					},
				},
				Projects: []smListProject{},
			}
			_ = json.NewEncoder(w).Encode(resp)
		}
	}))
	defer server.Close()

	origApiURL := apiURL
	origIdtURL := idtURL
	apiURL = server.URL
	idtURL = server.URL
	defer func() {
		apiURL = origApiURL
		idtURL = origIdtURL
	}()

	// Create client
	client, err := newSMClient(context.Background(), kat.AccessToken)
	qt.Assert(t, err, qt.IsNil)

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err = client.smList(context.Background())
	qt.Assert(t, err, qt.IsNil)

	_ = w.Close()
	os.Stdout = oldStdout

	buf := make([]byte, 1024)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	// Should contain decrypted key "TEST"
	qt.Assert(t, output, qt.Contains, "TEST")
}

// TestSM_GetByID tests getting a secret by UUID.
func TestSM_GetByID(t *testing.T) {
	data, err := os.ReadFile("testdata/sm-kat.json")
	qt.Assert(t, err, qt.IsNil)

	var kat struct {
		AccessToken      string `json:"access_token"`
		EncryptedPayload string `json:"encrypted_payload"`
		SecretID         string `json:"secret_id"`
		SecretValue      string `json:"secret_value"`
	}
	qt.Assert(t, json.Unmarshal(data, &kat), qt.IsNil)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/connect/token":
			_ = json.NewEncoder(w).Encode(smTokenExchangeResponse{
				AccessToken: makeTestJWT(map[string]interface{}{
					"organization": "f4e44a7f-1190-432a-9d4a-af96013127cb",
				}),
				ExpiresIn:        3600,
				TokenType:        "Bearer",
				EncryptedPayload: kat.EncryptedPayload,
			})
		case "/secrets/" + kat.SecretID:
			_ = json.NewEncoder(w).Encode(smSecretResponse{
				ID:    kat.SecretID,
				Value: kat.SecretValue,
			})
		}
	}))
	defer server.Close()

	origApiURL := apiURL
	origIdtURL := idtURL
	apiURL = server.URL
	idtURL = server.URL
	defer func() {
		apiURL = origApiURL
		idtURL = origIdtURL
	}()

	client, err := newSMClient(context.Background(), kat.AccessToken)
	qt.Assert(t, err, qt.IsNil)

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err = client.smGet(context.Background(), kat.SecretID)
	qt.Assert(t, err, qt.IsNil)

	_ = w.Close()
	os.Stdout = oldStdout

	buf := make([]byte, 1024)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	qt.Assert(t, output, qt.Equals, "TEST\n")
}

// TestSM_GetByKey tests getting a secret by exact key match.
func TestSM_GetByKey(t *testing.T) {
	data, err := os.ReadFile("testdata/sm-kat.json")
	qt.Assert(t, err, qt.IsNil)

	var kat struct {
		AccessToken      string `json:"access_token"`
		EncryptedPayload string `json:"encrypted_payload"`
		SecretID         string `json:"secret_id"`
		SecretKey        string `json:"secret_key"`
		SecretValue      string `json:"secret_value"`
	}
	qt.Assert(t, json.Unmarshal(data, &kat), qt.IsNil)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/connect/token" {
			_ = json.NewEncoder(w).Encode(smTokenExchangeResponse{
				AccessToken: makeTestJWT(map[string]interface{}{
					"organization": "f4e44a7f-1190-432a-9d4a-af96013127cb",
				}),
				ExpiresIn:        3600,
				TokenType:        "Bearer",
				EncryptedPayload: kat.EncryptedPayload,
			})
		} else if strings.HasSuffix(r.URL.Path, "/secrets") {
			resp := smListResponse{
				Secrets: []smListSecret{
					{
						ID:  kat.SecretID,
						Key: kat.SecretKey,
					},
				},
			}
			_ = json.NewEncoder(w).Encode(resp)
		} else if r.URL.Path == "/secrets/"+kat.SecretID {
			resp := smSecretResponse{
				ID:    kat.SecretID,
				Value: kat.SecretValue,
			}
			_ = json.NewEncoder(w).Encode(resp)
		}
	}))
	defer server.Close()

	origApiURL := apiURL
	origIdtURL := idtURL
	apiURL = server.URL
	idtURL = server.URL
	defer func() {
		apiURL = origApiURL
		idtURL = origIdtURL
	}()

	client, err := newSMClient(context.Background(), kat.AccessToken)
	qt.Assert(t, err, qt.IsNil)

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err = client.smGet(context.Background(), "TEST")
	qt.Assert(t, err, qt.IsNil)

	_ = w.Close()
	os.Stdout = oldStdout

	buf := make([]byte, 1024)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	qt.Assert(t, output, qt.Equals, "TEST\n")
}

// TestSM_GetFuzzy tests fuzzy matching for secret lookup.
func TestSM_GetFuzzy(t *testing.T) {
	data, err := os.ReadFile("testdata/sm-kat.json")
	qt.Assert(t, err, qt.IsNil)

	var kat struct {
		AccessToken      string `json:"access_token"`
		EncryptedPayload string `json:"encrypted_payload"`
		SecretID         string `json:"secret_id"`
		SecretKey        string `json:"secret_key"`
		SecretValue      string `json:"secret_value"`
	}
	qt.Assert(t, json.Unmarshal(data, &kat), qt.IsNil)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/connect/token" {
			_ = json.NewEncoder(w).Encode(smTokenExchangeResponse{
				AccessToken: makeTestJWT(map[string]interface{}{
					"organization": "f4e44a7f-1190-432a-9d4a-af96013127cb",
				}),
				ExpiresIn:        3600,
				TokenType:        "Bearer",
				EncryptedPayload: kat.EncryptedPayload,
			})
		} else if strings.HasSuffix(r.URL.Path, "/secrets") {
			resp := smListResponse{
				Secrets: []smListSecret{
					{
						ID:  kat.SecretID,
						Key: kat.SecretKey,
					},
				},
			}
			_ = json.NewEncoder(w).Encode(resp)
		} else if r.URL.Path == "/secrets/"+kat.SecretID {
			resp := smSecretResponse{
				ID:    kat.SecretID,
				Value: kat.SecretValue,
			}
			_ = json.NewEncoder(w).Encode(resp)
		}
	}))
	defer server.Close()

	origApiURL := apiURL
	origIdtURL := idtURL
	apiURL = server.URL
	idtURL = server.URL
	defer func() {
		apiURL = origApiURL
		idtURL = origIdtURL
	}()

	client, err := newSMClient(context.Background(), kat.AccessToken)
	qt.Assert(t, err, qt.IsNil)

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// "TES" should fuzzy match "TEST"
	err = client.smGet(context.Background(), "TES")
	qt.Assert(t, err, qt.IsNil)

	_ = w.Close()
	os.Stdout = oldStdout

	buf := make([]byte, 1024)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	qt.Assert(t, output, qt.Equals, "TEST\n")
}

// TestSM_GetNotFound tests error when secret is not found.
func TestSM_GetNotFound(t *testing.T) {
	data, err := os.ReadFile("testdata/sm-kat.json")
	qt.Assert(t, err, qt.IsNil)

	var kat struct {
		AccessToken      string `json:"access_token"`
		EncryptedPayload string `json:"encrypted_payload"`
	}
	qt.Assert(t, json.Unmarshal(data, &kat), qt.IsNil)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/connect/token" {
			_ = json.NewEncoder(w).Encode(smTokenExchangeResponse{
				AccessToken: makeTestJWT(map[string]interface{}{
					"organization": "f4e44a7f-1190-432a-9d4a-af96013127cb",
				}),
				ExpiresIn:        3600,
				TokenType:        "Bearer",
				EncryptedPayload: kat.EncryptedPayload,
			})
		} else if strings.HasSuffix(r.URL.Path, "/secrets") {
			resp := smListResponse{
				Secrets: []smListSecret{},
			}
			_ = json.NewEncoder(w).Encode(resp)
		}
	}))
	defer server.Close()

	origApiURL := apiURL
	origIdtURL := idtURL
	apiURL = server.URL
	idtURL = server.URL
	defer func() {
		apiURL = origApiURL
		idtURL = origIdtURL
	}()

	client, err := newSMClient(context.Background(), kat.AccessToken)
	qt.Assert(t, err, qt.IsNil)

	err = client.smGet(context.Background(), "NONEXISTENT")
	qt.Assert(t, err, qt.IsNotNil)
	qt.Assert(t, err.Error(), qt.Contains, "not found")
}

// TestSM_ErrorPaths tests HTTP error handling.
func TestSM_ErrorPaths(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		wantErr    string
	}{
		{
			name:       "401 unauthorized",
			statusCode: 401,
			wantErr:    "SM authentication failed (401)",
		},
		{
			name:       "403 forbidden",
			statusCode: 403,
			wantErr:    "SM authentication failed (403)",
		},
		{
			name:       "404 not found",
			statusCode: 404,
			// The UUID fetch 404s and falls through to key search, which
			// also 404s — the final message names the queried secret.
			wantErr: `secret "15744a66-341a-4c62-af50-af960166b6bc" not found`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data, err := os.ReadFile("testdata/sm-kat.json")
			qt.Assert(t, err, qt.IsNil)

			var kat struct {
				AccessToken      string `json:"access_token"`
				EncryptedPayload string `json:"encrypted_payload"`
			}
			qt.Assert(t, json.Unmarshal(data, &kat), qt.IsNil)

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/connect/token" {
					_ = json.NewEncoder(w).Encode(smTokenExchangeResponse{
						AccessToken: makeTestJWT(map[string]interface{}{
							"organization": "f4e44a7f-1190-432a-9d4a-af96013127cb",
						}),
						ExpiresIn:        3600,
						TokenType:        "Bearer",
						EncryptedPayload: kat.EncryptedPayload,
					})
				} else {
					http.Error(w, "error body", tc.statusCode)
				}
			}))
			defer server.Close()

			origApiURL := apiURL
			origIdtURL := idtURL
			apiURL = server.URL
			idtURL = server.URL
			defer func() {
				apiURL = origApiURL
				idtURL = origIdtURL
			}()

			client, err := newSMClient(context.Background(), kat.AccessToken)
			qt.Assert(t, err, qt.IsNil)

			err = client.smGet(context.Background(), "15744a66-341a-4c62-af50-af960166b6bc")
			qt.Assert(t, err, qt.IsNotNil)
			qt.Assert(t, err.Error(), qt.Contains, tc.wantErr)
		})
	}
}

// TestSM_UnsetToken tests error when SM_ACCESS_TOKEN is not set.
func TestSM_UnsetToken(t *testing.T) {
	origToken := os.Getenv("SM_ACCESS_TOKEN")
	_ = os.Unsetenv("SM_ACCESS_TOKEN")
	defer func() {
		if origToken != "" {
			_ = os.Setenv("SM_ACCESS_TOKEN", origToken)
		}
	}()

	err := cmdSM(context.Background(), []string{"list"})
	qt.Assert(t, err, qt.IsNotNil)
	qt.Assert(t, err.Error(), qt.Equals, "SM_ACCESS_TOKEN environment variable is not set")
}

// TestSM_ProjectNameDefensiveDecrypt tests defensive project name decryption.
func TestSM_ProjectNameDefensiveDecrypt(t *testing.T) {
	data, err := os.ReadFile("testdata/sm-kat.json")
	qt.Assert(t, err, qt.IsNil)

	var kat struct {
		AccessToken      string `json:"access_token"`
		EncryptedPayload string `json:"encrypted_payload"`
		SecretKey        string `json:"secret_key"`
	}
	qt.Assert(t, json.Unmarshal(data, &kat), qt.IsNil)

	// Parse and derive keys
	token, err := parseSMAccessToken(kat.AccessToken)
	qt.Assert(t, err, qt.IsNil)
	derivedKey, err := deriveSMKey(token.EncKey)
	qt.Assert(t, err, qt.IsNil)

	// Decrypt org key
	var orgKeyCS CipherString
	qt.Assert(t, orgKeyCS.UnmarshalText([]byte(kat.EncryptedPayload)), qt.IsNil)
	orgKeyPlaintext, err := decryptWith(orgKeyCS, derivedKey[:32], derivedKey[32:])
	qt.Assert(t, err, qt.IsNil)

	// Parse JSON to extract encryptionKey
	var payload smEncryptedPayload
	qt.Assert(t, json.Unmarshal(orgKeyPlaintext, &payload), qt.IsNil)
	orgKey, err := base64.StdEncoding.DecodeString(payload.EncryptionKey)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, len(orgKey), qt.Equals, 64)

	// Encrypt a project name with org key
	encProjName, err := encryptWith([]byte("EncryptedProject"), AesCbc256_HmacSha256_B64, orgKey[:32], orgKey[32:])
	qt.Assert(t, err, qt.IsNil)

	// Test decryptProjectName directly (now returns string, not (string, error))
	client2 := &smClient{orgKey: orgKey}
	qt.Assert(t, client2.decryptProjectName("PlaintextProject"), qt.Equals, "PlaintextProject")
	qt.Assert(t, client2.decryptProjectName(encProjName.String()), qt.Equals, "EncryptedProject")
	// Bad cipher string falls back to raw name
	qt.Assert(t, client2.decryptProjectName("2.bad|bad|bad"), qt.Equals, "2.bad|bad|bad")
}

// TestSM_TokenWhitespace tests that leading/trailing whitespace in
// SM_ACCESS_TOKEN is trimmed (M1).
func TestSM_TokenWhitespace(t *testing.T) {
	data, err := os.ReadFile("testdata/sm-kat.json")
	qt.Assert(t, err, qt.IsNil)

	var kat struct {
		AccessToken      string `json:"access_token"`
		EncryptedPayload string `json:"encrypted_payload"`
	}
	qt.Assert(t, json.Unmarshal(data, &kat), qt.IsNil)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/connect/token" {
			_ = json.NewEncoder(w).Encode(smTokenExchangeResponse{
				AccessToken: makeTestJWT(map[string]interface{}{
					"organization": "f4e44a7f-1190-432a-9d4a-af96013127cb",
				}),
				ExpiresIn:        3600,
				TokenType:        "Bearer",
				EncryptedPayload: kat.EncryptedPayload,
			})
		} else if strings.HasSuffix(r.URL.Path, "/secrets") {
			_ = json.NewEncoder(w).Encode(smListResponse{})
		}
	}))
	defer server.Close()

	origApiURL := apiURL
	origIdtURL := idtURL
	apiURL = server.URL
	idtURL = server.URL
	defer func() {
		apiURL = origApiURL
		idtURL = origIdtURL
	}()

	// Token with leading space + trailing \n should work
	tokenWithWhitespace := " " + kat.AccessToken + "\n"
	origToken := os.Getenv("SM_ACCESS_TOKEN")
	_ = os.Setenv("SM_ACCESS_TOKEN", tokenWithWhitespace)
	defer func() {
		if origToken != "" {
			_ = os.Setenv("SM_ACCESS_TOKEN", origToken)
		} else {
			_ = os.Unsetenv("SM_ACCESS_TOKEN")
		}
	}()

	err = cmdSM(context.Background(), []string{"list"})
	qt.Assert(t, err, qt.IsNil)
}

// TestSM_TokenWhitespaceOnly tests that a whitespace-only token is treated
// as unset (M1).
func TestSM_TokenWhitespaceOnly(t *testing.T) {
	origToken := os.Getenv("SM_ACCESS_TOKEN")
	_ = os.Setenv("SM_ACCESS_TOKEN", "   \n\t  ")
	defer func() {
		if origToken != "" {
			_ = os.Setenv("SM_ACCESS_TOKEN", origToken)
		} else {
			_ = os.Unsetenv("SM_ACCESS_TOKEN")
		}
	}()

	err := cmdSM(context.Background(), []string{"list"})
	qt.Assert(t, err, qt.IsNotNil)
	qt.Assert(t, err.Error(), qt.Equals, "SM_ACCESS_TOKEN environment variable is not set")
}

// TestSM_AmbiguousKey tests that duplicate keys produce an error (M2).
func TestSM_AmbiguousKey(t *testing.T) {
	data, err := os.ReadFile("testdata/sm-kat.json")
	qt.Assert(t, err, qt.IsNil)

	var kat struct {
		AccessToken      string `json:"access_token"`
		EncryptedPayload string `json:"encrypted_payload"`
		SecretKey        string `json:"secret_key"`
	}
	qt.Assert(t, json.Unmarshal(data, &kat), qt.IsNil)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/connect/token" {
			_ = json.NewEncoder(w).Encode(smTokenExchangeResponse{
				AccessToken: makeTestJWT(map[string]interface{}{
					"organization": "f4e44a7f-1190-432a-9d4a-af96013127cb",
				}),
				ExpiresIn:        3600,
				TokenType:        "Bearer",
				EncryptedPayload: kat.EncryptedPayload,
			})
		} else if strings.HasSuffix(r.URL.Path, "/secrets") {
			// Return two secrets with the same key
			resp := smListResponse{
				Secrets: []smListSecret{
					{ID: "id-1", Key: kat.SecretKey},
					{ID: "id-2", Key: kat.SecretKey},
				},
			}
			_ = json.NewEncoder(w).Encode(resp)
		}
	}))
	defer server.Close()

	origApiURL := apiURL
	origIdtURL := idtURL
	apiURL = server.URL
	idtURL = server.URL
	defer func() {
		apiURL = origApiURL
		idtURL = origIdtURL
	}()

	client, err := newSMClient(context.Background(), kat.AccessToken)
	qt.Assert(t, err, qt.IsNil)

	// Capture stdout to verify it's empty
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err = client.smGet(context.Background(), "TEST")

	_ = w.Close()
	os.Stdout = oldStdout

	buf := make([]byte, 1024)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	qt.Assert(t, err, qt.IsNotNil)
	qt.Assert(t, err.Error(), qt.Contains, "ambiguous")
	qt.Assert(t, err.Error(), qt.Contains, "2 secrets match")
	qt.Assert(t, output, qt.Equals, "") // stdout must be empty
}

// TestSM_Exchange401 tests that a 401 during token exchange produces
// "SM authentication failed" (M3).
func TestSM_Exchange401(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/connect/token" {
			http.Error(w, "invalid token", http.StatusUnauthorized)
		}
	}))
	defer server.Close()

	origIdtURL := idtURL
	idtURL = server.URL
	defer func() { idtURL = origIdtURL }()

	token := &smAccessToken{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		EncKey:       make([]byte, 16),
	}

	_, _, err := exchangeSMAccessToken(context.Background(), idtURL, token)
	qt.Assert(t, err, qt.IsNotNil)
	qt.Assert(t, err.Error(), qt.Contains, "SM authentication failed")
	qt.Assert(t, err.Error(), qt.Contains, "401")
}

// TestSM_List404IncludesContext tests that a 404 on the list endpoint
// includes context (m5).
func TestSM_List404IncludesContext(t *testing.T) {
	data, err := os.ReadFile("testdata/sm-kat.json")
	qt.Assert(t, err, qt.IsNil)

	var kat struct {
		AccessToken      string `json:"access_token"`
		EncryptedPayload string `json:"encrypted_payload"`
	}
	qt.Assert(t, json.Unmarshal(data, &kat), qt.IsNil)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/connect/token" {
			_ = json.NewEncoder(w).Encode(smTokenExchangeResponse{
				AccessToken: makeTestJWT(map[string]interface{}{
					"organization": "f4e44a7f-1190-432a-9d4a-af96013127cb",
				}),
				ExpiresIn:        3600,
				TokenType:        "Bearer",
				EncryptedPayload: kat.EncryptedPayload,
			})
		} else if strings.HasSuffix(r.URL.Path, "/secrets") {
			http.Error(w, "not found", 404)
		}
	}))
	defer server.Close()

	origApiURL := apiURL
	origIdtURL := idtURL
	apiURL = server.URL
	idtURL = server.URL
	defer func() {
		apiURL = origApiURL
		idtURL = origIdtURL
	}()

	client, err := newSMClient(context.Background(), kat.AccessToken)
	qt.Assert(t, err, qt.IsNil)

	err = client.smList(context.Background())
	qt.Assert(t, err, qt.IsNotNil)
	qt.Assert(t, err.Error(), qt.Contains, "list secrets")
	qt.Assert(t, err.Error(), qt.Contains, "not found")
}

// TestSM_UUIDKeyFallback tests that a key that is a valid UUID format
// but not an actual secret ID falls through to key/fuzzy search (m6).
func TestSM_UUIDKeyFallback(t *testing.T) {
	data, err := os.ReadFile("testdata/sm-kat.json")
	qt.Assert(t, err, qt.IsNil)

	var kat struct {
		AccessToken      string `json:"access_token"`
		EncryptedPayload string `json:"encrypted_payload"`
		SecretID         string `json:"secret_id"`
		SecretKey        string `json:"secret_key"`
		SecretValue      string `json:"secret_value"`
	}
	qt.Assert(t, json.Unmarshal(data, &kat), qt.IsNil)

	// Use a UUID as the key (the secret_id is a valid UUID)
	uuidKey := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

	// Derive the org key so we can encrypt a secret KEY that decrypts
	// to uuidKey — the fallback search must find it by exact key match.
	token, err := parseSMAccessToken(kat.AccessToken)
	qt.Assert(t, err, qt.IsNil)
	derivedKey, err := deriveSMKey(token.EncKey)
	qt.Assert(t, err, qt.IsNil)
	var orgKeyCS CipherString
	qt.Assert(t, orgKeyCS.UnmarshalText([]byte(kat.EncryptedPayload)), qt.IsNil)
	orgKeyPlaintext, err := decryptWith(orgKeyCS, derivedKey[:32], derivedKey[32:])
	qt.Assert(t, err, qt.IsNil)
	var payload smEncryptedPayload
	qt.Assert(t, json.Unmarshal(orgKeyPlaintext, &payload), qt.IsNil)
	orgKey, err := base64.StdEncoding.DecodeString(payload.EncryptionKey)
	qt.Assert(t, err, qt.IsNil)

	encUUIDKey, err := encryptWith([]byte(uuidKey), AesCbc256_HmacSha256_B64, orgKey[:32], orgKey[32:])
	qt.Assert(t, err, qt.IsNil)
	encUUIDKeyStr, err := encUUIDKey.MarshalText()
	qt.Assert(t, err, qt.IsNil)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/connect/token" {
			_ = json.NewEncoder(w).Encode(smTokenExchangeResponse{
				AccessToken: makeTestJWT(map[string]interface{}{
					"organization": "f4e44a7f-1190-432a-9d4a-af96013127cb",
				}),
				ExpiresIn:        3600,
				TokenType:        "Bearer",
				EncryptedPayload: kat.EncryptedPayload,
			})
		} else if r.URL.Path == "/secrets/"+uuidKey {
			// First request: UUID path → 404
			http.Error(w, "not found", 404)
		} else if strings.HasSuffix(r.URL.Path, "/secrets") {
			// Second request: list → return the secret whose key IS uuidKey
			resp := smListResponse{
				Secrets: []smListSecret{
					{
						ID:  kat.SecretID,
						Key: string(encUUIDKeyStr),
					},
				},
			}
			_ = json.NewEncoder(w).Encode(resp)
		} else if r.URL.Path == "/secrets/"+kat.SecretID {
			// Third request: fetch by real ID
			resp := smSecretResponse{
				ID:    kat.SecretID,
				Value: kat.SecretValue,
			}
			_ = json.NewEncoder(w).Encode(resp)
		}
	}))
	defer server.Close()

	origApiURL := apiURL
	origIdtURL := idtURL
	apiURL = server.URL
	idtURL = server.URL
	defer func() {
		apiURL = origApiURL
		idtURL = origIdtURL
	}()

	client, err := newSMClient(context.Background(), kat.AccessToken)
	qt.Assert(t, err, qt.IsNil)

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Use the UUID as the key — should fall through to key search
	err = client.smGet(context.Background(), uuidKey)
	qt.Assert(t, err, qt.IsNil)

	_ = w.Close()
	os.Stdout = oldStdout

	buf := make([]byte, 1024)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	qt.Assert(t, output, qt.Equals, "TEST\n")
}
