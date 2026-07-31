// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/google/uuid"
)

// cmdStatus prints the current runtime state of `bitw` for operators
// diagnosing auth / token / sync issues. Reads from `data.json`,
// `os.Getenv`, and (best-effort) libsecret — no network calls. Exits
// 0 even when the cached token is expired (expired is reported, not
// treated as an error).
//
// Usage:
//
//	bitw status [--json]
//
// Plain text output (default) prints one `key = value` per line to
// stdout; diagnostics on stderr. `--json` prints a single JSON object
// to stdout with the same field names (for scripting). Stdout
// discipline mirrors `bitw config` and ADR-0004 §Stdout discipline.
//
// Fields printed:
//   - email + email_source       (which tier supplied it)
//   - token_present, token_expiry, token_valid (RFC3339 / EXPIRED / n/a)
//   - refresh_token_present      (always false for client_credentials)
//   - grant                      (inferred: client_credentials vs password)
//   - master_password_source     ($PASSWORD / libsecret / would-prompt)
//   - last_sync, last_sync_age   (RFC3339 + "Xh ago")
//   - kdf                        (kdf: argon2id, iter=…, mem=…, par=…)
//   - api_url, identity_url
//   - device_id
//   - cipher_count               (personal + org = total)
func cmdStatus(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	var asJSON bool
	fs.BoolVar(&asJSON, "json", false, "emit a single JSON object to stdout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("usage: bitw status [--json]")
	}

	// We intentionally do NOT call ensureToken here. `bitw status` is a
	// diagnostic command — it must never trigger a re-auth or hit the
	// network. (ADR-0003 §Runtime token lifecycle documents the token
	// model; this command reports it without mutating it.)
	//
	// We also do NOT call secrets.initKeys — status reports source/state,
	// not decrypted secrets. No master password prompt.

	st := statusFromGlobal()

	if asJSON {
		out, err := json.MarshalIndent(st, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(out))
		return nil
	}

	// Plain text `key = value` output, one field per line.
	fmt.Printf("email                  = %s\n", st.Email)
	fmt.Printf("email_source           = %s\n", st.EmailSource)
	fmt.Printf("token_present          = %t\n", st.TokenPresent)
	fmt.Printf("token_expiry           = %s\n", st.TokenExpiry)
	fmt.Printf("token_valid            = %s\n", st.TokenValid)
	fmt.Printf("refresh_token_present  = %t\n", st.RefreshTokenPresent)
	fmt.Printf("grant                  = %s\n", st.Grant)
	fmt.Printf("master_password_source = %s\n", st.MasterPasswordSource)
	fmt.Printf("last_sync              = %s\n", st.LastSync)
	fmt.Printf("last_sync_age          = %s\n", st.LastSyncAge)
	fmt.Printf("kdf                    = %s\n", st.KDF)
	fmt.Printf("api_url                = %s\n", st.APIURL)
	fmt.Printf("identity_url           = %s\n", st.IdentityURL)
	fmt.Printf("device_id              = %s\n", st.DeviceID)
	fmt.Printf("cipher_count           = %d (personal=%d, org=%d)\n",
		st.CipherCount, st.PersonalCipherCount, st.OrgCipherCount)
	return nil
}

// status is the JSON-stable snapshot of `bitw` runtime state.
type status struct {
	Email                string `json:"email"`
	EmailSource          string `json:"email_source"`
	TokenPresent         bool   `json:"token_present"`
	TokenExpiry          string `json:"token_expiry"`
	TokenValid           string `json:"token_valid"`
	RefreshTokenPresent  bool   `json:"refresh_token_present"`
	Grant                string `json:"grant"`
	MasterPasswordSource string `json:"master_password_source"`
	LastSync             string `json:"last_sync"`
	LastSyncAge          string `json:"last_sync_age"`
	KDF                  string `json:"kdf"`
	APIURL               string `json:"api_url"`
	IdentityURL          string `json:"identity_url"`
	DeviceID             string `json:"device_id"`
	CipherCount          int    `json:"cipher_count"`
	PersonalCipherCount  int    `json:"personal_cipher_count"`
	OrgCipherCount       int    `json:"org_cipher_count"`
}

// statusFromGlobal assembles the status snapshot from globalData + env
// + best-effort libsecret lookup. The master-password libsecret check
// is silent: lookup failures are reported as "would-prompt", not as
// errors, because libsecret being locked is a normal user state.
func statusFromGlobal() status {
	s := status{
		APIURL:      apiURL,
		IdentityURL: idtURL,
		DeviceID:    globalData.DeviceID,
	}
	s.Email = secrets.email()
	s.EmailSource = secrets.emailSource()

	// Token model.
	if globalData.AccessToken != "" {
		s.TokenPresent = true
		s.TokenExpiry = globalData.TokenExpiry.Format(time.RFC3339)
		if time.Now().Before(globalData.TokenExpiry) {
			s.TokenValid = "valid"
		} else {
			s.TokenValid = "EXPIRED"
		}
	} else {
		s.TokenPresent = false
		s.TokenExpiry = "n/a"
		s.TokenValid = "n/a"
	}
	s.RefreshTokenPresent = globalData.RefreshToken != ""

	// Grant: inferred from env.
	switch {
	case os.Getenv("BW_CLIENTID") != "" && os.Getenv("BW_CLIENTSECRET") != "":
		s.Grant = "client_credentials"
	case globalData.RefreshToken != "":
		s.Grant = "password (with refresh_token)"
	default:
		s.Grant = "password (no refresh_token)"
	}

	// Master password source (best-effort, no prompt).
	s.MasterPasswordSource = passwordSource()

	// Last sync.
	if globalData.LastSync.IsZero() {
		s.LastSync = "never"
		s.LastSyncAge = "n/a"
	} else {
		s.LastSync = globalData.LastSync.Format(time.RFC3339)
		s.LastSyncAge = formatAge(time.Since(globalData.LastSync))
	}

	// KDF (reuse cache.go's kdfInfo if present; otherwise inline).
	s.KDF = kdfInfo()

	// Cipher counts (personal vs org).
	for i := range globalData.Sync.Ciphers {
		c := &globalData.Sync.Ciphers[i]
		if c.OrganizationID == nil || c.OrganizationID.String() == uuid.Nil.String() {
			s.PersonalCipherCount++
		} else {
			s.OrgCipherCount++
		}
	}
	s.CipherCount = s.PersonalCipherCount + s.OrgCipherCount

	return s
}

// passwordSource returns which tier would supply the master password
// right now. Mirrors the resolution order in `password()` (crypto.go:97-119)
// but reports the source without actually retrieving the value.
//
// The libsecret tier is reported as a static check (does `secret-tool`
// exist on PATH?) rather than a live probe. We deliberately do NOT
// run `secret-tool lookup` here because:
//  1. `readLibsecretPassword` (which we'd otherwise reuse) consumes
//     the password into `secrets._password`, mutating state during
//     what should be a pure diagnostic command.
//  2. A live `secret-tool lookup` may trigger a GUI keyring unlock
//     prompt on a locked keyring, contradicting the "no prompt"
//     promise of `bitw status`.
//  3. The tier reports conservatively — users who need to verify
//     libsecret presence can run `secret-tool lookup bitwarden
//     master-password` directly.
func passwordSource() string {
	if secrets._password != nil {
		return "cache"
	}
	if os.Getenv("PASSWORD") != "" {
		return "$PASSWORD"
	}
	if _, err := exec.LookPath("secret-tool"); err == nil {
		return "libsecret (if stored)"
	}
	return "would-prompt"
}

// formatAge renders a time.Duration as a short human-readable string.
// Used for the last_sync_age field. Negative durations are rendered as
// "in the future" (clock skew).
func formatAge(d time.Duration) string {
	if d < 0 {
		return "in the future (clock skew?)"
	}
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}
