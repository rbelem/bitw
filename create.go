// Copyright (c) 2019, Daniel Martí <mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
)

// cmdCreate creates a new Login-type cipher in the personal vault.
// Usage:
//
//	bitw create <cipher-name> [--notes NOTES] [--field NAME=VALUE]...
//
// PERSONAL VAULT ONLY — org-cipher creation (which requires RSA-OAEP
// encryption of the org key) is not implemented yet. If the same name
// already exists in any org vault you belong to, the idempotency check
// will still refuse; use `bw edit item <id>` to update the existing item.
//
// The secret value (login.password) is prompted for interactively via the
// standard zenity / kdialog / SSH_ASKPASS / tty priority chain
// (see promptWithAskpass in auth.go).
//
// Refuses to create a cipher whose name already exists; rotate existing
// items via `bw edit item <id>` instead. The script re-syncs after a
// successful creation so the new item is visible to subsequent `bitw` calls
// without requiring a separate `bitw sync`.
func cmdCreate(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("create", flag.ContinueOnError)
	var notes string
	var fields stringSliceFlag
	fs.StringVar(&notes, "notes", "", "notes for the cipher")
	fs.Var(&fields, "field", "custom field NAME=VALUE (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: bitw create [--notes NOTES] [--field NAME=VALUE]... <cipher-name> (personal vault only)")
	}
	cipherName := fs.Arg(0)

	// Parse --field NAME=VALUE pairs. Both halves must be non-empty.
	var parsedFields []fieldPair
	for _, f := range fields {
		eq := strings.IndexByte(f, '=')
		if eq <= 0 || eq == len(f)-1 {
			return fmt.Errorf("--field must be NAME=VALUE with non-empty both sides, got %q", f)
		}
		parsedFields = append(parsedFields, fieldPair{name: f[:eq], value: f[eq+1:]})
	}

	// Ensure token + sync (sync is required so the idempotency check below
	// sees the latest server state).
	if err := ensureToken(ctx); err != nil {
		return err
	}
	if err := sync(ctx); err != nil {
		return err
	}

	// Idempotency check: refuse if a cipher with this name already exists.
	if _, err := findCipherByName(cipherName); err == nil {
		return fmt.Errorf("cipher %q already exists; use `bw edit item <id>` to rotate", cipherName)
	}

	// Prompt for the secret value (hidden). Same priority chain as the
	// master password prompt, except we never read the secret from libsecret:
	// a stored secret in keyring would defeat the point of putting it in BW.
	prompt := fmt.Sprintf("Secret value for %q", cipherName)
	secret, err := passwordPromptFunc(prompt)
	if err != nil {
		return fmt.Errorf("could not obtain secret: %w", err)
	}
	secret = bytesTrimNewline(secret)
	if len(secret) == 0 {
		return fmt.Errorf("empty secret; aborting")
	}

	// Build the /ciphers/create request body.
	body, err := buildLoginCipher(cipherName, notes, secret, parsedFields)
	if err != nil {
		return err
	}

	// POST /ciphers/create.
	var created Cipher
	if err := jsonPOST(ctx, apiURL+"/ciphers/create", &created, body); err != nil {
		return fmt.Errorf("could not create cipher: %w", err)
	}

	fmt.Fprintf(os.Stderr, "✓ Created %s (id: %s)\n", cipherName, created.ID)
	if len(parsedFields) > 0 {
		fmt.Fprintf(os.Stderr, "  + %d custom field(s)\n", len(parsedFields))
	}

	// Re-sync so the local data.json reflects the new cipher. This is best-
	// effort: a sync failure does not roll back the successful creation on
	// the server, but the next `bitw cache` call will work regardless because
	// it loads data.json fresh on each invocation.
	if err := sync(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "warning: post-create sync failed: %v\n", err)
	}
	return nil
}

// fieldPair holds a parsed --field NAME=VALUE argument.
type fieldPair struct {
	name  string
	value string
}

// buildLoginCipher constructs a /ciphers/create request body for a personal
// Login cipher. organizationId is intentionally omitted (personal vault).
// All plaintext values (name, optional notes, password, custom field names
// and values) are encrypted with the user's symmetric key before being added
// to the body, so the request payload matches what Bitwarden expects.
func buildLoginCipher(name, notes string, password []byte, fields []fieldPair) (map[string]interface{}, error) {
	if err := secrets.initKeys(); err != nil {
		return nil, err
	}

	encName, err := secrets.encrypt([]byte(name))
	if err != nil {
		return nil, fmt.Errorf("encrypt name: %w", err)
	}

	body := map[string]interface{}{
		"type": CipherLogin,
		"name": encName,
		"login": map[string]interface{}{
			"username": CipherString{}, // empty encrypted username
			"password": mustEncrypt(password, "password"),
		},
	}

	if notes != "" {
		body["notes"] = mustEncrypt([]byte(notes), "notes")
	}

	if len(fields) > 0 {
		encFields := make([]map[string]interface{}, 0, len(fields))
		for _, f := range fields {
			encFields = append(encFields, map[string]interface{}{
				"type":  0, // text
				"name":  mustEncrypt([]byte(f.name), fmt.Sprintf("field name %q", f.name)),
				"value": mustEncrypt([]byte(f.value), fmt.Sprintf("field %q value", f.name)),
			})
		}
		body["fields"] = encFields
	}

	return body, nil
}

// mustEncrypt encrypts plaintext and panics on error. Used inside
// buildLoginCipher where every encryption call has already been guarded by
// an initKeys check; a panic here indicates a programmer error, not user
// input.
func mustEncrypt(plain []byte, label string) CipherString {
	cs, err := secrets.encrypt(plain)
	if err != nil {
		panic(fmt.Sprintf("encrypt %s: %v", label, err))
	}
	return cs
}

// bytesTrimNewline strips a single trailing newline from a secret returned
// by an interactive prompt (e.g. zenity echoes one; kdialog does not).
func bytesTrimNewline(b []byte) []byte {
	if n := len(b); n > 0 && b[n-1] == '\n' {
		return b[:n-1]
	}
	return b
}
