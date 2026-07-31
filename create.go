// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

// cmdCreate creates a new cipher in the personal vault.
// Usage:
//
//	bitw create <cipher-name> [--type N] [--notes NOTES] [--field NAME=VALUE]...
//	  [--password-stdin] [--ssh-private-key-stdin] [--ssh-public-key PUB]
//
// --type values: 1 (Login, default), 2 (SecureNote), 5 (SshKey).
//
// PERSONAL VAULT ONLY — org-cipher creation (which requires RSA-OAEP
// encryption of the org key) is not implemented yet. If the same name
// already exists in any org vault you belong to, the idempotency check
// will still refuse; use `bw edit item <id>` to update the existing item.
//
// For type 1 (Login): the secret value (login.password) is prompted for
// interactively via the standard zenity / kdialog / SSH_ASKPASS / tty
// priority chain (see promptWithAskpass in auth.go), or read from stdin
// with --password-stdin.
//
// For type 2 (SecureNote): --notes is required.
//
// For type 5 (SshKey): --ssh-private-key-stdin and --ssh-public-key are
// both required.
//
// Refuses to create a cipher whose name already exists; rotate existing
// items via `bw edit item <id>` instead. The script re-syncs after a
// successful creation so the new item is visible to subsequent `bitw` calls
// without requiring a separate `bitw sync`.
func cmdCreate(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("create", flag.ContinueOnError)
	var notes string
	var fields stringSliceFlag
	var stdinPassword bool
	var cipherType int
	var stdinSSHPrivKey bool
	var sshPubKey string
	fs.StringVar(&notes, "notes", "", "notes for the cipher")
	fs.Var(&fields, "field", "custom field NAME=VALUE (repeatable)")
	fs.BoolVar(&stdinPassword, "password-stdin", false, "read the login password from stdin")
	fs.IntVar(&cipherType, "type", 1, "cipher type: 1 (Login), 2 (SecureNote), 5 (SshKey)")
	fs.BoolVar(&stdinSSHPrivKey, "ssh-private-key-stdin", false, "read the SSH private key from stdin")
	fs.StringVar(&sshPubKey, "ssh-public-key", "", "SSH public key (for type 5)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: bitw create [--type N] [--notes NOTES] [--field NAME=VALUE]... [--password-stdin] [--ssh-private-key-stdin] [--ssh-public-key PUB] <cipher-name> (personal vault only)")
	}
	cipherName := fs.Arg(0)

	// Validate type.
	switch CipherType(cipherType) {
	case CipherLogin, CipherNote, CipherSshKey:
	default:
		return fmt.Errorf("--type must be 1 (Login), 2 (SecureNote), or 5 (SshKey), got %d", cipherType)
	}

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

	// Build the cipher body based on type.
	var body map[string]interface{}
	var err error

	switch CipherType(cipherType) {
	case CipherLogin:
		// Type 1: Login — requires password (via stdin or prompt).
		var secret []byte
		if stdinPassword {
			secret, err = stdinReadAll()
			if err != nil {
				return fmt.Errorf("could not read secret from stdin: %w", err)
			}
		} else {
			prompt := fmt.Sprintf("Secret value for %q", cipherName)
			secret, err = passwordPromptFunc(prompt)
			if err != nil {
				return fmt.Errorf("could not obtain secret: %w", err)
			}
		}
		secret = bytesTrimNewline(secret)
		if len(secret) == 0 {
			return fmt.Errorf("empty secret; aborting")
		}
		body, err = buildLoginCipher(cipherName, notes, secret, parsedFields)
		if err != nil {
			return err
		}

	case CipherNote:
		// Type 2: SecureNote — requires --notes.
		if notes == "" {
			return fmt.Errorf("--notes is required for type 2 (SecureNote)")
		}
		body, err = buildSecureNoteCipher(cipherName, notes, parsedFields)
		if err != nil {
			return err
		}

	case CipherSshKey:
		// Type 5: SshKey — requires both --ssh-private-key-stdin and --ssh-public-key.
		if !stdinSSHPrivKey {
			return fmt.Errorf("--ssh-private-key-stdin is required for type 5 (SshKey)")
		}
		if sshPubKey == "" {
			return fmt.Errorf("--ssh-public-key is required for type 5 (SshKey)")
		}
		privKey, err := stdinReadAll()
		if err != nil {
			return fmt.Errorf("could not read SSH private key from stdin: %w", err)
		}
		privKey = bytesTrimNewline(privKey)
		if len(privKey) == 0 {
			return fmt.Errorf("empty SSH private key; aborting")
		}
		body, err = buildSshKeyCipher(cipherName, notes, privKey, []byte(sshPubKey), parsedFields)
		if err != nil {
			return err
		}
	}

	// POST /ciphers/create. The legacy /ciphers/create endpoint expects the
	// cipher wrapped in a top-level "cipher" key (unlike the newer
	// /ciphers endpoint, which takes a flat body). Sending fields at the
	// top level causes the server to reject with "The Cipher field is
	// required".
	var created Cipher
	if err := jsonPOST(ctx, apiURL+"/ciphers/create", &created, map[string]interface{}{"cipher": body}); err != nil {
		return fmt.Errorf("could not create cipher: %w", err)
	}

	fmt.Fprintf(os.Stderr, "✓ Created %s (id: %s, personal vault)\n", cipherName, created.ID)
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

// stdinReadAll reads the whole of stdin and is overridable for tests.
var stdinReadAll = func() ([]byte, error) { return io.ReadAll(os.Stdin) }

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
			// The server's [EncryptedString] validator rejects empty strings
			// with "Username is not a valid encrypted string". Send null
			// (matches what bw sends for an absent username).
			"username": nil,
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

// buildSecureNoteCipher constructs a /ciphers/create request body for a
// personal SecureNote cipher (type 2).
func buildSecureNoteCipher(name, notes string, fields []fieldPair) (map[string]interface{}, error) {
	if err := secrets.initKeys(); err != nil {
		return nil, err
	}

	encName, err := secrets.encrypt([]byte(name))
	if err != nil {
		return nil, fmt.Errorf("encrypt name: %w", err)
	}

	body := map[string]interface{}{
		"type":  CipherNote,
		"name":  encName,
		"notes": mustEncrypt([]byte(notes), "notes"),
		"secureNote": map[string]interface{}{
			"type": 0, // Generic
		},
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

// buildSshKeyCipher constructs a /ciphers/create request body for a personal
// SshKey cipher (type 5).
func buildSshKeyCipher(name, notes string, privKey, pubKey []byte, fields []fieldPair) (map[string]interface{}, error) {
	if err := secrets.initKeys(); err != nil {
		return nil, err
	}

	encName, err := secrets.encrypt([]byte(name))
	if err != nil {
		return nil, fmt.Errorf("encrypt name: %w", err)
	}

	body := map[string]interface{}{
		"type": CipherSshKey,
		"name": encName,
		"sshKey": map[string]interface{}{
			"privateKey": mustEncrypt(privKey, "ssh private key"),
			"publicKey":  mustEncrypt(pubKey, "ssh public key"),
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
// build*Cipher where every encryption call has already been guarded by
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
