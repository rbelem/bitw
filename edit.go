// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
)

// cmdEdit modifies an existing cipher in the vault.
// Usage:
//
//	bitw edit <cipher-name> [--notes NOTES] [--password-stdin] [--field NAME=VALUE]...
//	  [--ssh-private-key-stdin] [--ssh-public-key PUB]
//
// At least one modifier flag is required. The cipher's per-item key (if any)
// is preserved: fields are re-encrypted with the same item key, so the
// cipher.Key field is left unchanged on the wire.
//
// --password-stdin is only valid for login ciphers (type 1).
// --notes is valid for any cipher type.
// --field updates or creates custom fields by name (repeatable).
// --ssh-private-key-stdin and --ssh-public-key are only valid for ssh-key
// ciphers (type 5) and must be used together.
//
// The PUT endpoint /ciphers/{id} accepts the bare cipher (no wrapper),
// unlike the legacy POST /ciphers/create which wraps in {"cipher": ...}.
func cmdEdit(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("edit", flag.ContinueOnError)
	var notes string
	var stdinPassword bool
	var fields stringSliceFlag
	var stdinSSHPrivKey bool
	var sshPubKey string
	var hasNotes bool
	fs.StringVar(&notes, "notes", "", "new notes for the cipher")
	fs.BoolVar(&stdinPassword, "password-stdin", false, "read new login password from stdin")
	fs.Var(&fields, "field", "custom field NAME=VALUE (repeatable; updates or creates)")
	fs.BoolVar(&stdinSSHPrivKey, "ssh-private-key-stdin", false, "read new SSH private key from stdin (type 5 only)")
	fs.StringVar(&sshPubKey, "ssh-public-key", "", "new SSH public key (type 5 only)")
	// Track whether --notes was explicitly set (empty string is a valid value).
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "notes" {
			hasNotes = true
		}
	})
	if err := fs.Parse(args); err != nil {
		return err
	}
	// Re-check after parse since Visit runs during Parse.
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "notes" {
			hasNotes = true
		}
	})
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: bitw edit <cipher-name> [--notes NOTES] [--password-stdin] [--field NAME=VALUE]... [--ssh-private-key-stdin] [--ssh-public-key PUB]")
	}
	cipherName := fs.Arg(0)

	hasSSHPriv := stdinSSHPrivKey
	hasSSHPub := sshPubKey != ""

	// At least one modifier flag required.
	if !hasNotes && !stdinPassword && len(fields) == 0 && !hasSSHPriv && !hasSSHPub {
		return fmt.Errorf("at least one of --notes, --password-stdin, --field, --ssh-private-key-stdin, or --ssh-public-key is required")
	}

	// SSH key flags must be used together.
	if hasSSHPriv != hasSSHPub {
		return fmt.Errorf("--ssh-private-key-stdin and --ssh-public-key must be used together")
	}

	// Parse --field NAME=VALUE pairs.
	var parsedFields []fieldPair
	for _, f := range fields {
		eq := strings.IndexByte(f, '=')
		if eq <= 0 || eq == len(f)-1 {
			return fmt.Errorf("--field must be NAME=VALUE with non-empty both sides, got %q", f)
		}
		parsedFields = append(parsedFields, fieldPair{name: f[:eq], value: f[eq+1:]})
	}

	// Unlock vault.
	if _, err := secrets.password(); err != nil {
		return err
	}
	if err := secrets.initKeys(); err != nil {
		return err
	}

	// Find the cipher.
	cipher, err := findCipherByName(cipherName)
	if err != nil {
		return err
	}

	// Validate flag/cipher-type compatibility.
	if stdinPassword && cipher.Type != CipherLogin {
		return fmt.Errorf("--password-stdin is only valid for login ciphers (type 1); cipher %q is type %d", cipherName, cipher.Type)
	}
	if (hasSSHPriv || hasSSHPub) && cipher.Type != CipherSshKey {
		return fmt.Errorf("cannot set ssh key on cipher type %d", cipher.Type)
	}

	// Read new password from stdin if requested (before any encryption).
	var newPassword []byte
	if stdinPassword {
		newPassword, err = stdinReadAll()
		if err != nil {
			return fmt.Errorf("could not read password from stdin: %w", err)
		}
		newPassword = bytesTrimNewline(newPassword)
		if len(newPassword) == 0 {
			return fmt.Errorf("empty password; aborting")
		}
	}

	// Read new SSH private key from stdin if requested.
	var newSSHPrivKey []byte
	if hasSSHPriv {
		newSSHPrivKey, err = stdinReadAll()
		if err != nil {
			return fmt.Errorf("could not read SSH private key from stdin: %w", err)
		}
		newSSHPrivKey = bytesTrimNewline(newSSHPrivKey)
		if len(newSSHPrivKey) == 0 {
			return fmt.Errorf("empty SSH private key; aborting")
		}
	}

	// Build the PUT body. We re-encrypt fields using encryptFieldWith, which
	// preserves the cipher's item key (if any) or falls back to the base key.
	// The cipher.Key field is left unchanged.
	putBody := buildEditBody(cipher, hasNotes, notes, newPassword, parsedFields, newSSHPrivKey, []byte(sshPubKey))

	// Ensure token for the PUT call.
	if err := ensureToken(ctx); err != nil {
		return err
	}

	// PUT /ciphers/{id}. The modern endpoint accepts the bare cipher (no wrapper).
	var updated Cipher
	if err := jsonPUT(ctx, apiURL+"/ciphers/"+cipher.ID.String(), &updated, putBody); err != nil {
		return fmt.Errorf("could not edit cipher: %w", err)
	}

	fmt.Fprintf(os.Stderr, "✓ Edited %s (id: %s)\n", cipherName, cipher.ID)

	// Re-sync so the local data.json reflects the changes.
	if err := sync(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "warning: post-edit sync failed: %v\n", err)
	}
	return nil
}

// buildEditBody constructs the PUT body for /ciphers/{id}. It re-encrypts
// modified fields using the cipher's item key (if present) or the base key,
// preserving the existing cipher.Key. Unmodified fields are re-encrypted
// as-is to maintain the wire contract (all fields must be present).
func buildEditBody(cipher *Cipher, hasNotes bool, notes string, newPassword []byte, newFields []fieldPair, newSSHPrivKey, newSSHPubKey []byte) map[string]interface{} {
	body := map[string]interface{}{
		"type": cipher.Type,
		"name": cipher.Name, // already encrypted; pass through
	}

	// Preserve cipher.Key (item key) if present.
	if !cipher.Key.IsZero() {
		body["key"] = cipher.Key
	}

	// Notes: re-encrypt if changed, otherwise pass through.
	if hasNotes {
		if notes != "" {
			encNotes, _ := secrets.encryptFieldWith(cipher, []byte(notes))
			body["notes"] = encNotes
		} else {
			// Empty notes → clear.
			body["notes"] = nil
		}
	} else if cipher.Notes != nil {
		body["notes"] = *cipher.Notes
	}

	// Type-specific fields.
	switch cipher.Type {
	case CipherLogin:
		loginBody := map[string]interface{}{}
		if cipher.Login != nil {
			// Pass through existing login fields.
			if !cipher.Login.Username.IsZero() {
				loginBody["username"] = cipher.Login.Username
			} else {
				loginBody["username"] = nil
			}
			if !cipher.Login.URI.IsZero() {
				loginBody["uri"] = cipher.Login.URI
			}
			if !cipher.Login.Totp.IsZero() {
				loginBody["totp"] = cipher.Login.Totp
			}
			// Password: use new password if provided, else pass through.
			if len(newPassword) > 0 {
				encPw, _ := secrets.encryptFieldWith(cipher, newPassword)
				loginBody["password"] = encPw
			} else if !cipher.Login.Password.IsZero() {
				loginBody["password"] = cipher.Login.Password
			}
		}
		body["login"] = loginBody

	case CipherNote:
		// SecureNote type metadata.
		if cipher.SecureNote != nil {
			body["secureNote"] = map[string]interface{}{
				"type": cipher.SecureNote.Type,
			}
		} else {
			body["secureNote"] = map[string]interface{}{
				"type": 0,
			}
		}

	case CipherSshKey:
		if cipher.SshKey != nil {
			sshKeyMap := map[string]interface{}{}
			if len(newSSHPrivKey) > 0 {
				encPriv, _ := secrets.encryptFieldWith(cipher, newSSHPrivKey)
				sshKeyMap["privateKey"] = encPriv
			} else if !cipher.SshKey.PrivateKey.IsZero() {
				sshKeyMap["privateKey"] = cipher.SshKey.PrivateKey
			}
			if len(newSSHPubKey) > 0 {
				encPub, _ := secrets.encryptFieldWith(cipher, newSSHPubKey)
				sshKeyMap["publicKey"] = encPub
			} else if !cipher.SshKey.PublicKey.IsZero() {
				sshKeyMap["publicKey"] = cipher.SshKey.PublicKey
			}
			body["sshKey"] = sshKeyMap
		}
	}

	// Custom fields: merge existing with new (new overrides by name).
	existingFields := make(map[string]int) // name → index in result
	var mergedFields []map[string]interface{}
	for _, f := range cipher.Fields {
		fName, _ := secrets.decryptFieldStr(cipher, f.Name)
		existingFields[fName] = len(mergedFields)
		mergedFields = append(mergedFields, map[string]interface{}{
			"type":  f.Type,
			"name":  f.Name,
			"value": f.Value,
		})
	}
	for _, nf := range newFields {
		encName, _ := secrets.encryptFieldWith(cipher, []byte(nf.name))
		encValue, _ := secrets.encryptFieldWith(cipher, []byte(nf.value))
		if idx, ok := existingFields[nf.name]; ok {
			// Update existing field.
			mergedFields[idx]["name"] = encName
			mergedFields[idx]["value"] = encValue
		} else {
			// Add new field.
			mergedFields = append(mergedFields, map[string]interface{}{
				"type":  0, // text
				"name":  encName,
				"value": encValue,
			})
			existingFields[nf.name] = len(mergedFields) - 1
		}
	}
	if len(mergedFields) > 0 {
		body["fields"] = mergedFields
	}

	return body
}
