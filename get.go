// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"
)

var shellIdentRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func isValidShellIdent(s string) bool {
	return shellIdentRe.MatchString(s)
}

// findCipherByName searches all ciphers (not just logins) by decrypted name.
// Item-key-aware: uses decryptFieldStr so ciphers with per-item keys are
// correctly matched.
func findCipherByName(name string) (*Cipher, error) {
	for i := range globalData.Sync.Ciphers {
		cipher := &globalData.Sync.Ciphers[i]
		decName, err := secrets.decryptFieldStr(cipher, cipher.Name)
		if err != nil {
			continue
		}
		if decName == name {
			return cipher, nil
		}
	}
	return nil, fmt.Errorf("cipher %q not found", name)
}

type stringSliceFlag []string

func (s *stringSliceFlag) String() string { return strings.Join(*s, ",") }
func (s *stringSliceFlag) Set(v string) error {
	*s = append(*s, v)
	return nil
}

const getUsage = "usage: bitw get [--env-name NAME] [--json] [--field FIELD] <cipher-name> | bitw get totp <cipher-name>"

func cmdGet(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("get", flag.ContinueOnError)
	var envName string
	var jsonMode bool
	var fields stringSliceFlag
	fs.StringVar(&envName, "env-name", "", "variable name for password in default mode")
	fs.BoolVar(&jsonMode, "json", false, "emit the fully decrypted cipher as JSON")
	fs.Var(&fields, "field", "field to emit (repeatable); triggers field mode")
	if err := fs.Parse(args); err != nil {
		return err
	}

	totpMode := false
	pickerMode := false
	var cipherName string
	switch {
	case fs.NArg() == 0:
		// `bitw get` with no cipher → interactive picker (needs a terminal).
		if !isTerminalFunc(int(os.Stdin.Fd())) {
			return fmt.Errorf(getUsage)
		}
		pickerMode = true
	case fs.NArg() == 1 && fs.Arg(0) == "totp":
		// `bitw get totp` bare → picker in TOTP mode.
		if !isTerminalFunc(int(os.Stdin.Fd())) {
			return fmt.Errorf("usage: bitw get totp <cipher-name>")
		}
		pickerMode = true
		totpMode = true
	case fs.NArg() == 1:
		cipherName = fs.Arg(0)
	case fs.NArg() == 2 && fs.Arg(0) == "totp":
		totpMode = true
		cipherName = fs.Arg(1)
	default:
		return fmt.Errorf(getUsage)
	}

	// Unlock vault.
	if _, err := secrets.password(); err != nil {
		return err
	}
	if err := secrets.initKeys(); err != nil {
		return err
	}

	var cipher *Cipher
	if pickerMode {
		picked, err := pickCipher(decryptCipherList(), "")
		if err != nil {
			return err
		}
		if picked == nil {
			return nil // cancelled (Esc / Ctrl-C / EOF)
		}
		cipher = picked.cipher
		cipherName = picked.name
	} else {
		c, err := findCipherByName(cipherName)
		if err != nil {
			// No exact match. Rank fuzzy candidates and decide whether the
			// top match is confident enough to auto-select, ambiguous, or too
			// weak — see autoSelectCandidate and fuzzyFallbackFloor.
			// Candidates are "name username" for logins, so a query matching
			// either part can resolve the item.
			items := decryptCipherList()
			cands := make([]string, len(items))
			for i := range items {
				cands[i] = items[i].matchText()
			}
			if auto := autoSelectCandidate(fuzzyRank(cipherName, cands)); auto != nil {
				// Map the winning candidate back to its item (duplicate
				// name+username pairs resolve to the first, as before).
				var picked *pickerItem
				for i, cand := range cands {
					if cand == auto.name {
						picked = &items[i]
						break
					}
				}
				if picked == nil {
					return fmt.Errorf("internal: fuzzy match %q has no item", auto.name)
				}
				fmt.Fprintf(os.Stderr, "warning: no exact match for %q, using %q\n", cipherName, picked.name)
				c, cipherName = picked.cipher, picked.name
			} else if isTerminalFunc(int(os.Stdin.Fd())) {
				// Weak/ambiguous: let the user confirm via the picker, with
				// their query pre-typed so they can fix a typo or pick the
				// intended item. Cancel → exit 0 silently.
				picked, err := pickCipher(items, cipherName)
				if err != nil {
					return err
				}
				if picked == nil {
					return nil
				}
				c = picked.cipher
				cipherName = picked.name
			} else {
				// Non-interactive and not confident: never auto-select.
				return fmt.Errorf("cipher %q not found", cipherName)
			}
		}
		cipher = c
	}

	return cmdGetCipher(cipher, cipherName, totpMode, jsonMode, envName, fields)
}

// fuzzyFallbackFloor is the minimum fuzzyScore at which a non-exact name match
// is auto-selected without user confirmation. Calibrated against fuzzyScore's
// units (verified by TestFuzzyFallback_Calibration):
//   - "gith"→"GitHub Token" (4-char consecutive run)        = 32  → accept
//   - "git" →"GitHub"        (3-char consecutive run)        = 24  → accept
//   - "gt"  →"GitHub"        (gappy 2-char subsequence)      = 6   → reject
//
// A floor of 10 sits in the gap, accepting confident matches (≥16 for clean
// 2-char+ prefixes, higher for longer) while forcing weak gappy matches and
// single characters through the picker for confirmation.
const fuzzyFallbackFloor = 10

// autoSelectCandidate returns the fuzzy match that is safe to auto-select
// without user confirmation, or nil if there is no match, the best is below
// fuzzyFallbackFloor, or the top two are tied (ambiguous). ranked must be the
// output of fuzzyRank (sorted by score descending, ties broken alphabetically).
func autoSelectCandidate(ranked []rankedMatch) *rankedMatch {
	if len(ranked) == 0 || ranked[0].score < fuzzyFallbackFloor {
		return nil
	}
	if len(ranked) > 1 && ranked[1].score == ranked[0].score {
		return nil // exact tie → ambiguous
	}
	best := ranked[0]
	return &best
}

// cmdGetCipher emits a selected cipher per the mode flags. Shared by the
// normal name-based path, the interactive picker, and the fuzzy fallback so
// all three reach a single emit path.
func cmdGetCipher(cipher *Cipher, name string, totpMode, jsonMode bool, envName string, fields stringSliceFlag) error {
	if totpMode {
		return emitTotp(cipher, name)
	}
	if jsonMode {
		return emitCipherJSON(cipher)
	}
	if len(fields) > 0 {
		// Field mode: emit bare values, one per --field.
		for _, f := range fields {
			val, err := resolveField(cipher, f)
			if err != nil {
				return err
			}
			if val == "" {
				continue
			}
			fmt.Println(val)
		}
		return nil
	}

	// Default mode: depends on cipher type.
	switch cipher.Type {
	case CipherLogin:
		return emitLoginExports(cipher, envName)
	case CipherNote, CipherSshKey:
		return emitNoteExport(cipher, envName)
	default:
		return fmt.Errorf("cipher %q has unsupported type %d", name, cipher.Type)
	}
}

// decryptCipherList returns all ciphers whose name decrypts successfully,
// warning on stderr about any that fail (mirrors the cipherIndex loop in
// cache.go). Used both to populate the picker and to seed fuzzy fallback.
func decryptCipherList() []pickerItem {
	var items []pickerItem
	for i := range globalData.Sync.Ciphers {
		c := &globalData.Sync.Ciphers[i]
		name, err := secrets.decryptFieldStr(c, c.Name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not decrypt name of cipher %s: %v\n", c.ID, err)
			continue
		}
		it := pickerItem{cipher: c, name: name, typ: c.Type}
		// For logins, also surface the username so fuzzy matching and the
		// picker can disambiguate by it. A failing username decrypt is
		// non-fatal (the item still works, just without a username), but
		// warn so the user knows the row is missing it.
		if c.Type == CipherLogin && c.Login != nil && !c.Login.Username.IsZero() {
			if u, err := secrets.decryptFieldStr(c, c.Login.Username); err == nil {
				it.username = u
			} else {
				fmt.Fprintf(os.Stderr, "warning: could not decrypt username of cipher %s: %v\n", c.ID, err)
			}
		}
		items = append(items, it)
	}
	return items
}

// emitLoginExports emits shell-eval export lines for a login cipher.
func emitLoginExports(cipher *Cipher, envName string) error {
	if cipher.Login == nil {
		return nil
	}
	password, err := secrets.decryptFieldStr(cipher, cipher.Login.Password)
	if err != nil {
		return fmt.Errorf("could not decrypt password: %v", err)
	}
	pwVar := envName
	if pwVar == "" {
		pwVar = "LOGIN_PASSWORD"
	}
	if !isValidShellIdent(pwVar) {
		fmt.Fprintf(os.Stderr, "warning: skipping invalid shell identifier %q\n", pwVar)
	} else if password != "" {
		fmt.Printf("export %s=%s\n", pwVar, shellQuote(password))
	}

	for _, field := range cipher.Fields {
		name, err := secrets.decryptFieldStr(cipher, field.Name)
		if err != nil {
			return fmt.Errorf("could not decrypt field name: %v", err)
		}
		if !isValidShellIdent(name) {
			fmt.Fprintf(os.Stderr, "warning: skipping field with invalid shell identifier %q\n", name)
			continue
		}
		val, err := secrets.decryptFieldStr(cipher, field.Value)
		if err != nil {
			return fmt.Errorf("could not decrypt field %q: %v", name, err)
		}
		if strings.TrimSpace(val) == "" {
			continue
		}
		fmt.Printf("export %s=%s\n", name, shellQuote(val))
	}
	return nil
}

// emitNoteExport emits export NOTES='...' for non-login ciphers.
func emitNoteExport(cipher *Cipher, envName string) error {
	var notes string
	if cipher.Notes != nil {
		var err error
		notes, err = secrets.decryptFieldStr(cipher, *cipher.Notes)
		if err != nil {
			return fmt.Errorf("could not decrypt notes: %v", err)
		}
	}
	nVar := envName
	if nVar == "" {
		nVar = "NOTES"
	}
	if !isValidShellIdent(nVar) {
		fmt.Fprintf(os.Stderr, "warning: skipping invalid shell identifier %q\n", nVar)
	} else if notes != "" {
		fmt.Printf("export %s=%s\n", nVar, shellQuote(notes))
	}
	return nil
}

// jsonCipher* types model the --json output schema.
type jsonCipherOutput struct {
	Type         CipherType        `json:"type"`
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Notes        string            `json:"notes,omitempty"`
	RevisionDate string            `json:"revisionDate"`
	Login        *jsonCipherLogin  `json:"login,omitempty"`
	SshKey       *jsonCipherSshKey `json:"sshKey,omitempty"`
	Fields       []jsonCipherField `json:"fields,omitempty"`
}

type jsonCipherLogin struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	URI      string `json:"uri,omitempty"`
}

type jsonCipherSshKey struct {
	PrivateKey string `json:"privateKey,omitempty"`
	PublicKey  string `json:"publicKey,omitempty"`
}

type jsonCipherField struct {
	Name  string `json:"name,omitempty"`
	Value string `json:"value,omitempty"`
}

// emitCipherJSON emits the fully decrypted cipher as JSON on stdout.
func emitCipherJSON(cipher *Cipher) error {
	out := jsonCipherOutput{
		Type:         cipher.Type,
		ID:           cipher.ID.String(),
		RevisionDate: cipher.RevisionDate.Format("2006-01-02T15:04:05Z07:00"),
	}

	name, err := secrets.decryptFieldStr(cipher, cipher.Name)
	if err != nil {
		return fmt.Errorf("could not decrypt name: %v", err)
	}
	out.Name = name

	if cipher.Notes != nil {
		notes, err := secrets.decryptFieldStr(cipher, *cipher.Notes)
		if err != nil {
			return fmt.Errorf("could not decrypt notes: %v", err)
		}
		out.Notes = notes
	}

	if cipher.Login != nil {
		login := &jsonCipherLogin{}
		if !cipher.Login.Username.IsZero() {
			login.Username, err = secrets.decryptFieldStr(cipher, cipher.Login.Username)
			if err != nil {
				return fmt.Errorf("could not decrypt username: %v", err)
			}
		}
		if !cipher.Login.Password.IsZero() {
			login.Password, err = secrets.decryptFieldStr(cipher, cipher.Login.Password)
			if err != nil {
				return fmt.Errorf("could not decrypt password: %v", err)
			}
		}
		if !cipher.Login.URI.IsZero() {
			login.URI, err = secrets.decryptFieldStr(cipher, cipher.Login.URI)
			if err != nil {
				return fmt.Errorf("could not decrypt URI: %v", err)
			}
		}
		out.Login = login
	}

	if cipher.SshKey != nil {
		sshKey := &jsonCipherSshKey{}
		if !cipher.SshKey.PrivateKey.IsZero() {
			sshKey.PrivateKey, err = secrets.decryptFieldStr(cipher, cipher.SshKey.PrivateKey)
			if err != nil {
				return fmt.Errorf("could not decrypt privateKey: %v", err)
			}
		}
		if !cipher.SshKey.PublicKey.IsZero() {
			sshKey.PublicKey, err = secrets.decryptFieldStr(cipher, cipher.SshKey.PublicKey)
			if err != nil {
				return fmt.Errorf("could not decrypt publicKey: %v", err)
			}
		}
		out.SshKey = sshKey
	}

	for _, f := range cipher.Fields {
		fName, err := secrets.decryptFieldStr(cipher, f.Name)
		if err != nil {
			return fmt.Errorf("could not decrypt field name: %v", err)
		}
		fVal, err := secrets.decryptFieldStr(cipher, f.Value)
		if err != nil {
			return fmt.Errorf("could not decrypt field value: %v", err)
		}
		out.Fields = append(out.Fields, jsonCipherField{Name: fName, Value: fVal})
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// resolveField decrypts a named field from a cipher, item-key aware.
func resolveField(cipher *Cipher, field string) (string, error) {
	switch field {
	case "password":
		if cipher.Login == nil {
			return "", nil
		}
		return secrets.decryptFieldStr(cipher, cipher.Login.Password)
	case "username":
		if cipher.Login == nil {
			return "", nil
		}
		return secrets.decryptFieldStr(cipher, cipher.Login.Username)
	case "notes":
		if cipher.Notes == nil {
			return "", nil
		}
		return secrets.decryptFieldStr(cipher, *cipher.Notes)
	case "totp":
		if cipher.Login == nil {
			return "", nil
		}
		return secrets.decryptFieldStr(cipher, cipher.Login.Totp)
	case "uri":
		if cipher.Login == nil {
			return "", nil
		}
		return secrets.decryptFieldStr(cipher, cipher.Login.URI)
	case "privatekey":
		if cipher.SshKey == nil {
			return "", nil
		}
		return secrets.decryptFieldStr(cipher, cipher.SshKey.PrivateKey)
	case "publickey":
		if cipher.SshKey == nil {
			return "", nil
		}
		return secrets.decryptFieldStr(cipher, cipher.SshKey.PublicKey)
	default:
		// Search custom fields by name.
		for _, f := range cipher.Fields {
			name, err := secrets.decryptFieldStr(cipher, f.Name)
			if err != nil {
				return "", fmt.Errorf("could not decrypt field name: %v", err)
			}
			if name == field {
				return secrets.decryptFieldStr(cipher, f.Value)
			}
		}
		return "", fmt.Errorf("field %q not found in cipher", field)
	}
}
