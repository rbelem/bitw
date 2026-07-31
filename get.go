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
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: bitw get [--env-name NAME] [--json] [--field FIELD] <cipher-name>")
	}
	cipherName := fs.Arg(0)

	// Unlock vault.
	if _, err := secrets.password(); err != nil {
		return err
	}
	if err := secrets.initKeys(); err != nil {
		return err
	}

	cipher, err := findCipherByName(cipherName)
	if err != nil {
		return err
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
	case CipherNote:
		return emitNoteExport(cipher, envName)
	case CipherSshKey:
		return emitNoteExport(cipher, envName)
	default:
		return fmt.Errorf("cipher %q has unsupported type %d", cipherName, cipher.Type)
	}
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
		return cipher.Login.Totp, nil
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
