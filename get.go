// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"context"
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

func findCipherByName(name string) (*Cipher, error) {
	for i := range globalData.Sync.Ciphers {
		cipher := &globalData.Sync.Ciphers[i]
		if cipher.Login == nil {
			continue
		}
		decName, err := secrets.decryptStr(cipher.Name, cipher.OrganizationID)
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
	var fields stringSliceFlag
	fs.StringVar(&envName, "env-name", "", "variable name for password in default mode")
	fs.Var(&fields, "field", "field to emit (repeatable); triggers field mode")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: bitw get [--env-name NAME] [--field FIELD] <cipher-name>")
	}
	cipherName := fs.Arg(0)

	// Unlock vault.
	if _, err := secrets.password(); err != nil {
		return err
	}

	cipher, err := findCipherByName(cipherName)
	if err != nil {
		return err
	}
	if cipher.Login == nil {
		return fmt.Errorf("cipher %q is not a login", cipherName)
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

	// Default mode: emit shell-eval export lines.
	password, err := secrets.decryptStr(cipher.Login.Password, cipher.OrganizationID)
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
		name, err := secrets.decryptStr(field.Name, cipher.OrganizationID)
		if err != nil {
			return fmt.Errorf("could not decrypt field name: %v", err)
		}
		if !isValidShellIdent(name) {
			fmt.Fprintf(os.Stderr, "warning: skipping field with invalid shell identifier %q\n", name)
			continue
		}
		val, err := secrets.decryptStr(field.Value, cipher.OrganizationID)
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

func resolveField(cipher *Cipher, field string) (string, error) {
	orgID := cipher.OrganizationID
	switch field {
	case "password":
		return secrets.decryptStr(cipher.Login.Password, orgID)
	case "username":
		return secrets.decryptStr(cipher.Login.Username, orgID)
	case "notes":
		if cipher.Notes == nil {
			return "", nil
		}
		return secrets.decryptStr(*cipher.Notes, orgID)
	case "totp":
		return cipher.Login.Totp, nil
	case "uri":
		return secrets.decryptStr(cipher.Login.URI, orgID)
	default:
		// Search custom fields by name.
		for _, f := range cipher.Fields {
			name, err := secrets.decryptStr(f.Name, orgID)
			if err != nil {
				return "", fmt.Errorf("could not decrypt field name: %v", err)
			}
			if name == field {
				return secrets.decryptStr(f.Value, orgID)
			}
		}
		return "", fmt.Errorf("field %q not found in cipher", field)
	}
}
