// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func cipherTypeLabel(t CipherType) string {
	switch t {
	case CipherLogin:
		return "login"
	case CipherNote:
		return "note"
	case CipherSshKey:
		return "ssh"
	default:
		return fmt.Sprintf("type-%d", int(t))
	}
}

// sanitizeName replaces control characters that would corrupt TSV output
// or the names file (tabs, newlines, carriage returns) with spaces.
func sanitizeName(s string) string {
	return strings.NewReplacer("\t", " ", "\n", " ", "\r", " ").Replace(s)
}

func cmdList(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	var namesOnly bool
	fs.BoolVar(&namesOnly, "names-only", false, "print only cipher names, one per line")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("usage: bitw list [--names-only]")
	}

	// Unlock vault.
	if _, err := secrets.password(); err != nil {
		return err
	}
	if err := secrets.initKeys(); err != nil {
		return err
	}

	type entry struct {
		name     string
		username string
		typeLbl  string
	}
	var entries []entry
	var names []string

	for i := range globalData.Sync.Ciphers {
		c := &globalData.Sync.Ciphers[i]
		name, err := secrets.decryptFieldStr(c, c.Name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not decrypt name of cipher %s: %v\n", c.ID, err)
			continue
		}
		var username string
		if c.Login != nil && !c.Login.Username.IsZero() {
			username, err = secrets.decryptFieldStr(c, c.Login.Username)
			if err != nil {
				username = ""
			}
		}
		// Sanitize control chars for TSV/names-file output.
		safeName := sanitizeName(name)
		safeUsername := sanitizeName(username)
		entries = append(entries, entry{
			name:     safeName,
			username: safeUsername,
			typeLbl:  cipherTypeLabel(c.Type),
		})
		names = append(names, safeName)
	}

	sort.Strings(names)

	// Write names index for shell completion (atomic write).
	if dir, err := resolveConfigDir(); err == nil {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not create config dir: %v\n", err)
		} else {
			content := ""
			if len(names) > 0 {
				content = strings.Join(names, "\n") + "\n"
			}
			namesPath := filepath.Join(dir, "names")
			tmp, err := os.CreateTemp(dir, ".names-*.tmp")
			if err != nil {
				fmt.Fprintf(os.Stderr, "warning: could not create temp file for names: %v\n", err)
			} else {
				tmpName := tmp.Name()
				cleanup := true
				defer func() {
					if cleanup {
						os.Remove(tmpName)
					}
				}()
				if _, err := tmp.WriteString(content); err != nil {
					tmp.Close()
					fmt.Fprintf(os.Stderr, "warning: could not write names file: %v\n", err)
				} else if err := tmp.Chmod(0o600); err != nil {
					tmp.Close()
					fmt.Fprintf(os.Stderr, "warning: could not chmod names file: %v\n", err)
				} else if err := tmp.Close(); err != nil {
					fmt.Fprintf(os.Stderr, "warning: could not close names file: %v\n", err)
				} else if err := os.Rename(tmpName, namesPath); err != nil {
					fmt.Fprintf(os.Stderr, "warning: could not rename names file: %v\n", err)
				} else {
					cleanup = false
				}
			}
		}
	} else {
		fmt.Fprintf(os.Stderr, "warning: could not resolve config dir: %v\n", err)
	}

	if namesOnly {
		for _, n := range names {
			fmt.Println(n)
		}
		return nil
	}

	// Sort entries by name for output.
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].name < entries[j].name
	})

	fmt.Println("name\tusername\ttype")
	for _, e := range entries {
		fmt.Printf("%s\t%s\t%s\n", e.name, e.username, e.typeLbl)
	}
	return nil
}
