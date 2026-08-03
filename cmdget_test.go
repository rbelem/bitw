// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"context"
	"os"
	"testing"

	qt "github.com/frankban/quicktest"
)

// TestCmdGet_FieldMode_AllFields verifies that cmdGet in field mode correctly
// resolves all built-in fields (password, username, uri, totp, notes).
func TestCmdGet_FieldMode_AllFields(t *testing.T) {
	origSecrets := secrets
	origGlobalData := globalData
	origEmail := os.Getenv("EMAIL")
	t.Cleanup(func() {
		secrets = origSecrets
		globalData = origGlobalData
		os.Setenv("EMAIL", origEmail)
	})

	os.Setenv("EMAIL", localTestEmail)
	secrets = secretCache{
		_password: []byte(localTestPassword),
		data: &dataFile{
			KDFIterations: 100000,
		},
	}
	secrets.data.Sync.Profile.Email = localTestEmail
	secrets.data.Sync.Profile.Key.UnmarshalText([]byte(localTestKey2))
	secrets.initKeys()

	notes := encryptStr(t, "test notes")
	cipher := Cipher{
		Type: CipherLogin,
		Name: encryptStr(t, "Test Cipher"),
		Login: &Login{
			Username: encryptStr(t, "testuser"),
			Password: encryptStr(t, "testpass"),
			URI:      encryptStr(t, "https://example.com"),
			Totp:     encryptStr(t, "123456"),
		},
		Notes: &notes,
	}
	globalData = dataFile{
		Sync: SyncData{
			Ciphers: []Cipher{cipher},
		},
	}

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := cmdGet(context.Background(), []string{
		"--field", "password",
		"--field", "username",
		"--field", "uri",
		"--field", "totp",
		"--field", "notes",
		"Test Cipher",
	})
	w.Close()
	os.Stdout = oldStdout

	qt.Assert(t, err, qt.IsNil)

	var buf [4096]byte
	n, _ := r.Read(buf[:])
	output := string(buf[:n])
	qt.Assert(t, output, qt.Contains, "testpass")
	qt.Assert(t, output, qt.Contains, "testuser")
	qt.Assert(t, output, qt.Contains, "https://example.com")
	qt.Assert(t, output, qt.Contains, "123456")
	qt.Assert(t, output, qt.Contains, "test notes")
}

// TestCmdGet_FieldMode_CustomField verifies that cmdGet in field mode correctly
// resolves custom fields by name.
func TestCmdGet_FieldMode_CustomField(t *testing.T) {
	origSecrets := secrets
	origGlobalData := globalData
	origEmail := os.Getenv("EMAIL")
	t.Cleanup(func() {
		secrets = origSecrets
		globalData = origGlobalData
		os.Setenv("EMAIL", origEmail)
	})

	os.Setenv("EMAIL", localTestEmail)
	secrets = secretCache{
		_password: []byte(localTestPassword),
		data: &dataFile{
			KDFIterations: 100000,
		},
	}
	secrets.data.Sync.Profile.Email = localTestEmail
	secrets.data.Sync.Profile.Key.UnmarshalText([]byte(localTestKey2))
	secrets.initKeys()

	cipher := Cipher{
		Type: CipherLogin,
		Name: encryptStr(t, "Test Cipher"),
		Login: &Login{
			Password: encryptStr(t, "testpass"),
		},
		Fields: []Field{
			{
				Name:  encryptStr(t, "CUSTOM_FIELD"),
				Value: encryptStr(t, "custom-value"),
			},
		},
	}
	globalData = dataFile{
		Sync: SyncData{
			Ciphers: []Cipher{cipher},
		},
	}

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := cmdGet(context.Background(), []string{"--field", "CUSTOM_FIELD", "Test Cipher"})
	w.Close()
	os.Stdout = oldStdout

	qt.Assert(t, err, qt.IsNil)

	var buf [1024]byte
	n, _ := r.Read(buf[:])
	output := string(buf[:n])
	qt.Assert(t, output, qt.Contains, "custom-value")
}

// TestCmdGet_FieldMode_EmptyValueSkipped verifies that cmdGet in field mode
// skips empty values (line 84-86).
func TestCmdGet_FieldMode_EmptyValueSkipped(t *testing.T) {
	origSecrets := secrets
	origGlobalData := globalData
	origEmail := os.Getenv("EMAIL")
	t.Cleanup(func() {
		secrets = origSecrets
		globalData = origGlobalData
		os.Setenv("EMAIL", origEmail)
	})

	os.Setenv("EMAIL", localTestEmail)
	secrets = secretCache{
		_password: []byte(localTestPassword),
		data: &dataFile{
			KDFIterations: 100000,
		},
	}
	secrets.data.Sync.Profile.Email = localTestEmail
	secrets.data.Sync.Profile.Key.UnmarshalText([]byte(localTestKey2))
	secrets.initKeys()

	cipher := Cipher{
		Type: CipherLogin,
		Name: encryptStr(t, "Test Cipher"),
		Login: &Login{
			Password: encryptStr(t, ""), // Empty password
			Totp:     encryptStr(t, ""), // Empty totp
		},
	}
	globalData = dataFile{
		Sync: SyncData{
			Ciphers: []Cipher{cipher},
		},
	}

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := cmdGet(context.Background(), []string{"--field", "password", "--field", "totp", "Test Cipher"})
	w.Close()
	os.Stdout = oldStdout

	qt.Assert(t, err, qt.IsNil)

	var buf [1024]byte
	n, _ := r.Read(buf[:])
	output := string(buf[:n])
	// Empty values should be skipped, so output should be empty
	qt.Assert(t, output, qt.Equals, "")
}

// TestCmdGet_DefaultMode_InvalidEnvName verifies that cmdGet in default mode
// warns when --env-name is not a valid shell identifier (line 101-103).
func TestCmdGet_DefaultMode_InvalidEnvName(t *testing.T) {
	origSecrets := secrets
	origGlobalData := globalData
	origEmail := os.Getenv("EMAIL")
	t.Cleanup(func() {
		secrets = origSecrets
		globalData = origGlobalData
		os.Setenv("EMAIL", origEmail)
	})

	os.Setenv("EMAIL", localTestEmail)
	secrets = secretCache{
		_password: []byte(localTestPassword),
		data: &dataFile{
			KDFIterations: 100000,
		},
	}
	secrets.data.Sync.Profile.Email = localTestEmail
	secrets.data.Sync.Profile.Key.UnmarshalText([]byte(localTestKey2))
	secrets.initKeys()

	cipher := Cipher{
		Type: CipherLogin,
		Name: encryptStr(t, "Test Cipher"),
		Login: &Login{
			Password: encryptStr(t, "testpass"),
		},
	}
	globalData = dataFile{
		Sync: SyncData{
			Ciphers: []Cipher{cipher},
		},
	}

	stderr := captureStderr(t, func() {
		// Capture stdout
		oldStdout := os.Stdout
		_, w, _ := os.Pipe()
		os.Stdout = w

		err := cmdGet(context.Background(), []string{"--env-name", "invalid-name", "Test Cipher"})
		w.Close()
		os.Stdout = oldStdout

		qt.Assert(t, err, qt.IsNil)
	})

	qt.Assert(t, stderr, qt.Contains, "warning: skipping invalid shell identifier")
}

// TestCmdGet_DefaultMode_InvalidFieldName verifies that cmdGet in default mode
// warns when a custom field name is not a valid shell identifier (line 112-114).
func TestCmdGet_DefaultMode_InvalidFieldName(t *testing.T) {
	origSecrets := secrets
	origGlobalData := globalData
	origEmail := os.Getenv("EMAIL")
	t.Cleanup(func() {
		secrets = origSecrets
		globalData = origGlobalData
		os.Setenv("EMAIL", origEmail)
	})

	os.Setenv("EMAIL", localTestEmail)
	secrets = secretCache{
		_password: []byte(localTestPassword),
		data: &dataFile{
			KDFIterations: 100000,
		},
	}
	secrets.data.Sync.Profile.Email = localTestEmail
	secrets.data.Sync.Profile.Key.UnmarshalText([]byte(localTestKey2))
	secrets.initKeys()

	cipher := Cipher{
		Type: CipherLogin,
		Name: encryptStr(t, "Test Cipher"),
		Login: &Login{
			Password: encryptStr(t, "testpass"),
		},
		Fields: []Field{
			{
				Name:  encryptStr(t, "invalid-field-name"),
				Value: encryptStr(t, "value"),
			},
		},
	}
	globalData = dataFile{
		Sync: SyncData{
			Ciphers: []Cipher{cipher},
		},
	}

	stderr := captureStderr(t, func() {
		// Capture stdout
		oldStdout := os.Stdout
		_, w, _ := os.Pipe()
		os.Stdout = w

		err := cmdGet(context.Background(), []string{"Test Cipher"})
		w.Close()
		os.Stdout = oldStdout

		qt.Assert(t, err, qt.IsNil)
	})

	qt.Assert(t, stderr, qt.Contains, "warning: skipping field with invalid shell identifier")
}

// TestCmdGet_DefaultMode_EmptyFieldValueSkipped verifies that cmdGet in default
// mode skips custom fields with empty/whitespace-only values (line 120-122).
func TestCmdGet_DefaultMode_EmptyFieldValueSkipped(t *testing.T) {
	origSecrets := secrets
	origGlobalData := globalData
	origEmail := os.Getenv("EMAIL")
	t.Cleanup(func() {
		secrets = origSecrets
		globalData = origGlobalData
		os.Setenv("EMAIL", origEmail)
	})

	os.Setenv("EMAIL", localTestEmail)
	secrets = secretCache{
		_password: []byte(localTestPassword),
		data: &dataFile{
			KDFIterations: 100000,
		},
	}
	secrets.data.Sync.Profile.Email = localTestEmail
	secrets.data.Sync.Profile.Key.UnmarshalText([]byte(localTestKey2))
	secrets.initKeys()

	cipher := Cipher{
		Type: CipherLogin,
		Name: encryptStr(t, "Test Cipher"),
		Login: &Login{
			Password: encryptStr(t, "testpass"),
		},
		Fields: []Field{
			{
				Name:  encryptStr(t, "EMPTY_FIELD"),
				Value: encryptStr(t, "   "), // Whitespace only
			},
		},
	}
	globalData = dataFile{
		Sync: SyncData{
			Ciphers: []Cipher{cipher},
		},
	}

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := cmdGet(context.Background(), []string{"Test Cipher"})
	w.Close()
	os.Stdout = oldStdout

	qt.Assert(t, err, qt.IsNil)

	var buf [4096]byte
	n, _ := r.Read(buf[:])
	output := string(buf[:n])
	// Should contain password export but not EMPTY_FIELD
	qt.Assert(t, output, qt.Contains, "LOGIN_PASSWORD")
	qt.Assert(t, output, qt.Not(qt.Contains), "EMPTY_FIELD")
}

// TestCmdGet_UsageError verifies that cmdGet returns a usage error when no
// cipher name is provided.
func TestCmdGet_UsageError(t *testing.T) {
	origSecrets := secrets
	origEmail := os.Getenv("EMAIL")
	t.Cleanup(func() {
		secrets = origSecrets
		os.Setenv("EMAIL", origEmail)
	})

	os.Setenv("EMAIL", localTestEmail)
	secrets = secretCache{
		_password: []byte(localTestPassword),
		data: &dataFile{
			KDFIterations: 100000,
		},
	}

	err := cmdGet(context.Background(), []string{})
	qt.Assert(t, err, qt.ErrorMatches, "usage: bitw get.*")
}

// TestCmdGet_ParseError verifies that cmdGet returns an error when flag parsing fails.
func TestCmdGet_ParseError(t *testing.T) {
	origSecrets := secrets
	origEmail := os.Getenv("EMAIL")
	t.Cleanup(func() {
		secrets = origSecrets
		os.Setenv("EMAIL", origEmail)
	})

	os.Setenv("EMAIL", localTestEmail)
	secrets = secretCache{
		_password: []byte(localTestPassword),
		data: &dataFile{
			KDFIterations: 100000,
		},
	}

	err := cmdGet(context.Background(), []string{"--invalid-flag"})
	qt.Assert(t, err, qt.IsNotNil)
}

// TestResolveField_NotesNil verifies that resolveField returns "" when
// cipher.Notes is nil.
func TestResolveField_NotesNil(t *testing.T) {
	origSecrets := secrets
	origEmail := os.Getenv("EMAIL")
	t.Cleanup(func() {
		secrets = origSecrets
		os.Setenv("EMAIL", origEmail)
	})

	os.Setenv("EMAIL", localTestEmail)
	secrets = secretCache{
		_password: []byte(localTestPassword),
		data: &dataFile{
			KDFIterations: 100000,
		},
	}
	secrets.data.Sync.Profile.Email = localTestEmail
	secrets.data.Sync.Profile.Key.UnmarshalText([]byte(localTestKey2))
	secrets.initKeys()

	cipher := &Cipher{
		Login: &Login{},
		Notes: nil,
	}

	val, err := resolveField(cipher, "notes")
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, val, qt.Equals, "")
}

// TestResolveField_CustomFieldNotFound verifies that resolveField returns an
// error when a custom field is not found.
func TestResolveField_CustomFieldNotFound(t *testing.T) {
	origSecrets := secrets
	origEmail := os.Getenv("EMAIL")
	t.Cleanup(func() {
		secrets = origSecrets
		os.Setenv("EMAIL", origEmail)
	})

	os.Setenv("EMAIL", localTestEmail)
	secrets = secretCache{
		_password: []byte(localTestPassword),
		data: &dataFile{
			KDFIterations: 100000,
		},
	}
	secrets.data.Sync.Profile.Email = localTestEmail
	secrets.data.Sync.Profile.Key.UnmarshalText([]byte(localTestKey2))
	secrets.initKeys()

	cipher := &Cipher{
		Login:  &Login{},
		Fields: []Field{},
	}

	_, err := resolveField(cipher, "nonexistent")
	qt.Assert(t, err, qt.ErrorMatches, "field .* not found.*")
}
