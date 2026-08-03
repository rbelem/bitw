// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// steamTotpChars is the alphabet used by Steam's TOTP variant.
const steamTotpChars = "23456789BCDFGHJKMNPQRTVWXY"

// totpHotp computes an RFC 4226 HOTP value as a zero-padded decimal string.
func totpHotp(key []byte, counter uint64, digits int) string {
	h := hmac.New(sha1.New, key)
	binary.Write(h, binary.BigEndian, counter)
	sum := h.Sum(nil)
	// Dynamic truncation per RFC 4226 §5.3.
	v := binary.BigEndian.Uint32(sum[sum[len(sum)-1]&0x0F:]) & 0x7FFFFFFF
	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, v%mod)
}

// totpCode computes an RFC 6238 TOTP code for the given time. Bitwarden (and
// most services) use a 30-second period, 6 digits and SHA-1.
func totpCode(key []byte, t time.Time) string {
	return totpHotp(key, uint64(t.Unix())/30, 6)
}

// steamCode computes a Steam guard code for the given time. Matches Steam's
// own algorithm (as implemented by node-steam-totp and Steam Desktop
// Authenticator): dynamic truncation to a single 31-bit integer, then five
// divmod steps over the Steam alphabet.
func steamCode(key []byte, t time.Time) string {
	h := hmac.New(sha1.New, key)
	binary.Write(h, binary.BigEndian, uint64(t.Unix())/30)
	sum := h.Sum(nil)
	v := binary.BigEndian.Uint32(sum[sum[len(sum)-1]&0x0F:]) & 0x7FFFFFFF
	code := make([]byte, 5)
	for i := range code {
		code[i] = steamTotpChars[v%uint32(len(steamTotpChars))]
		v /= uint32(len(steamTotpChars))
	}
	return string(code)
}

// totpSecret extracts the raw secret from a Bitwarden TOTP key: an otpauth://
// URL, a steam:// URL, or a bare base32 string.
func totpSecret(raw string) ([]byte, error) {
	key := strings.TrimSpace(raw)
	switch {
	case strings.HasPrefix(key, "otpauth://"):
		u, err := url.Parse(key)
		if err != nil {
			return nil, fmt.Errorf("invalid otpauth URI: %v", err)
		}
		key = u.Query().Get("secret")
		if key == "" {
			return nil, fmt.Errorf("otpauth URI has no secret parameter")
		}
	case strings.HasPrefix(key, "steam://"):
		key = strings.TrimPrefix(key, "steam://")
	}
	// Normalize: strip whitespace, uppercase, pad to a multiple of 8.
	key = strings.ToUpper(strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, key))
	key += strings.Repeat("=", -len(key)&7)
	secret, err := base32.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, fmt.Errorf("invalid TOTP secret: %v", err)
	}
	return secret, nil
}

// currentTotp generates the current TOTP code for a Bitwarden TOTP key.
func currentTotp(raw string, now time.Time) (string, error) {
	raw = strings.TrimSpace(raw)
	key, err := totpSecret(raw)
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(raw, "steam://") {
		return steamCode(key, now), nil
	}
	return totpCode(key, now), nil
}

// emitTotp generates and prints the current TOTP code for a login cipher.
func emitTotp(cipher *Cipher, name string) error {
	if cipher.Login == nil || cipher.Login.Totp.IsZero() {
		return fmt.Errorf("cipher %q has no TOTP secret", name)
	}
	secret, err := secrets.decryptFieldStr(cipher, cipher.Login.Totp)
	if err != nil {
		return fmt.Errorf("could not decrypt TOTP secret for %q: %v", name, err)
	}
	code, err := currentTotp(secret, time.Now())
	if err != nil {
		return fmt.Errorf("could not generate TOTP code for %q: %v", name, err)
	}
	fmt.Println(code)
	return nil
}
