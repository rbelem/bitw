// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"regexp"
	"strings"
	"testing"

	qt "github.com/frankban/quicktest"
)

// ---- test helpers ----------------------------------------------------

// setupVault installs a working vault (derived master key from the local
// fixture) and restores global state on cleanup. It configures secrets and
// EMAIL so the caller can encryptStr(...) afterwards, then assign
// globalData.Sync.Ciphers. Mirrors the pattern in cmdget_test.go.
func setupVault(t *testing.T) {
	t.Helper()
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
		data:      &dataFile{KDFIterations: 100000},
	}
	secrets.data.Sync.Profile.Email = localTestEmail
	secrets.data.Sync.Profile.Key.UnmarshalText([]byte(localTestKey2))
	if err := secrets.initKeys(); err != nil {
		t.Fatalf("initKeys: %v", err)
	}
	globalData = dataFile{Sync: SyncData{Ciphers: nil}}
}

// keySeq returns a readKeyFunc that yields the given keys then EOF.
func keySeq(keys ...pickerKey) func() (pickerKey, error) {
	i := 0
	return func() (pickerKey, error) {
		if i >= len(keys) {
			return pickerKey{}, io.EOF
		}
		k := keys[i]
		i++
		return k, nil
	}
}

// runes types a string into the picker.
func runes(s string) []pickerKey {
	keys := make([]pickerKey, 0, len(s))
	for _, r := range s {
		keys = append(keys, pickerKey{kind: kRune, r: r})
	}
	return keys
}

// wirePickerSeams wires the picker to a fake terminal: isTerminal reports
// isTerm, keys come from the injected sequence, raw-mode setup is a no-op, and
// render frames go to out (io.Discard for end-to-end cmdGet tests, or a buffer
// when a test needs to assert on what the picker drew).
func wirePickerSeams(t *testing.T, isTerm bool, out io.Writer, keys ...pickerKey) {
	t.Helper()
	oldTerm := isTerminalFunc
	oldRead := readKeyFunc
	oldSetup := pickerSetupFunc
	oldOut := pickerOut
	isTerminalFunc = func(int) bool { return isTerm }
	readKeyFunc = keySeq(keys...)
	pickerSetupFunc = func() (func(), error) { return func() {}, nil }
	pickerOut = out
	t.Cleanup(func() {
		isTerminalFunc = oldTerm
		readKeyFunc = oldRead
		pickerSetupFunc = oldSetup
		pickerOut = oldOut
	})
}

// overridePickerSeams is the common case: frames discarded (so they don't
// pollute captured stdout), isTerminal and keys injected.
func overridePickerSeams(t *testing.T, isTerm bool, keys ...pickerKey) {
	t.Helper()
	wirePickerSeams(t, isTerm, io.Discard, keys...)
}

// ---- model-level picker tests (no terminal, no rendering I/O) --------

// TestPicker_FilterNarrowing verifies that typing narrows the rows and that
// the selection resolves to the right item on Enter.
func TestPicker_FilterNarrowing(t *testing.T) {
	items := []pickerItem{
		{name: "GitHub"},
		{name: "GitLab"},
		{name: "Yahoo"},
	}
	m := &pickerModel{items: items}
	m.recompute()
	qt.Assert(t, len(m.rows), qt.Equals, 3)

	// "git" keeps GitHub + GitLab, drops Yahoo.
	for _, r := range "git" {
		m.handleKey(pickerKey{kind: kRune, r: r})
	}
	qt.Assert(t, len(m.rows), qt.Equals, 2)

	// "gith" narrows to GitHub only.
	m.handleKey(pickerKey{kind: kRune, r: 'h'})
	qt.Assert(t, len(m.rows), qt.Equals, 1)
	qt.Assert(t, m.rows[0].item.name, qt.Equals, "GitHub")

	// Enter selects it.
	qt.Assert(t, m.handleKey(pickerKey{kind: kEnter}), qt.Equals, actSelect)
}

// TestPicker_BackspaceAndCtrlU verifies filter editing.
func TestPicker_BackspaceAndCtrlU(t *testing.T) {
	items := []pickerItem{{name: "GitHub"}, {name: "Gmail"}}
	m := &pickerModel{items: items}
	m.recompute()

	for _, r := range "gi" {
		m.handleKey(pickerKey{kind: kRune, r: r})
	}
	qt.Assert(t, string(m.filter), qt.Equals, "gi")

	m.handleKey(pickerKey{kind: kBackspace})
	qt.Assert(t, string(m.filter), qt.Equals, "g")

	m.handleKey(pickerKey{kind: kCtrlU})
	qt.Assert(t, string(m.filter), qt.Equals, "")
	qt.Assert(t, len(m.rows), qt.Equals, 2)
}

// TestPicker_Navigation verifies Up/Down and Ctrl-N/Ctrl-P.
func TestPicker_Navigation(t *testing.T) {
	items := []pickerItem{{name: "alpha"}, {name: "beta"}, {name: "gamma"}}
	m := &pickerModel{items: items}
	m.recompute()
	qt.Assert(t, m.rows[m.selected].item.name, qt.Equals, "alpha")

	m.handleKey(pickerKey{kind: kDown})
	qt.Assert(t, m.rows[m.selected].item.name, qt.Equals, "beta")
	m.handleKey(pickerKey{kind: kCtrlN})
	qt.Assert(t, m.rows[m.selected].item.name, qt.Equals, "gamma")
	// Clamped at the bottom.
	m.handleKey(pickerKey{kind: kDown})
	qt.Assert(t, m.rows[m.selected].item.name, qt.Equals, "gamma")
	// Back up.
	m.handleKey(pickerKey{kind: kCtrlP})
	qt.Assert(t, m.rows[m.selected].item.name, qt.Equals, "beta")
	m.handleKey(pickerKey{kind: kUp})
	qt.Assert(t, m.rows[m.selected].item.name, qt.Equals, "alpha")
	// Clamped at the top.
	m.handleKey(pickerKey{kind: kUp})
	qt.Assert(t, m.rows[m.selected].item.name, qt.Equals, "alpha")
}

// ---- loop-level picker tests (injected keys, captured render) --------

// TestPickerLoop_Select returns the selected item.
func TestPickerLoop_Select(t *testing.T) {
	items := []pickerItem{
		{name: "GitHub"},
		{name: "GitLab"},
	}
	m := &pickerModel{items: items}
	m.recompute()
	var buf bytes.Buffer
	keys := append(runes("gith"), pickerKey{kind: kEnter})
	picked, err := runPickerLoop(m, &buf, keySeq(keys...), 80, 24)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, picked, qt.IsNotNil)
	qt.Assert(t, picked.name, qt.Equals, "GitHub")
}

// TestPickerLoop_Cancel verifies Esc cancels cleanly.
func TestPickerLoop_Cancel(t *testing.T) {
	items := []pickerItem{{name: "GitHub"}}
	m := &pickerModel{items: items}
	m.recompute()
	var buf bytes.Buffer
	picked, err := runPickerLoop(m, &buf, keySeq(pickerKey{kind: kEsc}), 80, 24)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, picked, qt.IsNil)
}

// TestPickerLoop_CtrlC verifies Ctrl-C cancels cleanly too.
func TestPickerLoop_CtrlC(t *testing.T) {
	items := []pickerItem{{name: "GitHub"}}
	m := &pickerModel{items: items}
	m.recompute()
	var buf bytes.Buffer
	picked, err := runPickerLoop(m, &buf, keySeq(pickerKey{kind: kCtrlC}), 80, 24)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, picked, qt.IsNil)
}

// TestPickerLoop_EmptyMatchesEnterError verifies that Enter with no matches is
// an error (the spec's "Enter on empty filter with no results → error").
func TestPickerLoop_EmptyMatchesEnterError(t *testing.T) {
	items := []pickerItem{{name: "GitHub"}}
	m := &pickerModel{items: items}
	m.recompute()
	var buf bytes.Buffer
	_, err := runPickerLoop(m, &buf, keySeq(runes("zzz")...), 80, 24)
	qt.Assert(t, err, qt.IsNil) // typed nothing after zzz yet

	m2 := &pickerModel{items: items}
	m2.recompute()
	_, err = runPickerLoop(m2, &buf,
		keySeq(append(runes("zzz"), pickerKey{kind: kEnter})...), 80, 24)
	qt.Assert(t, err, qt.ErrorMatches, "no matching cipher")
}

// ansiEscRe matches CSI escape sequences, used to strip styling when
// asserting on rendered text.
var ansiEscRe = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

// TestPickerRender_EmptyStateAndHighlight verifies the frame shows the empty
// state when there are no matches and the matched-char emphasis otherwise.
func TestPickerRender_EmptyStateAndHighlight(t *testing.T) {
	items := []pickerItem{
		{name: "GitHub", typ: CipherLogin},
		{name: "GitLab", typ: CipherLogin},
	}
	m := &pickerModel{items: items}
	m.recompute()

	// No matches: empty state text appears.
	var buf bytes.Buffer
	m.filter = []rune("zzz")
	m.recompute()
	renderPicker(&buf, m, 80, 24)
	qt.Assert(t, buf.String(), qt.Contains, "no matches")

	// Match: the selected row is reverse-video with bold emphasis on the
	// matched rune; a non-selected matched row shows bold-cyan emphasis.
	buf.Reset()
	m.filter = []rune("g")
	m.recompute()
	renderPicker(&buf, m, 80, 24)
	out := buf.String()
	// Emphasis splits words with SGR codes, so strip them before checking
	// the name text.
	qt.Assert(t, ansiEscRe.ReplaceAllString(out, ""), qt.Contains, "GitHub")
	qt.Assert(t, ansiEscRe.ReplaceAllString(out, ""), qt.Contains, "GitLab")
	qt.Assert(t, out, qt.Contains, "\x1b[1;36m",
		qt.Commentf("expected bold-cyan emphasis on non-selected row; got %q", out))
	qt.Assert(t, out, qt.Contains, "2/2") // hint line count
	qt.Assert(t, out, qt.Contains, "login")
}

// TestPickerRender_SelectedUsesReverseVideo verifies the selected row is
// reverse-video and the marker is present.
func TestPickerRender_SelectedUsesReverseVideo(t *testing.T) {
	items := []pickerItem{{name: "alpha"}, {name: "beta"}}
	m := &pickerModel{items: items}
	m.recompute()
	m.selected = 1
	var buf bytes.Buffer
	renderPicker(&buf, m, 80, 24)
	out := buf.String()
	qt.Assert(t, out, qt.Contains, "\x1b[7m", qt.Commentf("expected reverse video on selected row"))
	qt.Assert(t, out, qt.Contains, "▶")
}

// ---- cmdGet integration tests (picker seams overridden) -------------

// TestCmdGet_NoArgs_NonTerminal verifies that `bitw get` with no args and no
// terminal returns the usage error rather than hanging.
func TestCmdGet_NoArgs_NonTerminal(t *testing.T) {
	setupVault(t) // empty vault is fine; we never reach the picker
	overridePickerSeams(t, false /* non-terminal */)

	err := cmdGet(context.Background(), nil)
	qt.Assert(t, err, qt.ErrorMatches, "usage: bitw get.*")
}

// TestCmdGet_TotpBare_NonTerminal verifies the same for `bitw get totp`.
func TestCmdGet_TotpBare_NonTerminal(t *testing.T) {
	setupVault(t)
	overridePickerSeams(t, false)

	err := cmdGet(context.Background(), []string{"totp"})
	qt.Assert(t, err, qt.ErrorMatches, "usage: bitw get.*")
}

// TestCmdGet_Picker_GetBare verifies `bitw get` (interactive) opens the picker
// and emits the selected login's exports.
func TestCmdGet_Picker_GetBare(t *testing.T) {
	setupVault(t)
	globalData.Sync.Ciphers = []Cipher{{
		Type: CipherLogin,
		Name: encryptStr(t, "GitHub"),
		Login: &Login{
			Password: encryptStr(t, "supersecret"),
		},
	}}
	overridePickerSeams(t, true, pickerKey{kind: kEnter})

	stdout := captureStdout(t, func() {
		err := cmdGet(context.Background(), nil)
		qt.Assert(t, err, qt.IsNil)
	})
	qt.Assert(t, stdout, qt.Contains, "supersecret")
}

// TestCmdGet_Picker_Navigation verifies the picker honors Down before Enter,
// selecting the second cipher.
func TestCmdGet_Picker_Navigation(t *testing.T) {
	setupVault(t)
	globalData.Sync.Ciphers = []Cipher{
		{
			Type: CipherLogin,
			Name: encryptStr(t, "alpha"),
			Login: &Login{
				Password: encryptStr(t, "alpha-pw"),
			},
		},
		{
			Type: CipherLogin,
			Name: encryptStr(t, "beta"),
			Login: &Login{
				Password: encryptStr(t, "beta-pw"),
			},
		},
	}
	overridePickerSeams(t, true,
		pickerKey{kind: kDown},
		pickerKey{kind: kEnter},
	)

	stdout := captureStdout(t, func() {
		err := cmdGet(context.Background(), nil)
		qt.Assert(t, err, qt.IsNil)
	})
	qt.Assert(t, stdout, qt.Contains, "beta-pw")
	qt.Assert(t, stdout, qt.Not(qt.Contains), "alpha-pw")
}

// TestCmdGet_Picker_Cancel verifies that cancelling the picker is a clean
// no-op (nil error, no output).
func TestCmdGet_Picker_Cancel(t *testing.T) {
	setupVault(t)
	globalData.Sync.Ciphers = []Cipher{{
		Type: CipherLogin,
		Name: encryptStr(t, "GitHub"),
		Login: &Login{
			Password: encryptStr(t, "supersecret"),
		},
	}}
	overridePickerSeams(t, true, pickerKey{kind: kEsc})

	stdout := captureStdout(t, func() {
		err := cmdGet(context.Background(), nil)
		qt.Assert(t, err, qt.IsNil)
	})
	qt.Assert(t, stdout, qt.Equals, "")
}

// TestCmdGet_TotpBare_Picker verifies `bitw get totp` (interactive) opens the
// picker and emits a TOTP code for the selection.
func TestCmdGet_TotpBare_Picker(t *testing.T) {
	setupVault(t)
	globalData.Sync.Ciphers = []Cipher{{
		Type: CipherLogin,
		Name: encryptStr(t, "totptest"),
		Login: &Login{
			Totp: encryptStr(t, "JBSWY3DPEHPK3PXP"), // valid base32 secret
		},
	}}
	overridePickerSeams(t, true, pickerKey{kind: kEnter})

	stdout := captureStdout(t, func() {
		err := cmdGet(context.Background(), []string{"totp"})
		qt.Assert(t, err, qt.IsNil)
	})
	matched, _ := regexp.MatchString(`^\d{6}$`, strings.TrimSpace(stdout))
	qt.Assert(t, matched, qt.IsTrue, qt.Commentf("expected a 6-digit TOTP code; got %q", stdout))
}

// ---- fuzzy fallback tests -------------------------------------------

// TestCmdGet_FuzzyFallback_PartialName verifies that a partial name with no
// exact match falls back to the best fuzzy match, warns on stderr, and emits
// the selected cipher's data.
func TestCmdGet_FuzzyFallback_PartialName(t *testing.T) {
	setupVault(t)
	globalData.Sync.Ciphers = []Cipher{{
		Type: CipherLogin,
		Name: encryptStr(t, "GitHub"),
		Login: &Login{
			Password: encryptStr(t, "fuzzy-pw"),
		},
	}}

	stderr := captureStderr(t, func() {
		stdout := captureStdout(t, func() {
			err := cmdGet(context.Background(), []string{"git"})
			qt.Assert(t, err, qt.IsNil)
		})
		qt.Assert(t, stdout, qt.Contains, "fuzzy-pw")
	})
	qt.Assert(t, stderr, qt.Contains,
		`warning: no exact match for "git", using "GitHub"`)
}

// TestCmdGet_FuzzyFallback_GarbageName verifies that a name with no fuzzy
// match at all keeps the existing "not found" error.
func TestCmdGet_FuzzyFallback_GarbageName(t *testing.T) {
	setupVault(t)
	globalData.Sync.Ciphers = []Cipher{{
		Type: CipherLogin,
		Name: encryptStr(t, "GitHub"),
		Login: &Login{
			Password: encryptStr(t, "fuzzy-pw"),
		},
	}}

	err := cmdGet(context.Background(), []string{"zzzzzz-no-such-cipher"})
	qt.Assert(t, err, qt.ErrorMatches, `cipher "zzzzzz-no-such-cipher" not found`)
}

// TestCmdGet_FuzzyFallback_ExactMatchNoWarning verifies the warning is
// NOT emitted when the exact name is found (no regression for normal lookups).
func TestCmdGet_FuzzyFallback_ExactMatchNoWarning(t *testing.T) {
	setupVault(t)
	globalData.Sync.Ciphers = []Cipher{{
		Type: CipherLogin,
		Name: encryptStr(t, "GitHub"),
		Login: &Login{
			Password: encryptStr(t, "exact-pw"),
		},
	}}

	stderr := captureStderr(t, func() {
		// Discard stdout; we only care that no warning is emitted.
		oldStdout := os.Stdout
		_, w, _ := os.Pipe()
		os.Stdout = w
		err := cmdGet(context.Background(), []string{"GitHub"})
		w.Close()
		os.Stdout = oldStdout
		qt.Assert(t, err, qt.IsNil)
	})
	qt.Assert(t, stderr, qt.Not(qt.Contains), "warning: no exact match")
}

// ---- UTF-8 input (readKeyFromStdin byte decoding) -------------------

// stdinWith replaces os.Stdin with a pipe that yields data, then EOF. The
// write happens on a goroutine so the read side never blocks on a missing
// producer.
func stdinWith(t *testing.T, data []byte) {
	t.Helper()
	r, w, err := os.Pipe()
	qt.Assert(t, err, qt.IsNil)
	origStdin := os.Stdin
	os.Stdin = r
	t.Cleanup(func() {
		os.Stdin = origStdin
		r.Close()
	})
	go func() {
		w.Write(data)
		w.Close()
	}()
}

// TestReadKeyFromStdin_UTF8_Accented verifies a 2-byte UTF-8 codepoint ("é",
// 0xC3 0xA9) decodes to a single rune rather than two Latin-1 bytes.
func TestReadKeyFromStdin_UTF8_Accented(t *testing.T) {
	stdinWith(t, []byte("é"))
	k, err := readKeyFromStdin()
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, k.kind, qt.Equals, kRune)
	qt.Assert(t, k.r, qt.Equals, 'é')
}

// TestReadKeyFromStdin_UTF8_Emoji verifies a 4-byte UTF-8 codepoint (rocket,
// U+1F680) decodes to a single rune.
func TestReadKeyFromStdin_UTF8_Emoji(t *testing.T) {
	stdinWith(t, []byte("🚀"))
	k, err := readKeyFromStdin()
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, k.kind, qt.Equals, kRune)
	qt.Assert(t, k.r, qt.Equals, '🚀')
}

// TestReadKeyFromStdin_UTF8_StrayContinuationIgnored verifies a stray
// continuation byte (0x80, which cannot start a rune) is skipped and the next
// real key is returned — never corrupted into a garbage rune.
func TestReadKeyFromStdin_UTF8_StrayContinuationIgnored(t *testing.T) {
	stdinWith(t, []byte{0x80, 'a'})
	k, err := readKeyFromStdin()
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, k.kind, qt.Equals, kRune)
	qt.Assert(t, k.r, qt.Equals, 'a')
}

// TestReadKeyFromStdin_UTF8_TruncatedIgnored verifies a lead byte with no
// following continuation byte (EOF mid-codepoint) is dropped rather than
// producing a half rune.
func TestReadKeyFromStdin_UTF8_TruncatedIgnored(t *testing.T) {
	stdinWith(t, []byte{0xC3}) // lead byte for a 2-byte rune, no continuation
	_, err := readKeyFromStdin()
	qt.Assert(t, err, qt.Equals, io.EOF)
}

// TestReadKey_UTF8_FilterIntegration exercises the full byte→rune→filter→fuzzy
// path: piping "café\r" through the real readKeyFromStdin filters the list
// down to "Café au Lait" and selects it on Enter.
func TestReadKey_UTF8_FilterIntegration(t *testing.T) {
	items := []pickerItem{{name: "Café au Lait"}, {name: "GitHub"}}
	stdinWith(t, []byte("café\r"))
	oldRead := readKeyFunc
	readKeyFunc = readKeyFromStdin
	t.Cleanup(func() { readKeyFunc = oldRead })

	m := &pickerModel{items: items}
	m.recompute()
	var buf bytes.Buffer
	picked, err := runPickerLoop(m, &buf, readKeyFunc, 80, 24)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, picked, qt.IsNotNil)
	qt.Assert(t, picked.name, qt.Equals, "Café au Lait")
}

// ---- fuzzy fallback calibration & threshold -------------------------

// TestFuzzyFallback_Calibration anchors fuzzyFallbackFloor to the actual
// fuzzyScore values. If the scoring in fuzzy.go ever changes, this test
// forces a re-calibration of the floor constant. Measured scores:
//
//	"gith"→"GitHub Token" = 32 (strong, must auto-select)
//	"git" →"GitHub"       = 24 (strong, must auto-select)
//	"gi"  →"GitHub"       = 16 (strong)
//	"gth" →"GitHub"       = 14 (3-char one-gap, still above the floor)
//	"g"   →"GitHub"       = 8  (weak, below floor)
//	"gt"  →"GitHub"       = 6  (weak gappy, must NOT auto-select)
func TestFuzzyFallback_Calibration(t *testing.T) {
	cases := []struct {
		q, c   string
		want   int
		accept bool // whether this score should clear fuzzyFallbackFloor
	}{
		{"gith", "GitHub Token", 32, true},
		{"git", "GitHub", 24, true},
		{"gi", "GitHub", 16, true},
		{"gth", "GitHub", 14, true},
		{"g", "GitHub", 8, false},
		{"gt", "GitHub", 6, false},
	}
	// 1. Lock the exact scores produced by fuzzy.go.
	for _, tc := range cases {
		score, _ := fuzzyScore(tc.q, tc.c)
		qt.Assert(t, score, qt.Equals, tc.want,
			qt.Commentf("fuzzyScore(%q, %q)", tc.q, tc.c))
	}
	// 2. Lock the floor constant.
	qt.Assert(t, fuzzyFallbackFloor, qt.Equals, 10)
	// 3. Verify the floor cleanly separates the accept/reject cases — the
	//    safety property that no weak/ambiguous match can sneak through.
	for _, tc := range cases {
		score, _ := fuzzyScore(tc.q, tc.c)
		qt.Assert(t, score >= fuzzyFallbackFloor, qt.Equals, tc.accept,
			qt.Commentf("floor mis-classifies %q→%q (score %d, floor %d, want accept=%v)",
				tc.q, tc.c, score, fuzzyFallbackFloor, tc.accept))
	}
}

// TestAutoSelectCandidate covers the threshold + ambiguity decision directly.
func TestAutoSelectCandidate(t *testing.T) {
	mk := func(name string, score int) rankedMatch {
		return rankedMatch{name: name, score: score}
	}
	// Empty → nil.
	qt.Assert(t, autoSelectCandidate(nil), qt.IsNil)
	qt.Assert(t, autoSelectCandidate([]rankedMatch{}), qt.IsNil)
	// One weak match → nil.
	qt.Assert(t, autoSelectCandidate([]rankedMatch{mk("GitHub", 6)}), qt.IsNil)
	// One strong match → it.
	got := autoSelectCandidate([]rankedMatch{mk("GitHub", 32)})
	qt.Assert(t, got, qt.IsNotNil)
	qt.Assert(t, got.name, qt.Equals, "GitHub")
	// Two strong matches tied → nil (ambiguous).
	qt.Assert(t, autoSelectCandidate([]rankedMatch{
		mk("abc", 16), mk("abd", 16),
	}), qt.IsNil)
	// Clear winner over a weaker second → winner.
	got = autoSelectCandidate([]rankedMatch{
		mk("GitHub", 32), mk("GitLab", 24),
	})
	qt.Assert(t, got, qt.IsNotNil)
	qt.Assert(t, got.name, qt.Equals, "GitHub")
	// Winner above floor, second below floor → winner (not ambiguous).
	got = autoSelectCandidate([]rankedMatch{
		mk("GitHub", 32), mk("Other", 6),
	})
	qt.Assert(t, got, qt.IsNotNil)
	qt.Assert(t, got.name, qt.Equals, "GitHub")
}

// TestCmdGet_FuzzyFallback_StrongMatch_Selects verifies a strong match (above
// the floor, unambiguous) still auto-selects with the stderr warning. Uses
// "gith"→"GitHub Token" (score 32), the calibration's headline case.
func TestCmdGet_FuzzyFallback_StrongMatch_Selects(t *testing.T) {
	setupVault(t)
	globalData.Sync.Ciphers = []Cipher{{
		Type: CipherLogin,
		Name: encryptStr(t, "GitHub Token"),
		Login: &Login{
			Password: encryptStr(t, "strong-pw"),
		},
	}}

	stderr := captureStderr(t, func() {
		stdout := captureStdout(t, func() {
			err := cmdGet(context.Background(), []string{"gith"})
			qt.Assert(t, err, qt.IsNil)
		})
		qt.Assert(t, stdout, qt.Contains, "strong-pw")
	})
	qt.Assert(t, stderr, qt.Contains,
		`warning: no exact match for "gith", using "GitHub Token"`)
}

// TestCmdGet_FuzzyFallback_WeakMatch_NonTerminal verifies a weak gappy match
// ("gt"→"GitHub", score 6) is NOT auto-selected when non-interactive, keeping
// the original "not found" error.
func TestCmdGet_FuzzyFallback_WeakMatch_NonTerminal(t *testing.T) {
	setupVault(t)
	globalData.Sync.Ciphers = []Cipher{{
		Type:  CipherLogin,
		Name:  encryptStr(t, "GitHub"),
		Login: &Login{Password: encryptStr(t, "secret")},
	}}

	err := cmdGet(context.Background(), []string{"gt"})
	qt.Assert(t, err, qt.ErrorMatches, `cipher "gt" not found`)
}

// TestCmdGet_FuzzyFallback_WeakMatch_Terminal_PickerSeeded verifies that a
// weak match in an interactive session opens the picker with the query
// pre-typed, and that cancelling leaves no output (exit 0).
func TestCmdGet_FuzzyFallback_WeakMatch_Terminal_PickerSeeded(t *testing.T) {
	setupVault(t)
	globalData.Sync.Ciphers = []Cipher{{
		Type:  CipherLogin,
		Name:  encryptStr(t, "GitHub"),
		Login: &Login{Password: encryptStr(t, "secret")},
	}}

	var render bytes.Buffer
	wirePickerSeams(t, true /* interactive */, &render, pickerKey{kind: kEsc})

	stdout := captureStdout(t, func() {
		err := cmdGet(context.Background(), []string{"gt"})
		qt.Assert(t, err, qt.IsNil) // cancel → silent exit 0
	})
	// The picker was opened with the query pre-seeded and the candidate shown.
	frame := ansiEscRe.ReplaceAllString(render.String(), "")
	qt.Assert(t, frame, qt.Contains, "gt", qt.Commentf("filter should be seeded with the query; frame: %q", render.String()))
	qt.Assert(t, frame, qt.Contains, "GitHub", qt.Commentf("candidate should be visible; frame: %q", render.String()))
	// Cancel must not leak any secret.
	qt.Assert(t, stdout, qt.Not(qt.Contains), "secret")
	qt.Assert(t, stdout, qt.Equals, "")
}

// TestCmdGet_FuzzyFallback_AmbiguousTie_NonTerminal verifies that two equally
// good matches (a tie) are NOT auto-selected when non-interactive.
func TestCmdGet_FuzzyFallback_AmbiguousTie_NonTerminal(t *testing.T) {
	setupVault(t)
	globalData.Sync.Ciphers = []Cipher{
		{Type: CipherLogin, Name: encryptStr(t, "abc"), Login: &Login{Password: encryptStr(t, "pw-a")}},
		{Type: CipherLogin, Name: encryptStr(t, "abd"), Login: &Login{Password: encryptStr(t, "pw-b")}},
	}

	err := cmdGet(context.Background(), []string{"ab"})
	qt.Assert(t, err, qt.ErrorMatches, `cipher "ab" not found`)
}

// TestCmdGet_FuzzyFallback_AmbiguousTie_Terminal_Picker verifies that a tie in
// an interactive session opens the picker (with both candidates) for the user
// to disambiguate.
func TestCmdGet_FuzzyFallback_AmbiguousTie_Terminal_Picker(t *testing.T) {
	setupVault(t)
	globalData.Sync.Ciphers = []Cipher{
		{Type: CipherLogin, Name: encryptStr(t, "abc"), Login: &Login{Password: encryptStr(t, "pw-a")}},
		{Type: CipherLogin, Name: encryptStr(t, "abd"), Login: &Login{Password: encryptStr(t, "pw-b")}},
	}

	var render bytes.Buffer
	wirePickerSeams(t, true, &render, pickerKey{kind: kEsc})

	stdout := captureStdout(t, func() {
		err := cmdGet(context.Background(), []string{"ab"})
		qt.Assert(t, err, qt.IsNil)
	})
	frame := ansiEscRe.ReplaceAllString(render.String(), "")
	qt.Assert(t, frame, qt.Contains, "abc")
	qt.Assert(t, frame, qt.Contains, "abd")
	qt.Assert(t, stdout, qt.Equals, "")
}

// TestCmdGet_FuzzyFallback_TypoFieldPassword_NeverLeaks is the critical
// regression: a typo'd name passed to `--field password` must NEVER auto-print
// another cipher's password. With the old "fuzzyBest always picks" behavior
// this would have leaked "leaked-pw"; now the weak match falls through to
// "not found" with empty stdout.
func TestCmdGet_FuzzyFallback_TypoFieldPassword_NeverLeaks(t *testing.T) {
	setupVault(t)
	globalData.Sync.Ciphers = []Cipher{{
		Type:  CipherLogin,
		Name:  encryptStr(t, "GitHub"),
		Login: &Login{Password: encryptStr(t, "leaked-pw")},
	}}

	stdout := captureStdout(t, func() {
		err := cmdGet(context.Background(), []string{"--field", "password", "gt"})
		qt.Assert(t, err, qt.ErrorMatches, `cipher "gt" not found`)
	})
	qt.Assert(t, stdout, qt.Equals, "",
		qt.Commentf("a typo'd --field password query must not print anything; got %q", stdout))
	qt.Assert(t, stdout, qt.Not(qt.Contains), "leaked-pw")
}
