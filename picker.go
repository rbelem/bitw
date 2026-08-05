// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/term"
)

// pickerKeyKind identifies a decoded key press in the picker.
type pickerKeyKind int

const (
	kRune pickerKeyKind = iota
	kUp
	kDown
	kEnter
	kBackspace
	kEsc
	kCtrlN
	kCtrlP
	kCtrlC
	kCtrlU
)

// pickerKey is a decoded key event. For kRune, r holds the character.
type pickerKey struct {
	kind pickerKeyKind
	r    rune
}

// Overridable seams so the picker can be driven hermetically in tests
// (same pattern as isTerminalFunc / readLineFunc in main.go and auth.go).
var (
	// readKeyFunc reads and decodes one key event from raw stdin.
	readKeyFunc func() (pickerKey, error) = readKeyFromStdin

	// pickerSetupFunc puts the terminal into raw mode + alternate screen and
	// returns a restore func. Tests swap this for a no-op.
	pickerSetupFunc = enterRawAlt

	// pickerOut is where the picker renders its frames (os.Stdout in prod,
	// io.Discard when testing the surrounding cmdGet flow).
	pickerOut io.Writer = os.Stdout
)

// pickerItem is one selectable row: a decrypted name plus the cipher it
// belongs to, its type (for the badge), and (for logins) its username,
// which is shown after the name and included in fuzzy matching.
type pickerItem struct {
	cipher   *Cipher
	name     string
	username string
	typ      CipherType
}

// matchText returns the text fuzzy matching and display run against: the
// cipher name, plus the username (for logins) so both are searchable.
func (it *pickerItem) matchText() string {
	if it.username == "" {
		return it.name
	}
	return it.name + " " + it.username
}

// pickerRow is a ranked match row kept alongside its originating item so the
// picker never loses the cipher pointer (duplicate names are possible).
type pickerRow struct {
	item  *pickerItem
	score int
	spans []int // byte offsets in item.name to highlight
}

// typeBadge returns a short, subtle label for a cipher type.
func typeBadge(t CipherType) string {
	switch t {
	case CipherLogin:
		return "login"
	case CipherNote:
		return "note"
	case CipherCard:
		return "card"
	case CipherIdentity:
		return "id"
	case CipherSshKey:
		return "ssh"
	default:
		return "?"
	}
}

// pickerAction is the result of applying a key to the model.
type pickerAction int

const (
	actContinue pickerAction = iota
	actSelect
	actCancel
)

// pickerModel holds the picker's mutable state.
type pickerModel struct {
	items    []pickerItem
	rows     []pickerRow // current filtered + ranked view
	filter   []rune
	selected int
	top      int // first visible row index (scrolling)
}

// recompute rebuilds m.rows for the current filter and clamps the selection.
func (m *pickerModel) recompute() {
	q := string(m.filter)
	m.rows = m.rows[:0]
	if q == "" {
		for i := range m.items {
			m.rows = append(m.rows, pickerRow{item: &m.items[i]})
		}
	} else {
		for i := range m.items {
			score, spans := fuzzyScore(q, m.items[i].matchText())
			if score > 0 {
				m.rows = append(m.rows, pickerRow{item: &m.items[i], score: score, spans: spans})
			}
		}
		sort.SliceStable(m.rows, func(a, b int) bool {
			if m.rows[a].score != m.rows[b].score {
				return m.rows[a].score > m.rows[b].score
			}
			return m.rows[a].item.name < m.rows[b].item.name
		})
	}
	if m.selected >= len(m.rows) {
		m.selected = len(m.rows) - 1
	}
	if m.selected < 0 {
		m.selected = 0
	}
}

// handleKey applies one decoded key to the model and returns the resulting
// action. It never touches the terminal, so it is trivially testable.
func (m *pickerModel) handleKey(k pickerKey) pickerAction {
	switch k.kind {
	case kRune:
		m.filter = append(m.filter, k.r)
		m.recompute()
	case kBackspace:
		if len(m.filter) > 0 {
			m.filter = m.filter[:len(m.filter)-1]
			m.recompute()
		}
	case kCtrlU:
		m.filter = m.filter[:0]
		m.recompute()
	case kUp, kCtrlP:
		if m.selected > 0 {
			m.selected--
		}
	case kDown, kCtrlN:
		if m.selected < len(m.rows)-1 {
			m.selected++
		}
	case kEnter:
		return actSelect
	case kEsc, kCtrlC:
		return actCancel
	}
	return actContinue
}

// runPickerLoop drives the model with readKey, rendering each frame to out.
// It performs NO terminal setup — production wrapping (raw mode + alt screen)
// lives in pickCipher; tests call this directly with a bytes.Buffer and an
// injected key source. Returns the picked item (or nil on cancel/EOF).
func runPickerLoop(m *pickerModel, out io.Writer, readKey func() (pickerKey, error), width, height int) (*pickerItem, error) {
	for {
		renderPicker(out, m, width, height)
		k, err := readKey()
		if err != nil {
			// EOF or read error → treat as cancel so we never spin.
			return nil, nil
		}
		switch m.handleKey(k) {
		case actSelect:
			if len(m.rows) == 0 {
				return nil, fmt.Errorf("no matching cipher")
			}
			return m.rows[m.selected].item, nil
		case actCancel:
			return nil, nil
		}
	}
}

// pickCipher runs the interactive picker over items and returns the selected
// item, or (nil, nil) if the user cancelled. initialFilter seeds the filter
// input (used by the fuzzy-fallback path to pre-fill the user's query so they
// can confirm a weak/ambiguous match). Terminal setup/teardown is deferred so
// Ctrl-C / Esc / EOF all leave the shell usable.
func pickCipher(items []pickerItem, initialFilter string) (*pickerItem, error) {
	restore, err := pickerSetupFunc()
	if err != nil {
		return nil, err
	}
	defer restore()
	w, h := termSize()
	m := &pickerModel{items: items, filter: []rune(initialFilter)}
	m.recompute()
	return runPickerLoop(m, pickerOut, readKeyFunc, w, h)
}

// ---- rendering --------------------------------------------------------

// dim wraps s in faint SGR. Uses 22 (not full reset) to turn it off so it can
// be nested inside other styles without clobbering them.
func dim(s string) string { return "\x1b[2m" + s + "\x1b[22m" }

// truncateName caps a name to max display runes with an ellipsis.
func truncateName(s string, max int) string {
	if max < 4 {
		max = 4
	}
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	return string([]rune(s)[:max-1]) + "…"
}

// styledName emphasizes the matched chars (by byte offset) within name.
// emphasized chars get on/off; the function never emits a full reset, so it is
// safe to embed inside a wider styled run (e.g. reverse-video selection).
func styledName(name string, spans []int, selected bool) string {
	mark := make(map[int]bool, len(spans))
	for _, s := range spans {
		mark[s] = true
	}
	on, off := "\x1b[1;36m", "\x1b[39;22m" // bold cyan / default fg + normal
	if selected {
		on, off = "\x1b[1m", "\x1b[22m" // within reverse video, just bold
	}
	var b strings.Builder
	cur := false
	byteOff := 0
	for _, r := range name {
		want := mark[byteOff]
		if want && !cur {
			b.WriteString(on)
			cur = true
		} else if !want && cur {
			b.WriteString(off)
			cur = false
		}
		b.WriteRune(r)
		byteOff += utf8.RuneLen(r)
	}
	if cur {
		b.WriteString(off)
	}
	return b.String()
}

// pickerUserMax caps how many runes of a login username are shown dimmed
// after the cipher name; the name's share of the row width shrinks to fit it.
const pickerUserMax = 24

// spansInRange keeps byte-offset spans that fall inside [lo, hi), shifted
// down by lo. Used to slice fuzzy spans (which are offsets into the full
// "name username" match text) down to a single display segment.
func spansInRange(spans []int, lo, hi int) []int {
	var out []int
	for _, s := range spans {
		if s >= lo && s < hi {
			out = append(out, s-lo)
		}
	}
	return out
}

// renderRowLine builds a single visible row (no trailing newline).
func renderRowLine(row pickerRow, selected bool, width int) string {
	marker := "  "
	if selected {
		marker = "▶ "
	}
	badge := typeBadge(row.item.typ)
	if w := utf8.RuneCountInString(badge); w < 5 {
		badge += strings.Repeat(" ", 5-w)
	}
	nameMax := width - 2 - 5 - 1 - 1
	username := row.item.username
	if username != "" {
		nameMax -= 1 + pickerUserMax
		if nameMax < 4 {
			// Terminal too narrow for both name and username: drop the
			// username and give the name the full row width.
			username = ""
			nameMax = width - 2 - 5 - 1 - 1
		}
	}
	name := truncateName(row.item.name, nameMax)
	nameSpans := spansInRange(row.spans, 0, len(name))
	body := marker + "\x1b[2m" + badge + "\x1b[22m " + styledName(name, nameSpans, selected)
	if username != "" {
		usr := truncateName(username, pickerUserMax)
		// Spans are byte offsets into "name username"; shift the ones that
		// land in the username into its coordinate space.
		usrSpans := spansInRange(row.spans, len(row.item.name)+1, len(row.item.name)+1+len(usr))
		if len(usrSpans) > 0 {
			// A matched username is rendered with the same emphasis as the
			// name (dim would conflict with the emphasis's intensity codes).
			body += " " + styledName(usr, usrSpans, selected)
		} else {
			body += " " + dim(usr)
		}
	}
	if selected {
		return "\x1b[7m" + body + "\x1b[0m\x1b[K"
	}
	return body + "\x1b[0m\x1b[K"
}

// renderPicker draws one full frame to out: title, input, hint, then a
// scrollable window of rows. It homes the cursor and clears to end-of-screen
// so stale frames don't ghost.
func renderPicker(out io.Writer, m *pickerModel, width, height int) {
	const header = 3 // title + input + hint
	visible := height - header
	if visible < 1 {
		visible = 1
	}
	// Keep the selection in view.
	if m.selected < m.top {
		m.top = m.selected
	}
	if m.selected > m.top+visible-1 {
		m.top = m.selected - visible + 1
	}
	if m.top < 0 {
		m.top = 0
	}

	lines := make([]string, 0, header+visible)
	lines = append(lines, dim(" bitw — fuzzy find")+"\x1b[K")
	lines = append(lines, "\x1b[1m>\x1b[22m "+string(m.filter)+"\x1b[7m \x1b[0m\x1b[K")
	lines = append(lines, dim(fmt.Sprintf(" %d/%d  ↑↓ move  Ctrl-N/P move  Ctrl-U clear  Enter select  Esc cancel",
		len(m.rows), len(m.items)))+"\x1b[K")

	if len(m.rows) == 0 {
		msg := "  no matches"
		if len(m.items) == 0 {
			msg = "  vault is empty — nothing to get"
		}
		lines = append(lines, dim(msg)+"\x1b[K")
		for i := 1; i < visible; i++ {
			lines = append(lines, "\x1b[K")
		}
	} else {
		last := m.top + visible
		if last > len(m.rows) {
			last = len(m.rows)
		}
		drawn := 0
		for i := m.top; i < last; i++ {
			lines = append(lines, renderRowLine(m.rows[i], i == m.selected, width))
			drawn++
		}
		for ; drawn < visible; drawn++ {
			lines = append(lines, "\x1b[K")
		}
	}
	if len(lines) > height {
		lines = lines[:height]
	}
	frame := "\x1b[H" + strings.Join(lines, "\r\n") + "\x1b[0J"
	fmt.Fprint(out, frame)
}

// ---- terminal setup --------------------------------------------------

// enterRawAlt switches stdin to raw mode and stdout to the alternate screen
// (hiding the cursor). The returned restore func undoes both.
func enterRawAlt() (func(), error) {
	fd := int(os.Stdin.Fd())
	old, err := term.MakeRaw(fd)
	if err != nil {
		return nil, fmt.Errorf("could not enter raw mode: %w", err)
	}
	fmt.Fprint(pickerOut, "\x1b[?1049h\x1b[?25l") // enter alt screen, hide cursor
	return func() {
		fmt.Fprint(pickerOut, "\x1b[?25h\x1b[?1049l") // show cursor, leave alt screen
		term.Restore(fd, old)
	}, nil
}

// termSize reports the terminal size, falling back to 80×24.
func termSize() (width, height int) {
	width, height = 80, 24
	fd := int(os.Stdin.Fd())
	if w, h, err := term.GetSize(fd); err == nil && w > 0 && h > 0 {
		width, height = w, h
	}
	return
}

// ---- key decoding (production only) ----------------------------------

// escTimeout bounds how long we wait for the trailing bytes of a potential
// escape sequence before deciding a lone 0x1b is just Esc.
const escTimeout = 50 * time.Millisecond

// readKeyFromStdin reads raw bytes from stdin and decodes one key event.
// Ctrl-C arrives as byte 0x03 because raw mode clears ISIG, so we handle it
// in-process (restoring the terminal via pickCipher's defer) rather than
// relying on SIGINT.
func readKeyFromStdin() (pickerKey, error) {
	var buf [1]byte
	if _, err := os.Stdin.Read(buf[:]); err != nil {
		return pickerKey{}, err
	}
	switch b := buf[0]; {
	case b == 0x1b:
		// Possible escape sequence (arrow keys send ESC [ A/B). Peek for the
		// rest with a short timeout; if nothing follows, it's a bare Esc.
		if final, ok := readEscSeq(); ok {
			switch final {
			case 'A':
				return pickerKey{kind: kUp}, nil
			case 'B':
				return pickerKey{kind: kDown}, nil
			}
		}
		return pickerKey{kind: kEsc}, nil
	case b == '\r' || b == '\n':
		return pickerKey{kind: kEnter}, nil
	case b == 0x7f || b == 0x08:
		return pickerKey{kind: kBackspace}, nil
	case b == 0x03:
		return pickerKey{kind: kCtrlC}, nil
	case b == 0x0e:
		return pickerKey{kind: kCtrlN}, nil
	case b == 0x10:
		return pickerKey{kind: kCtrlP}, nil
	case b == 0x15:
		return pickerKey{kind: kCtrlU}, nil
	case b < 0x20:
		// Any other control char: ignore and read the next key.
		return readKeyFromStdin()
	default:
		// Byte ≥ 0x80: a UTF-8 lead byte (continuation bytes are 0x80–0xBF
		// and never start a rune). Frame the full codepoint, decode it, and
		// ignore truncated/invalid sequences so they can't corrupt the
		// filter (typing "é" must become one rune, not two Latin-1 bytes).
		n := utf8LeadLen(b)
		if n == 0 {
			return readKeyFromStdin() // stray continuation byte
		}
		full := make([]byte, 0, n)
		full = append(full, b)
		for len(full) < n {
			var c [1]byte
			if _, err := os.Stdin.Read(c[:]); err != nil {
				return readKeyFromStdin() // truncated multi-byte sequence
			}
			if c[0]&0xC0 != 0x80 {
				return readKeyFromStdin() // expected a continuation byte
			}
			full = append(full, c[0])
		}
		r, size := utf8.DecodeRune(full)
		if size != len(full) {
			return readKeyFromStdin() // overlong/invalid encoding
		}
		return pickerKey{kind: kRune, r: r}, nil
	}
}

// utf8LeadLen returns the expected total byte length of a UTF-8 codepoint
// whose lead byte is b: 1 for ASCII, 2–4 for a valid lead byte, 0 for a
// continuation byte, -1 for an invalid byte.
func utf8LeadLen(b byte) int {
	switch {
	case b < 0x80:
		return 1
	case b < 0xC0:
		return 0 // continuation byte, not a lead
	case b < 0xE0:
		return 2
	case b < 0xF0:
		return 3
	case b < 0xF8:
		return 4
	default:
		return -1
	}
}

// readEscSeq tries to read the "[A"/"[B" tail of an arrow-key escape sequence.
// The goroutine is only leaked in the bare-Esc case, which cancels the picker
// (and exits the read loop), so there is no subsequent reader to race with.
func readEscSeq() (final byte, ok bool) {
	type result struct {
		final byte
		ok    bool
	}
	ch := make(chan result, 1)
	go func() {
		var buf [2]byte
		if _, err := os.Stdin.Read(buf[:1]); err != nil || (buf[0] != '[' && buf[0] != 'O') {
			ch <- result{}
			return
		}
		if _, err := os.Stdin.Read(buf[1:2]); err != nil {
			ch <- result{}
			return
		}
		ch <- result{final: buf[1], ok: true}
	}()
	select {
	case r := <-ch:
		return r.final, r.ok
	case <-time.After(escTimeout):
		return 0, false
	}
}
