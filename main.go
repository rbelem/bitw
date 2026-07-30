// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/kenshaw/ini"
	"golang.org/x/term"
)

var flagSet = flag.NewFlagSet("bitw", flag.ContinueOnError)

func init() { flagSet.Usage = usage }

func usage() {
	fmt.Fprint(os.Stderr, `
Usage of bitw:

	bitw [command]

Commands:

	help    show a command's help text
	sync    fetch the latest data from the server
	login   force a new login, even if not necessary
	dump    list all the stored login secrets
	get     retrieve a cipher's fields (shell-eval or bare output)
	cache   decrypt ciphers into a shell-sourceable env file
	create  create a new Login cipher in the personal vault
	serve   start the org.freedesktop.secrets D-Bus service
	config  print the current configuration
	`[1:])
	flagSet.PrintDefaults()
}

func main() { os.Exit(main1(os.Stderr)) }

func main1(stderr io.Writer) int {
	if err := flagSet.Parse(os.Args[1:]); err != nil {
		return 2
	}
	args := flagSet.Args()
	if err := run(args...); err != nil {
		switch err {
		case context.Canceled:
			return 0
		case flag.ErrHelp:
			return 2
		}
		// errCacheFailed: summary already printed to stderr, exit 1 without printing.
		if errors.Is(err, errCacheFailed) {
			return 1
		}
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	return 0
}

// These can be overriden by the config.
var (
	apiURL = "https://api.bitwarden.com"
	idtURL = "https://identity.bitwarden.com"
)

// readLine is similar to term.ReadPassword, but it doesn't use key codes.
func readLine(prompt string) ([]byte, error) {
	fmt.Fprintf(os.Stderr, "%s: ", prompt)
	defer fmt.Fprintln(os.Stderr)

	var buf [1]byte
	var line []byte
	for {
		n, err := os.Stdin.Read(buf[:])
		if n > 0 {
			switch buf[0] {
			case '\n', '\r':
				return line, nil
			default:
				line = append(line, buf[0])
			}
		} else if err != nil {
			if err == io.EOF && len(line) > 0 {
				return line, nil
			}
			return nil, err
		}
	}
}

// termPasswordPrompt reads a password from the terminal using term.ReadPassword.
// This is the lowest-level prompt fallback when no GUI/SSH_ASKPASS tool is available.
func termPasswordPrompt(prompt string) ([]byte, error) {
	// TODO: Support cancellation with ^C. Currently not possible in any
	// simple way. Closing os.Stdin on cancel doesn't seem to do the trick
	// either. Simply doing an os.Exit keeps the terminal broken because of
	// ReadPassword.

	fd := int(os.Stdin.Fd())
	switch {
	case term.IsTerminal(fd):
		fmt.Fprintf(os.Stderr, "%s: ", prompt)
		password, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err == nil && len(password) == 0 {
			err = io.ErrUnexpectedEOF
		}
		return password, err
	case os.Getenv("FORCE_STDIN_PROMPTS") == "true":
		return readLine(prompt)
	default:
		return nil, fmt.Errorf("need a terminal to prompt for a password")
	}
}

// promptWithAskpass tries GUI/SSH_ASKPASS programs before falling back to terminal.
// Mirrors devbox-global/bin/secrets-setup's prompt_password helper.
func promptWithAskpass(prompt string) ([]byte, error) {
	// 1. zenity (GTK dialog — works on KDE too)
	if path, _ := exec.LookPath("zenity"); path != "" {
		out, err := exec.Command(path, "--password", "--title="+prompt).Output()
		if err == nil {
			return bytes.TrimSpace(out), nil
		}
	}
	// 2. kdialog (KDE)
	if path, _ := exec.LookPath("kdialog"); path != "" {
		out, err := exec.Command(path, "--password", prompt).Output()
		if err == nil {
			return bytes.TrimSpace(out), nil
		}
	}
	// 3. SSH_ASKPASS (program specified by env var; typical for non-TTY)
	if askpass := os.Getenv("SSH_ASKPASS"); askpass != "" {
		if _, err := exec.LookPath(askpass); err == nil {
			display := os.Getenv("DISPLAY")
			if display == "" {
				display = ":0"
			}
			cmd := exec.Command(askpass, prompt)
			cmd.Env = append(os.Environ(), "DISPLAY="+display)
			out, err := cmd.Output()
			if err == nil {
				return bytes.TrimSpace(out), nil
			}
			// Fall through to terminal on SSH_ASKPASS failure
			fmt.Fprintf(os.Stderr, "warning: SSH_ASKPASS=%s failed: %v\n", askpass, err)
		}
	}
	// 4. Terminal fallback (existing /dev/tty logic)
	return termPasswordPrompt(prompt)
}

func passwordPrompt(prompt string) ([]byte, error) {
	out, err := promptWithAskpass(prompt)
	if err != nil {
		return nil, fmt.Errorf("could not obtain %s: %w", prompt, err)
	}
	return out, nil
}

var (
	config     *ini.File
	globalData dataFile

	saveData bool

	secrets secretCache
)

func init() { secrets.data = &globalData }

type dataFile struct {
	path string

	DeviceID       string
	AccessToken    string
	RefreshToken   string
	TokenExpiry    time.Time
	KDF            KDFType
	KDFIterations  int
	KDFMemory      int
	KDFParallelism int

	LastSync time.Time
	Sync     SyncData
}

func loadDataFile(path string) error {
	globalData.path = path
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	defer f.Close()
	if err := json.NewDecoder(f).Decode(&globalData); err != nil {
		return err
	}
	return nil
}

func (f *dataFile) Save() error {
	bs, err := json.MarshalIndent(f, "", "\t")
	if err != nil {
		return err
	}
	bs = append(bs, '\n')
	if err := os.MkdirAll(filepath.Dir(f.path), 0o755); err != nil {
		return err
	}
	return ioutil.WriteFile(f.path, bs, 0o600)
}

func run(args ...string) (err error) {
	if len(args) == 0 {
		flagSet.Usage()
		return flag.ErrHelp
	}
	switch args[0] {
	case "help":
		// TODO: per-command help
		flagSet.Usage()
		return flag.ErrHelp
	}
	dir := os.Getenv("CONFIG_DIR")
	if dir == "" {
		if dir, err = os.UserConfigDir(); err != nil {
			return err
		}
		dir = filepath.Join(dir, "bitw")
	}
	config, err = ini.LoadFile(filepath.Join(dir, "config"))
	if err != nil {
		return err
	}
	for _, section := range config.AllSections() {
		if section.Name() != "" {
			return fmt.Errorf("sections are not used in config files yet")
		}
		for _, key := range section.Keys() {
			// note that these are lowercased
			switch key {
			case "email":
				secrets._configEmail = section.Get(key)
			case "apiurl":
				apiURL = section.Get(key)
			case "identityurl":
				idtURL = section.Get(key)
			default:
				return fmt.Errorf("unknown config key: %q", key)
			}
		}
	}

	dataPath := filepath.Join(dir, "data.json")
	if err := loadDataFile(dataPath); err != nil {
		return fmt.Errorf("could not load %s: %v", dataPath, err)
	}

	if args[0] == "config" {
		fmt.Printf("email       = %q\n", secrets.email())
		fmt.Printf("apiURL      = %q\n", apiURL)
		fmt.Printf("identityURL = %q\n", idtURL)
		return nil
	}

	defer func() {
		if !saveData {
			return
		}
		if err1 := globalData.Save(); err == nil {
			err = err1
		}
	}()

	if globalData.DeviceID == "" {
		globalData.DeviceID = uuid.New().String()
		saveData = true
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	// If stdin is a terminal, ensure we reset its state before exiting.
	stdinFD := int(os.Stdin.Fd())
	stdinOldState, _ := term.GetState(stdinFD)

	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)

	go func() {
		<-c
		cancel()

		// If we still haven't exited after 200ms,
		// we're probably stuck reading a password.
		// Unfortunately, term.ReadPassword can't be cancelled right now.
		//
		// The least we can do is restore the terminal to its original state,
		// and exit the entire program.
		// TODO: probably revisit this at some point.
		time.Sleep(200 * time.Millisecond)
		if stdinOldState != nil { // if nil, stdin is not a terminal
			_ = term.Restore(stdinFD, stdinOldState)
		}
		fmt.Println()
		os.Exit(0)
	}()

	ctx = context.WithValue(ctx, authToken{}, globalData.AccessToken)
	switch args[0] {
	case "login":
		if err := login(ctx); err != nil {
			return err
		}
	case "sync":
		if err := ensureToken(ctx); err != nil {
			return err
		}
		if err := sync(ctx); err != nil {
			return err
		}
	case "dump":
		// Make sure we have the password before printing anything.
		if _, err := secrets.password(); err != nil {
			return err
		}

		// Split the ciphers into categories, for printing.
		// Don't use text/tabwriter, as deciphering hundreds can be slow.
		// TODO: print non-login ciphers too, such as cards.
		// TODO: use encoding/csv instead.
		var logins []*Cipher
		for i := range globalData.Sync.Ciphers {
			cipher := &globalData.Sync.Ciphers[i]
			if cipher.Login != nil {
				logins = append(logins, cipher)
			}
		}
		fmt.Println("# Logins:")
		fmt.Println("name\turi\tusername\tpassword")
		for _, cipher := range logins {
			if ctx.Err() != nil {
				break // cancelled
			}
			for i, cipherStr := range [...]CipherString{
				cipher.Name,
				cipher.Login.URI,
				cipher.Login.Username,
				cipher.Login.Password,
			} {
				if cipherStr.IsZero() {
					continue
				}

				var s []byte
				var err error

				s, err = secrets.decrypt(cipherStr, cipher.OrganizationID)

				if err != nil {
					return err
				}
				if i > 0 && len(s) > 0 {
					fmt.Printf("\t")
				}
				fmt.Printf("%s", s)
			}
			fmt.Println()
		}
	case "get":
		if err := cmdGet(ctx, args[1:]); err != nil {
			return err
		}
	case "cache":
		if err := cmdCache(ctx, args[1:]); err != nil {
			return err
		}
	case "create":
		if err := cmdCreate(ctx, args[1:]); err != nil {
			return err
		}
	case "serve":
		if err := serveDBus(ctx); err != nil {
			return err
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %q\n", args[0])
		flagSet.Usage()
		return flag.ErrHelp
	}
	return nil
}

func ensureToken(ctx context.Context) error {
	// Fast path: a cached access token that is not yet expired is still
	// usable. This matters for client_credentials grants, where the server
	// does not return a refresh token (public API docs) and the only way
	// to obtain a fresh access token is to re-authenticate. Skipping the
	// re-auth here lets `bitw sync` succeed immediately after a successful
	// `bitw login`, even when the cached RefreshToken is empty.
	if globalData.AccessToken != "" && time.Now().Before(globalData.TokenExpiry) {
		return nil
	}
	if globalData.RefreshToken == "" {
		if err := login(ctx); err != nil {
			return err
		}
	} else if time.Now().After(globalData.TokenExpiry) {
		if err := refreshToken(ctx); err != nil {
			return err
		}
	}
	return nil
}
