# bitw

A simple BitWarden client. Requires Go 1.19 or later.

	go install github.com/rbelem/bitw@latest

The goal is a static and portable client which integrates well with one's
system. `bitw` is a CLI client — it does not expose a Secret Service
endpoint; for desktop integration, use a project that implements the
`org.freedesktop.secrets` D-Bus service such as
[kwalletd](https://invent.kde.org/frameworks/kwallet) or
[gnome-keyring](https://gitlab.gnome.org/GNOME/gnome-keyring).

**Note that this project isn't being actively developed right now, as I lack the time.**
I am happy to hand over the repository to whoever can maintain and develop the project,
with the only requirement that they make at least two non-trivial contributions first.

#### Quickstart

Log in and sync, providing a password when asked:

	export EMAIL=you@domain.com
	bitw sync

You can then view your secrets:

	bitw dump

Fetch individual values for shell scripts (shell-eval-safe output):

	# default mode: emits `export VAR='value'`
	eval "$(bitw get my-item --env-name MY_VAR)"

	# field mode: extract a single field
	password=$(bitw get my-item --field password)

Generate the current TOTP code for an account (login items with a TOTP
secret; accepts raw base32, otpauth:// and steam:// keys):

	bitw get totp my-item

Interactively pick a cipher with a fuzzy-finder (same flags apply to the
selection), or let `get` fuzzy-match a partial name:

	bitw get                 # interactive picker
	bitw get totp            # picker, then TOTP code
	bitw get gith            # fuzzy-matches "GitHub Token" (warns on stderr)

Note: fuzzy fallback auto-selects only for confident matches (a clean
prefix/substring-style match). Weak or ambiguous matches open the picker
so you confirm before any secret is printed — piping `2>/dev/null` away
the warning cannot leak another item's secret.

List stored ciphers without exposing secrets:

	bitw list                # name, username, type (TSV, sorted)
	bitw list --names-only   # bare names, for scripts

Shell tab completion for commands and cipher names (bash, zsh, fish). Run
`bitw list` once first — it writes the decrypted cipher names to
`$CONFIG_DIR/names` (0600), which the completion scripts read:

	eval "$(bitw completions bash)"     # add to your .bashrc

Note: the names file stores decrypted item names on disk (0600) so tab
completion works without a password prompt. Item names are not treated as
secrets; delete the file to disable name completion.

#### Releasing

Release versions are stamped in `version.go` and printed by `bitw --version`.
This is distinct from the wire-protocol `clientVersion` constant in `api.go`
(what Bitwarden servers see; tracks upstream bitwarden/clients).

To release a new version:

	./release.sh 0.1.2

The script bumps `version.go`, runs the test suite, commits, and pushes the
`v0.1.2` tag. Pushing a `v*` tag triggers the Release workflow
(`.github/workflows/release.yml`), which builds the platform binaries and
creates the GitHub release with generated notes. The script refuses to run on
a dirty tree or if `version.go` doesn't match the previous tag (releases must
be sequential); the very first release must be tagged manually.

#### Secrets Manager

Read-only support for Bitwarden Secrets Manager (machine accounts). Set
`SM_ACCESS_TOKEN` (the `0.<id>.<secret>:<key>` machine-account token; its
encryption key is only held in process memory):

	export SM_ACCESS_TOKEN=0.48c78342-....:B3h5D+YgLvFiQhWkIq6Bow==

	bitw sm list                # decrypted secret keys + projects (TSV)
	bitw sm get <key-or-id>     # print a secret's value

The access token is exchanged per run (no persistence) and the org/secret
keys are decrypted in memory with the existing AES-CBC-HMAC machinery.

Refresh a shell-sourceable cache of all configured secrets (replaces the
bash `secrets-refresh` loop):

	bitw cache --output ~/.cache/devbox-secrets.sh

Inspect current runtime state (token expiry, KDF, last sync, etc.):

	bitw status

#### Non-goals

These features are not planned at the moment:

* A graphical interface — use `vault.bitwarden.com`
* A D-Bus Secret Service endpoint — `bitw` is a CLI; use kwalletd /
  gnome-keyring for desktop integration
* Desktop autotype/autofill integration

#### Further reading

Talking to BitWarden:

* https://github.com/jcs/rubywarden/blob/master/API.md
* https://fossil.birl.ca/doc/trunk/docs/build/html/crypto.html

Fork-specific docs (the rbelem/bitw fork):

* `devbox.d/bitw/flake.nix` — per-commit rationale for the fork's
  pin to a specific upstream commit
* `docs/adr/0001`–`docs/adr/0005` in devbox-global — the architecture
  decisions (vault source-of-truth, libsecret fallback, ADR-0005 token-
  broker rejection)
