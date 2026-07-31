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
