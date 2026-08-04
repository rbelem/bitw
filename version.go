// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

// version is the bitw release version, printed by `bitw --version` and
// bumped by release.sh. It is intentionally NOT the wire-protocol
// Bitwarden-Client-Version header sent to BW servers — that lives
// separately in api.go as clientVersion and tracks the upstream
// bitwarden/clients CLI (see the comment there).
var version = "0.1.1"
