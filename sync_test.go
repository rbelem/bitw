// Copyright (c) 2019, Daniel Martí <mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	qt "github.com/frankban/quicktest"
)

// TestSync_RefreshesKDF verifies that sync() refreshes the KDF block in
// data.json by calling /accounts/prelogin after /sync. Without this, client
// credentials logins (Phase 3a prelogin-skip) leave a stale KDF in the cache,
// and decryption fails with "decrypt: MAC mismatch" (crypto.go:308) on every
// get after any vault re-key.
//
// This is the regression guard: if anyone re-introduces a prelogin skip in
// sync, this test fails — mirroring the "Auth-Email header must not be sent"
// assertion added in Phase 3b.
func TestSync_RefreshesKDF(t *testing.T) {
	var preloginCalled bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sync":
			json.NewEncoder(w).Encode(SyncData{
				Profile: Profile{Email: "test@example.com"},
			})
		case "/accounts/prelogin":
			preloginCalled = true
			json.NewEncoder(w).Encode(preLoginResponse{
				KDF:            1,
				KDFIterations:  600000,
				KDFMemory:      64,
				KDFParallelism: 4,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	oldApi, oldIdt := apiURL, idtURL
	apiURL, idtURL = server.URL, server.URL
	defer func() { apiURL, idtURL = oldApi, oldIdt }()

	globalData = dataFile{AccessToken: "tok"}
	secrets = secretCache{data: &globalData}

	c := qt.New(t)
	c.Assert(sync(context.Background()), qt.IsNil)
	c.Assert(preloginCalled, qt.IsTrue)
	c.Assert(globalData.KDF, qt.Equals, KDFTypeArgon2id)
	c.Assert(globalData.KDFIterations, qt.Equals, 600000)
	c.Assert(globalData.KDFMemory, qt.Equals, 64)
	c.Assert(globalData.KDFParallelism, qt.Equals, 4)
}

// TestSync_NoEmail_SkipsPrelogin verifies that an empty synced profile email
// does not break sync (e.g. for org-only accounts or pre-profile state). The
// KDF block is left untouched in this case — if it was zero, the next
// decryption will error clearly; if it was valid, decryption still works.
func TestSync_NoEmail_SkipsPrelogin(t *testing.T) {
	var preloginCalled bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sync":
			json.NewEncoder(w).Encode(SyncData{Profile: Profile{Email: ""}})
		case "/accounts/prelogin":
			preloginCalled = true
			json.NewEncoder(w).Encode(preLoginResponse{KDF: 0, KDFIterations: 100000})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	oldApi, oldIdt := apiURL, idtURL
	apiURL, idtURL = server.URL, server.URL
	defer func() { apiURL, idtURL = oldApi, oldIdt }()

	globalData = dataFile{AccessToken: "tok", KDFIterations: 100000}
	secrets = secretCache{data: &globalData}

	c := qt.New(t)
	c.Assert(sync(context.Background()), qt.IsNil)
	c.Assert(preloginCalled, qt.IsFalse)
	c.Assert(globalData.KDFIterations, qt.Equals, 100000)
}

// TestSync_PreloginFails_KDFCached_NonFatal verifies that when
// /accounts/prelogin errors out but a KDF is already cached in data.json,
// sync() returns nil (warning to stderr) instead of failing. This protects
// working users from transient identity-endpoint flakiness — refreshKDF
// (auth.go refreshKDF helper) takes the non-fatal branch at auth.go:53-55.
func TestSync_PreloginFails_KDFCached_NonFatal(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sync":
			json.NewEncoder(w).Encode(SyncData{Profile: Profile{Email: "test@example.com"}})
		case "/accounts/prelogin":
			http.Error(w, "boom", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	oldApi, oldIdt := apiURL, idtURL
	apiURL, idtURL = server.URL, server.URL
	defer func() { apiURL, idtURL = oldApi, oldIdt }()

	// KDF already cached — refreshKDF takes the non-fatal branch.
	globalData = dataFile{AccessToken: "tok", KDFIterations: 100000, KDFMemory: 16, KDFParallelism: 1}
	secrets = secretCache{data: &globalData}

	c := qt.New(t)
	c.Assert(sync(context.Background()), qt.IsNil)
	c.Assert(globalData.KDFIterations, qt.Equals, 100000)
	c.Assert(globalData.KDFMemory, qt.Equals, 16)
	c.Assert(globalData.KDFParallelism, qt.Equals, 1)
}
