// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package l10ntest checks that a project's committed translation catalog
// matches the templates registered in code.
package l10ntest

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"maunium.net/go/mautrix/bridgev2/l10n"
)

// UpdateEnv is the environment variable that makes CheckCatalog rewrite the
// catalog file instead of failing when it's stale.
const UpdateEnv = "L10N_UPDATE"

type CatalogFile struct {
	Namespace string              `json:"namespace"`
	Messages  []l10n.CatalogEntry `json:"messages"`
}

// GenerateCatalog returns the catalog file contents for a namespace.
func GenerateCatalog(namespace string) ([]byte, error) {
	data, err := json.MarshalIndent(&CatalogFile{
		Namespace: namespace,
		Messages:  l10n.Catalog(namespace),
	}, "", "\t")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// CheckCatalog fails the test if the catalog file at path doesn't match the
// templates registered for the namespace. Run the test with L10N_UPDATE=1 to
// rewrite the file.
//
// The test must live in a package that (transitively) imports every package
// defining templates in the namespace, otherwise those templates are missing
// from the generated catalog.
func CheckCatalog(t *testing.T, path, namespace string) {
	t.Helper()
	expected, err := GenerateCatalog(namespace)
	if err != nil {
		t.Fatalf("failed to generate catalog: %v", err)
	}
	if os.Getenv(UpdateEnv) == "1" {
		if err = os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("failed to create catalog directory: %v", err)
		} else if err = os.WriteFile(path, expected, 0o644); err != nil {
			t.Fatalf("failed to write catalog: %v", err)
		}
		return
	}
	actual, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read catalog (run with %s=1 to create it): %v", UpdateEnv, err)
	}
	if !bytes.Equal(actual, expected) {
		t.Fatalf("%s is out of date, run the test with %s=1 to update it", path, UpdateEnv)
	}
}
