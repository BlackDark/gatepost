package main

import (
	"path/filepath"
	"testing"
)

func TestWatchEventRelevant(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	secrets := filepath.Join(dir, "secrets")
	base := filepath.Base(cfg)

	if !watchEventRelevant(cfg, cfg, dir, base, nil) {
		t.Fatal("config file should be relevant")
	}
	if watchEventRelevant(filepath.Join(dir, "other.txt"), cfg, dir, base, nil) {
		t.Fatal("unrelated file in config dir should be ignored")
	}
	if !watchEventRelevant(filepath.Join(dir, "..data"), cfg, dir, base, nil) {
		t.Fatal("k8s ..data should be relevant")
	}
	if watchEventRelevant(filepath.Join(dir, "..bak"), cfg, dir, base, nil) {
		t.Fatal("unrelated .. prefix should be ignored")
	}
	if !watchEventRelevant(filepath.Join(secrets, "a", "client-secret"), cfg, dir, base, []string{secrets}) {
		t.Fatal("secret under watch dir should be relevant")
	}
	if watchEventRelevant(filepath.Join(dir, "noise.log"), cfg, dir, base, []string{secrets}) {
		t.Fatal("noise outside secrets should be ignored")
	}
}
