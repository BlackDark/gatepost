package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
)

const reloadDebounce = 300 * time.Millisecond

// watchConfig reloads when CONFIG_FILE (or its K8s ConfigMap symlink sibling)
// or any path under SECRET_WATCH_DIRS changes. Blocks until ctx is cancelled.
func watchConfig(ctx context.Context, configPath string, secretDirs []string, reload func()) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Printf("gatepost-extauthz: file watch disabled: %v", err)
		return
	}
	defer watcher.Close()

	add := func(path string) {
		if path == "" {
			return
		}
		if err := watcher.Add(path); err != nil {
			log.Printf("gatepost-extauthz: watch %s: %v", path, err)
		}
	}

	configPath = filepath.Clean(configPath)
	configDir := filepath.Dir(configPath)
	configBase := filepath.Base(configPath)
	add(configDir)
	add(configPath)

	secretRoots := make([]string, 0, len(secretDirs))
	for _, d := range secretDirs {
		d = filepath.Clean(d)
		secretRoots = append(secretRoots, d)
		add(d)
	}

	relevant := func(name string) bool {
		return watchEventRelevant(name, configPath, configDir, configBase, secretRoots)
	}

	var timer *time.Timer
	schedule := func() {
		if timer == nil {
			timer = time.AfterFunc(reloadDebounce, reload)
			return
		}
		timer.Reset(reloadDebounce)
	}

	for {
		select {
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return
		case ev, ok := <-watcher.Events:
			if !ok {
				return
			}
			if !relevant(ev.Name) {
				continue
			}
			if ev.Has(fsnotify.Write) || ev.Has(fsnotify.Create) || ev.Has(fsnotify.Rename) || ev.Has(fsnotify.Remove) || ev.Has(fsnotify.Chmod) {
				schedule()
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			log.Printf("gatepost-extauthz: watch error: %v", err)
		}
	}
}

func watchEventRelevant(name, configPath, configDir, configBase string, secretRoots []string) bool {
	name = filepath.Clean(name)
	base := filepath.Base(name)
	if name == configPath || (filepath.Dir(name) == configDir && base == configBase) {
		return true
	}
	// K8s ConfigMap/Secret atomic updates flip the ..data symlink in the mount dir.
	if filepath.Dir(name) == configDir && base == "..data" {
		return true
	}
	for _, root := range secretRoots {
		if name == root || strings.HasPrefix(name, root+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}

func watchSIGHUP(ctx context.Context, reload func()) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	defer signal.Stop(ch)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ch:
			reload()
		}
	}
}

func parseSecretWatchDirs(value string) []string {
	var dirs []string
	for _, e := range strings.Split(value, ",") {
		e = strings.TrimSpace(e)
		if e != "" {
			dirs = append(dirs, e)
		}
	}
	return dirs
}

func configFilePath() string {
	path := os.Getenv("CONFIG_FILE")
	if path == "" {
		return "config.yaml"
	}
	return path
}

func doReload(ctx context.Context, mu *sync.Mutex, r *hostRouter, path string, next http.Handler, factory handlerFactory) {
	mu.Lock()
	defer mu.Unlock()

	// The documented promise is "bad reload keeps the previous map". That promise has to hold
	// for a PANIC too, not only for a returned error: doReload runs on a time.AfterFunc
	// goroutine, and an unrecovered panic there terminates the whole process, taking down
	// every tenant of this multi-client server, not just the client whose config was bad.
	// (This was reachable with `sessionCookie: null`, which decoded to a nil pointer that
	// src.New dereferenced.) recover here turns any such future bug into a logged, ignored
	// reload; the previous map keeps serving because the swap only happens after a
	// successful buildHostMap.
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("gatepost-extauthz: reload panicked (keeping previous config): %v\n%s", rec, debug.Stack())
		}
	}()

	if err := reloadFromFile(ctx, r, path, next, factory); err != nil {
		log.Printf("gatepost-extauthz: reload failed (keeping previous config): %v", err)
		return
	}
	log.Printf("gatepost-extauthz: reloaded config from %s", path)
}
