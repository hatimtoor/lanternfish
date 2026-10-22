// Command lanternfish-gui is the standalone desktop build of Lanternfish. Built with
// -ldflags "-H windowsgui", it launches with no console: a single native
// window (WebView2) plus the intercepting proxy on 127.0.0.1:8080. Logs go to a file in
// the config directory. For the full CLI use the `lanternfish` binary.
package main

import (
	"log"
	"os"
	"path/filepath"
	"runtime"

	"lanternfish/internal/app"
)

func main() {
	runtime.LockOSThread() // the native window owns the main OS thread

	dir := configDir()
	_ = os.MkdirAll(dir, 0o700)

	var logger *log.Logger
	if f, err := os.OpenFile(filepath.Join(dir, "lanternfish-gui.log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644); err == nil {
		logger = log.New(f, "[lanternfish] ", log.LstdFlags)
		defer f.Close()
	} else {
		logger = log.New(os.Stderr, "[lanternfish] ", 0)
	}

	if err := app.RunGUI(app.Options{ProxyAddr: "127.0.0.1:8080", ConfigDir: dir}, logger); err != nil {
		logger.Fatalf("gui: %v", err)
	}
}

func configDir() string {
	base, err := os.UserConfigDir()
	if err != nil || base == "" {
		base, _ = os.Getwd()
	}
	return filepath.Join(base, "lanternfish")
}
