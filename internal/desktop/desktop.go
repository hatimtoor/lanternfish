// Package desktop launches Lanternfish as a standalone native window. On Windows it
// uses the WebView2 runtime via Edge's app mode, producing a chromeless desktop
// window (no tabs, no address bar) with its own profile, separate from the
// user's browser. It falls back to the default browser if no suitable runtime
// is found. This keeps the build pure Go (no cgo) while giving a native shell.
package desktop

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// Launch opens url in a standalone app window and returns the running process.
// profileDir is a private user-data directory for the embedded runtime.
// If no app-capable runtime is found, it opens the default browser and returns
// a nil process with ok=false.
func Launch(url, profileDir string) (proc *os.Process, ok bool, err error) {
	_ = os.MkdirAll(profileDir, 0o700)
	switch runtime.GOOS {
	case "windows":
		return launchWindows(url, profileDir)
	case "darwin":
		// Prefer Chrome/Edge app mode if present; else default browser.
		for _, b := range []string{
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			"/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
		} {
			if _, e := os.Stat(b); e == nil {
				return startApp(b, url, profileDir)
			}
		}
		return openDefault(url)
	default:
		for _, name := range []string{"microsoft-edge", "google-chrome", "chromium", "chromium-browser", "brave-browser"} {
			if p, e := exec.LookPath(name); e == nil {
				return startApp(p, url, profileDir)
			}
		}
		return openDefault(url)
	}
}

func launchWindows(url, profileDir string) (*os.Process, bool, error) {
	candidates := []string{
		filepath.Join(os.Getenv("ProgramFiles(x86)"), `Microsoft\Edge\Application\msedge.exe`),
		filepath.Join(os.Getenv("ProgramFiles"), `Microsoft\Edge\Application\msedge.exe`),
		filepath.Join(os.Getenv("ProgramFiles"), `Google\Chrome\Application\chrome.exe`),
		filepath.Join(os.Getenv("ProgramFiles(x86)"), `Google\Chrome\Application\chrome.exe`),
	}
	for _, c := range candidates {
		if _, e := os.Stat(c); e == nil {
			return startApp(c, url, profileDir)
		}
	}
	return openDefault(url)
}

func startApp(bin, url, profileDir string) (*os.Process, bool, error) {
	args := []string{
		"--app=" + url,
		"--user-data-dir=" + profileDir,
		"--window-size=1440,900",
		"--no-first-run",
		"--no-default-browser-check",
		"--disable-features=Translate,AutofillServerCommunication",
	}
	cmd := exec.Command(bin, args...)
	if err := cmd.Start(); err != nil {
		return nil, false, err
	}
	return cmd.Process, true, nil
}

func openDefault(url string) (*os.Process, bool, error) {
	switch runtime.GOOS {
	case "windows":
		// rundll32 is the reliable no-shell opener.
		cmd := exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
		err := cmd.Start()
		return nil, false, err
	case "darwin":
		return nil, false, exec.Command("open", url).Start()
	default:
		return nil, false, exec.Command("xdg-open", url).Start()
	}
}

// Describe returns a short human description of how the window will open.
func Describe() string {
	if runtime.GOOS == "windows" {
		return "WebView2 (Edge) app window"
	}
	return fmt.Sprintf("app window on %s", runtime.GOOS)
}
