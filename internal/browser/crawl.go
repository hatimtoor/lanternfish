package browser

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Result is what a headless crawl of one page discovered.
type Result struct {
	URL   string   `json:"url"`
	Links []string `json:"links"`
	Forms []Form   `json:"forms"`
	XHR   []string `json:"xhr"`
}

// Form is a discovered form.
type Form struct {
	Action string `json:"action"`
	Method string `json:"method"`
}

// hookScript instruments fetch/XHR so dynamically-issued requests are captured.
const hookScript = `
window.__lanternfish_xhr = [];
(function(){
  var push=function(u){try{window.__lanternfish_xhr.push(new URL(u, location.href).href)}catch(e){}};
  var of=window.fetch; if(of){window.fetch=function(i){try{push(typeof i==='string'?i:(i&&i.url))}catch(e){} return of.apply(this,arguments)}}
  var oo=XMLHttpRequest.prototype.open; XMLHttpRequest.prototype.open=function(m,u){push(u); return oo.apply(this,arguments)};
})();`

// collectScript returns a JSON string of links/forms/xhr from the loaded page.
const collectScript = `(function(){
  var abs=function(h){try{return new URL(h, location.href).href}catch(e){return null}};
  var links=[].slice.call(document.querySelectorAll('a[href]')).map(function(a){return abs(a.getAttribute('href'))}).filter(Boolean);
  var forms=[].slice.call(document.forms).map(function(f){return {action:abs(f.getAttribute('action')||location.href), method:(f.method||'GET').toUpperCase()}});
  var xhr=window.__lanternfish_xhr||[];
  return JSON.stringify({links:links, forms:forms, xhr:xhr});
})()`

// Available reports whether a usable Chromium-family browser was found.
func Available() bool { return findBrowser() != "" }

// Crawl loads url in a headless browser, lets its scripts run, and returns the
// links, forms, and fetch/XHR endpoints discovered. settle is how long to wait
// after load for late XHR (default 1.5s).
func Crawl(url string, settle time.Duration) (*Result, error) {
	value, err := withPage(url, hookScript, collectScript, settle)
	if err != nil {
		return nil, err
	}
	res := &Result{URL: url}
	if value != "" {
		_ = json.Unmarshal([]byte(value), res)
		res.URL = url
	}
	return res, nil
}

// withPage launches a headless browser, injects initScript before any page
// script runs, navigates to url, waits for load + settle, then returns the
// string value of evaluating collectExpr in the page.
func withPage(url, initScript, collectExpr string, settle time.Duration) (string, error) {
	bin := findBrowser()
	if bin == "" {
		return "", errors.New("no Chromium-family browser found")
	}
	if settle <= 0 {
		settle = 1500 * time.Millisecond
	}
	profile, err := os.MkdirTemp("", "lanternfish-headless-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(profile)

	cmd := exec.Command(bin,
		"--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
		"--disable-extensions", "--disable-sync", "--mute-audio",
		"--remote-debugging-port=0", "--user-data-dir="+profile, "about:blank",
	)
	if err := cmd.Start(); err != nil {
		return "", err
	}
	defer func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() }()

	wsURL, err := readBrowserWS(profile, 15*time.Second)
	if err != nil {
		return "", err
	}
	cdp, err := connectCDP(wsURL)
	if err != nil {
		return "", err
	}
	defer cdp.Close()

	raw, err := cdp.call("Target.createTarget", map[string]any{"url": "about:blank"}, "", 10*time.Second)
	if err != nil {
		return "", err
	}
	var ct struct {
		TargetID string `json:"targetId"`
	}
	_ = json.Unmarshal(raw, &ct)
	raw, err = cdp.call("Target.attachToTarget", map[string]any{"targetId": ct.TargetID, "flatten": true}, "", 10*time.Second)
	if err != nil {
		return "", err
	}
	var at struct {
		SessionID string `json:"sessionId"`
	}
	_ = json.Unmarshal(raw, &at)
	sid := at.SessionID
	if sid == "" {
		return "", errors.New("CDP attach returned no session")
	}

	_, _ = cdp.call("Page.enable", nil, sid, 10*time.Second)
	_, _ = cdp.call("Runtime.enable", nil, sid, 10*time.Second)
	if initScript != "" {
		_, _ = cdp.call("Page.addScriptToEvaluateOnNewDocument", map[string]any{"source": initScript}, sid, 10*time.Second)
	}
	if _, err := cdp.call("Page.navigate", map[string]any{"url": url}, sid, 20*time.Second); err != nil {
		return "", err
	}
	cdp.waitEvent("Page.loadEventFired", 20*time.Second)
	time.Sleep(settle)

	raw, err = cdp.call("Runtime.evaluate", map[string]any{
		"expression": collectExpr, "returnByValue": true, "awaitPromise": true,
	}, sid, 15*time.Second)
	if err != nil {
		return "", err
	}
	var ev struct {
		Result struct {
			Value string `json:"value"`
		} `json:"result"`
	}
	_ = json.Unmarshal(raw, &ev)
	return ev.Result.Value, nil
}

// readBrowserWS polls the DevToolsActivePort file Chromium writes and returns
// the browser-level WebSocket debugger URL.
func readBrowserWS(profile string, timeout time.Duration) (string, error) {
	path := filepath.Join(profile, "DevToolsActivePort")
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(path); err == nil {
			lines := strings.Split(strings.TrimSpace(string(b)), "\n")
			if len(lines) >= 2 {
				port := strings.TrimSpace(lines[0])
				wspath := strings.TrimSpace(lines[1])
				return "ws://127.0.0.1:" + port + wspath, nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return "", errors.New("timed out waiting for the browser DevTools port")
}

// findBrowser locates a Chromium-family browser binary.
func findBrowser() string {
	if runtime.GOOS == "windows" {
		for _, c := range []string{
			filepath.Join(os.Getenv("ProgramFiles(x86)"), `Microsoft\Edge\Application\msedge.exe`),
			filepath.Join(os.Getenv("ProgramFiles"), `Microsoft\Edge\Application\msedge.exe`),
			filepath.Join(os.Getenv("ProgramFiles"), `Google\Chrome\Application\chrome.exe`),
			filepath.Join(os.Getenv("ProgramFiles(x86)"), `Google\Chrome\Application\chrome.exe`),
		} {
			if _, err := os.Stat(c); err == nil {
				return c
			}
		}
		return ""
	}
	for _, name := range []string{"google-chrome", "chromium", "chromium-browser", "microsoft-edge", "brave-browser"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	for _, c := range []string{
		"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
		"/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
	} {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}
