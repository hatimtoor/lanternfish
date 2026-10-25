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
	URL    string   `json:"url"`
	Links  []string `json:"links"`
	Forms  []Form   `json:"forms"`
	XHR    []string `json:"xhr"`
	Routes []string `json:"routes"` // single-page-app routes (History API + route attributes)
}

// Form is a discovered form.
type Form struct {
	Action string `json:"action"`
	Method string `json:"method"`
}

// hookScript instruments fetch/XHR so dynamically-issued requests are captured,
// and hooks the History API so single-page-app route changes (router.push,
// pushState/replaceState) are recorded as navigable endpoints.
const hookScript = `
window.__lanternfish_xhr = [];
window.__lanternfish_routes = [];
(function(){
  var push=function(u){try{window.__lanternfish_xhr.push(new URL(u, location.href).href)}catch(e){}};
  var of=window.fetch; if(of){window.fetch=function(i){try{push(typeof i==='string'?i:(i&&i.url))}catch(e){} return of.apply(this,arguments)}}
  var oo=XMLHttpRequest.prototype.open; XMLHttpRequest.prototype.open=function(m,u){push(u); return oo.apply(this,arguments)};
  var route=function(u){try{window.__lanternfish_routes.push(new URL(u, location.href).href)}catch(e){}};
  var ps=history.pushState; history.pushState=function(s,t,u){try{if(u)route(u)}catch(e){} return ps.apply(this,arguments)};
  var rs=history.replaceState; history.replaceState=function(s,t,u){try{if(u)route(u)}catch(e){} return rs.apply(this,arguments)};
  window.addEventListener('hashchange',function(){route(location.href)});
})();`

// collectScript returns a JSON string of links/forms/xhr/routes from the loaded
// page. Beyond static anchors it gathers hash-based routes and single-page-app
// route attributes (Angular routerLink, data-href, etc.) so client-rendered
// navigation targets are discovered, not just server-rendered links.
const collectScript = `(function(){
  var abs=function(h){try{return new URL(h, location.href).href}catch(e){return null}};
  var seen={}, links=[], routes=[];
  var add=function(arr,v){if(v&&!seen[v]){seen[v]=1;arr.push(v)}};
  [].slice.call(document.querySelectorAll('a[href]')).forEach(function(a){add(links, abs(a.getAttribute('href')))});
  var sel='[routerLink],[routerlink],[data-href],[ng-href],[data-route],[data-link],[data-url]';
  [].slice.call(document.querySelectorAll(sel)).forEach(function(e){
    var h=e.getAttribute('routerLink')||e.getAttribute('routerlink')||e.getAttribute('data-href')||e.getAttribute('ng-href')||e.getAttribute('data-route')||e.getAttribute('data-link')||e.getAttribute('data-url');
    add(routes, abs(h));
  });
  (window.__lanternfish_routes||[]).forEach(function(r){add(routes, abs(r))});
  var forms=[].slice.call(document.forms).map(function(f){return {action:abs(f.getAttribute('action')||location.href), method:(f.method||'GET').toUpperCase()}});
  var xhr=window.__lanternfish_xhr||[];
  return JSON.stringify({links:links, forms:forms, xhr:xhr, routes:routes});
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
// withSession launches a headless browser, attaches a CDP session with Page,
// Runtime and Network enabled (and initScript installed before any page script
// runs), and invokes fn with the client and session id. It is the shared plumbing
// behind both crawling and authenticated login.
func withSession(initScript string, fn func(cdp *CDP, sid string) error) error {
	bin := findBrowser()
	if bin == "" {
		return errors.New("no Chromium-family browser found")
	}
	profile, err := os.MkdirTemp("", "lanternfish-headless-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(profile)

	cmd := exec.Command(bin,
		"--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
		"--disable-extensions", "--disable-sync", "--mute-audio",
		"--remote-debugging-port=0", "--user-data-dir="+profile, "about:blank",
	)
	if err := cmd.Start(); err != nil {
		return err
	}
	defer func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() }()

	wsURL, err := readBrowserWS(profile, 15*time.Second)
	if err != nil {
		return err
	}
	cdp, err := connectCDP(wsURL)
	if err != nil {
		return err
	}
	defer cdp.Close()

	raw, err := cdp.call("Target.createTarget", map[string]any{"url": "about:blank"}, "", 10*time.Second)
	if err != nil {
		return err
	}
	var ct struct {
		TargetID string `json:"targetId"`
	}
	_ = json.Unmarshal(raw, &ct)
	raw, err = cdp.call("Target.attachToTarget", map[string]any{"targetId": ct.TargetID, "flatten": true}, "", 10*time.Second)
	if err != nil {
		return err
	}
	var at struct {
		SessionID string `json:"sessionId"`
	}
	_ = json.Unmarshal(raw, &at)
	sid := at.SessionID
	if sid == "" {
		return errors.New("CDP attach returned no session")
	}

	_, _ = cdp.call("Page.enable", nil, sid, 10*time.Second)
	_, _ = cdp.call("Runtime.enable", nil, sid, 10*time.Second)
	_, _ = cdp.call("Network.enable", nil, sid, 10*time.Second)
	if initScript != "" {
		_, _ = cdp.call("Page.addScriptToEvaluateOnNewDocument", map[string]any{"source": initScript}, sid, 10*time.Second)
	}
	return fn(cdp, sid)
}

// evalString evaluates expr in the page and returns its string value.
func evalString(cdp *CDP, sid, expr string) (string, error) {
	raw, err := cdp.call("Runtime.evaluate", map[string]any{
		"expression": expr, "returnByValue": true, "awaitPromise": true,
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

func withPage(url, initScript, collectExpr string, settle time.Duration) (string, error) {
	if settle <= 0 {
		settle = 1500 * time.Millisecond
	}
	var out string
	err := withSession(initScript, func(cdp *CDP, sid string) error {
		if _, err := cdp.call("Page.navigate", map[string]any{"url": url}, sid, 20*time.Second); err != nil {
			return err
		}
		cdp.waitEvent("Page.loadEventFired", 20*time.Second)
		time.Sleep(settle)
		v, err := evalString(cdp, sid, collectExpr)
		out = v
		return err
	})
	return out, err
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
