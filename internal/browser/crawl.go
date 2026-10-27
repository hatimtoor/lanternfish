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
  // Hash-route detection is a sticky flag, not a single snapshot: an Angular
  // (etc.) app rewrites "/" to "/#/" during bootstrap, so a one-time check at
  // collection races the router and intermittently misses it, leaving routes
  // in bare server-path form. Record it the instant location ever carries a
  // "#/" segment, poll briefly across bootstrap, and keep it set thereafter.
  window.__lanternfish_hashrouted = false;
  var markHash=function(){try{if(/#\//.test(location.href)) window.__lanternfish_hashrouted=true;}catch(e){}};
  var route=function(u){try{window.__lanternfish_routes.push(new URL(u, location.href).href);markHash();}catch(e){}};
  var ps=history.pushState; history.pushState=function(s,t,u){try{if(u)route(u)}catch(e){} return ps.apply(this,arguments)};
  var rs=history.replaceState; history.replaceState=function(s,t,u){try{if(u)route(u)}catch(e){} return rs.apply(this,arguments)};
  window.addEventListener('hashchange',function(){route(location.href)});
  markHash(); var __hp=setInterval(markHash,100); setTimeout(function(){clearInterval(__hp)},4000);
})();`

// collectScript returns a JSON string of links/forms/xhr/routes from the loaded
// page. Beyond static anchors it gathers hash-based routes and single-page-app
// route attributes (Angular routerLink, data-href, etc.) so client-rendered
// navigation targets are discovered, not just server-rendered links.
const collectScript = `(function(){
  var abs=function(h){try{return new URL(h, location.href).href}catch(e){return null}};
  var seen={}, links=[], routes=[];
  var add=function(arr,v){if(v&&!seen[v]){seen[v]=1;arr.push(v)}};
  // Hash-routed SPAs (Angular HashLocationStrategy, many Vue/React apps) serve
  // one shell for every server path and route on location.hash. A routerLink
  // value like "/search" must be probed as "#/search", not the server path
  // "/search" (which just renders the default page). Detect hash routing from
  // the loaded URL or any #/ anchor, and map bare route paths into hash form.
  var hashRouted = !!window.__lanternfish_hashrouted || /#\//.test(location.href) || !![].slice.call(document.querySelectorAll('a[href^="#/"],a[href^="#!"]')).length;
  var toRoute=function(h){
    if(!h) return null;
    if(/^[a-z][a-z0-9+.-]*:/i.test(h) || h.charAt(0)==='#') return abs(h); // absolute or already a hash-route
    if(hashRouted) return abs('#'+(h.charAt(0)==='/'?h:'/'+h));
    return abs(h);
  };
  [].slice.call(document.querySelectorAll('a[href]')).forEach(function(a){add(links, abs(a.getAttribute('href')))});
  var sel='[routerLink],[routerlink],[data-href],[ng-href],[data-route],[data-link],[data-url]';
  [].slice.call(document.querySelectorAll(sel)).forEach(function(e){
    var h=e.getAttribute('routerLink')||e.getAttribute('routerlink')||e.getAttribute('data-href')||e.getAttribute('ng-href')||e.getAttribute('data-route')||e.getAttribute('data-link')||e.getAttribute('data-url');
    add(routes, toRoute(h));
  });
  (window.__lanternfish_routes||[]).forEach(function(r){add(routes, abs(r))});
  var forms=[].slice.call(document.forms).map(function(f){return {action:abs(f.getAttribute('action')||location.href), method:(f.method||'GET').toUpperCase()}});
  var xhr=window.__lanternfish_xhr||[];
  return JSON.stringify({links:links, forms:forms, xhr:xhr, routes:routes});
})()`

// driveSearchScript types a benign marker into search-style inputs and fires the
// input + Enter-key events a single-page-app search box listens to, so that
// input-driven routes (e.g. Angular's "#/search?q=...") are navigated and
// captured by the pushState/hashchange hooks. It is deliberately scoped to
// clearly search-related inputs (type=search, or id/name/aria-label/placeholder
// containing "search", or role=searchbox) so it does not drive login or other
// forms, and it uses synthetic key events (which never trigger implicit form
// submission) rather than submitting any form, so there is no full-page
// navigation side effect.
const driveSearchScript = `
  var __lfSleep=function(ms){return new Promise(function(r){setTimeout(r,ms)})};
  var __lfInputSel='input[type=search],input[id*="search" i],input[name*="search" i],input[aria-label*="search" i],input[placeholder*="search" i],input[class*="search" i],[role=searchbox]';
  var __lfGather=function(){ var seen=[],out=[]; try{ [].slice.call(document.querySelectorAll(__lfInputSel)).forEach(function(el){ if(el.tagName==='INPUT'&&seen.indexOf(el)<0){seen.push(el);out.push(el);} }); }catch(e){} return out; };
  try{
    // Many SPAs collapse the search box behind an icon/button (e.g. Angular
    // Material mat-search-bar), so the input is inert until opened. Click
    // likely search toggles first, then re-query for the revealed input.
    try{
      var __lfTog=[].slice.call(document.querySelectorAll('button[aria-label*="search" i],[mattooltip*="search" i],button[class*="search" i],[class*="searchButton" i],[id*="searchButton" i],mat-icon[class*="search" i]'));
      for(var __t=0;__t<Math.min(__lfTog.length,2);__t++){ try{ __lfTog[__t].click(); }catch(e){} }
    }catch(e){}
    await __lfSleep(250);
    var __lfInputs=__lfGather();
    for(var __i=0;__i<Math.min(__lfInputs.length,3);__i++){
      var __el=__lfInputs[__i];
      try{
        __el.focus();
        __el.value='lanternfishprobe';
        __el.dispatchEvent(new Event('input',{bubbles:true}));
        __el.dispatchEvent(new Event('change',{bubbles:true}));
        ['keydown','keypress','keyup'].forEach(function(t){ __el.dispatchEvent(new KeyboardEvent(t,{key:'Enter',code:'Enter',keyCode:13,which:13,bubbles:true})); });
      }catch(e){}
      await __lfSleep(350);
    }
  }catch(e){}
  await __lfSleep(400);`

// crawlScript drives search inputs (to surface input-driven SPA routes) and then
// returns the same links/forms/xhr/routes collection as collectScript. It is an
// async expression; evalString runs it with awaitPromise so the SPA has time to
// route before the page is read.
var crawlScript = "(async function(){" + driveSearchScript + "\nreturn " + collectScript + ";})()"

// Available reports whether a usable Chromium-family browser was found.
func Available() bool { return findBrowser() != "" }

// Crawl loads url in a headless browser, lets its scripts run, and returns the
// links, forms, and fetch/XHR endpoints discovered. settle is how long to wait
// after load for late XHR (default 1.5s).
func Crawl(url string, settle time.Duration) (*Result, error) {
	value, err := withPage(url, hookScript, crawlScript, settle)
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
