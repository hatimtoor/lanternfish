package browser

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Creds describes how to log in through the browser. UserField/PassField/Submit
// are optional CSS selectors; when empty, the fields are auto-detected (the
// password input and the nearest preceding text/email input, and the form's
// submit button).
type Creds struct {
	LoginURL  string
	User      string
	Pass      string
	UserField string
	PassField string
	Submit    string
}

// Cookie is a session cookie captured after login.
type Cookie struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Domain string `json:"domain"`
	Path   string `json:"path"`
}

// Header renders the cookies as a Cookie request-header value.
func CookieHeader(cs []Cookie) string {
	var parts []string
	for _, c := range cs {
		parts = append(parts, c.Name+"="+c.Value)
	}
	return strings.Join(parts, "; ")
}

// Login drives a headless browser through a login form and returns the session
// cookies the server set, so the scanner can then crawl and audit the
// authenticated application. Real targets live behind a login; this is how you
// get past it without hand-copying cookies.
func Login(c Creds, settle time.Duration) ([]Cookie, error) {
	if settle <= 0 {
		settle = 2 * time.Second
	}
	var cookies []Cookie
	err := withSession("", func(cdp *CDP, sid string) error {
		if _, err := cdp.call("Page.navigate", map[string]any{"url": c.LoginURL}, sid, 20*time.Second); err != nil {
			return err
		}
		cdp.waitEvent("Page.loadEventFired", 20*time.Second)
		time.Sleep(600 * time.Millisecond)

		if _, err := evalString(cdp, sid, fillAndSubmitJS(c)); err != nil {
			return err
		}
		// Let the submit navigate / the auth request complete.
		cdp.waitEvent("Page.loadEventFired", 15*time.Second)
		time.Sleep(settle)

		raw, err := cdp.call("Network.getAllCookies", nil, sid, 10*time.Second)
		if err != nil {
			return err
		}
		var out struct {
			Cookies []Cookie `json:"cookies"`
		}
		_ = json.Unmarshal(raw, &out)
		cookies = out.Cookies
		return nil
	})
	return cookies, err
}

// fillAndSubmitJS builds the page script that fills the login fields and submits
// the form. Values are JSON-encoded so quotes/special characters are safe.
func fillAndSubmitJS(c Creds) string {
	user, _ := json.Marshal(c.User)
	pass, _ := json.Marshal(c.Pass)
	userSel, _ := json.Marshal(c.UserField)
	passSel, _ := json.Marshal(c.PassField)
	submitSel, _ := json.Marshal(c.Submit)
	return fmt.Sprintf(`(function(){
  var USER=%s, PASS=%s, USEL=%s, PSEL=%s, SSEL=%s;
  function setVal(el,v){ if(!el) return false; try{
    var proto=el.tagName==='TEXTAREA'?HTMLTextAreaElement.prototype:HTMLInputElement.prototype;
    var d=Object.getOwnPropertyDescriptor(proto,'value'); d&&d.set?d.set.call(el,v):(el.value=v);
    el.dispatchEvent(new Event('input',{bubbles:true}));
    el.dispatchEvent(new Event('change',{bubbles:true}));
    return true;
  }catch(e){ try{el.value=v;}catch(_){ } return true; } }
  var pw = PSEL?document.querySelector(PSEL):document.querySelector('input[type=password]');
  var uf = USEL?document.querySelector(USEL):null;
  if(!uf){
    var cand=[].slice.call(document.querySelectorAll('input[type=text],input[type=email],input:not([type]),input[name*=user i],input[name*=email i],input[id*=user i],input[id*=email i]'));
    // Prefer a username/email field that appears before the password field.
    uf = cand[0] || null;
  }
  setVal(uf, USER); setVal(pw, PASS);
  var btn = SSEL?document.querySelector(SSEL):null;
  if(!btn && pw){ var f=pw.form; if(f){ btn=f.querySelector('button[type=submit],input[type=submit],button:not([type])'); } }
  if(!btn){ btn=document.querySelector('button[type=submit],input[type=submit]'); }
  if(btn){ btn.click(); }
  else if(pw && pw.form){ try{ pw.form.submit(); }catch(e){} }
  return "submitted";
})()`, user, pass, userSel, passSel, submitSel)
}
