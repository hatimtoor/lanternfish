package browser

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"strings"
	"time"
)

// randToken returns an unpredictable hex token for canaries, so a hostile page
// cannot guess and suppress the canary to evade DOM-XSS detection.
func randToken() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "0a1b2c3d4e5f"
	}
	return hex.EncodeToString(b[:])
}

// DOMHit is one dangerous DOM sink that received the canary.
type DOMHit struct {
	Sink  string `json:"sink"`
	Value string `json:"value"`
}

// DOMResult is the outcome of a DOM-XSS probe.
type DOMResult struct {
	URL    string   `json:"url"`
	Canary string   `json:"canary"`
	Hits   []DOMHit `json:"hits"`
}

// DOMXSS loads url in a headless browser with a unique canary placed in the URL
// fragment and query values, and hooks dangerous DOM sinks (document.write,
// innerHTML, eval, setTimeout(string), insertAdjacentHTML). If the canary flows
// into a sink, that is a DOM-based XSS source→sink path. This is the core idea
// behind Burp's DOM Invader, done via headless instrumentation.
func DOMXSS(target string, settle time.Duration) (*DOMResult, error) {
	canary := "lanternfishdom" + randToken()

	// Place the canary in the fragment and in every existing query value.
	u, err := url.Parse(target)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	for k := range q {
		q.Set(k, canary)
	}
	if len(q) == 0 {
		q.Set("q", canary)
	}
	// Prototype-pollution gadgets: client-side query parsers that merge these
	// into an object pollute Object.prototype. The hook script checks for it.
	q.Set("__proto__[lanternfishpp]", "LANTERNFISHPP")
	q.Set("constructor[prototype][lanternfishpp]", "LANTERNFISHPP")
	u.RawQuery = q.Encode()
	u.Fragment = canary
	probeURL := u.String()

	init := strings.ReplaceAll(domHookScript, "__CANARY__", canary)
	// The prototype-pollution check runs at collection time (after page scripts
	// have parsed the query), not at init time when nothing is polluted yet.
	collect := `(function(){try{if((({}).lanternfishpp==="LANTERNFISHPP"||Object.prototype.lanternfishpp==="LANTERNFISHPP")&&!window.__lanternfish_pp){window.__lanternfish_pp=1;(window.__lanternfish_dom=window.__lanternfish_dom||[]).push({sink:"prototype-pollution",value:"Object.prototype.lanternfishpp polluted via query"});}}catch(e){}return JSON.stringify(window.__lanternfish_dom||[]);})()`

	value, err := withPage(probeURL, init, collect, settle)
	if err != nil {
		return nil, err
	}
	res := &DOMResult{URL: probeURL, Canary: canary}
	if value != "" {
		_ = json.Unmarshal([]byte(value), &res.Hits)
	}
	return res, nil
}

// domHookScript hooks common DOM-XSS sinks and records when the canary passes
// through them, flags client-side prototype pollution, and feeds the canary in
// through additional sources (postMessage). __CANARY__ is substituted before
// injection. This broadens the sink/source coverage toward DOM Invador's.
const domHookScript = `
(function(){
  var CANARY="__CANARY__";
  window.__lanternfish_dom=[];
  function rec(sink,v){ try{ if(typeof v==="string" && v.indexOf(CANARY)>=0){ window.__lanternfish_dom.push({sink:sink,value:String(v).slice(0,200)});} }catch(e){} }
  function setProp(obj,name,hook){ try{ var d=Object.getOwnPropertyDescriptor(obj,name); if(d&&d.set){ Object.defineProperty(obj,name,{set:function(v){ hook(v); return d.set.call(this,v);},get:d.get,configurable:true}); } }catch(e){} }
  // HTML-writing sinks.
  try{ var dw=document.write; document.write=function(s){ rec("document.write",s); return dw.apply(this,arguments);} }catch(e){}
  try{ var dwl=document.writeln; document.writeln=function(s){ rec("document.writeln",s); return dwl.apply(this,arguments);} }catch(e){}
  setProp(Element.prototype,"innerHTML",function(v){ rec("innerHTML",v); });
  setProp(Element.prototype,"outerHTML",function(v){ rec("outerHTML",v); });
  try{ var iah=Element.prototype.insertAdjacentHTML; Element.prototype.insertAdjacentHTML=function(p,s){ rec("insertAdjacentHTML",s); return iah.apply(this,arguments);} }catch(e){}
  // Code-execution sinks.
  try{ var oe=window.eval; window.eval=function(s){ rec("eval",s); return oe.apply(this,arguments);} }catch(e){}
  try{ var oF=window.Function; window.Function=function(){ for(var i=0;i<arguments.length;i++) rec("Function",arguments[i]); return oF.apply(this,arguments);} }catch(e){}
  try{ var ost=window.setTimeout; window.setTimeout=function(f){ if(typeof f==="string") rec("setTimeout",f); return ost.apply(this,arguments);} }catch(e){}
  try{ var osi=window.setInterval; window.setInterval=function(f){ if(typeof f==="string") rec("setInterval",f); return osi.apply(this,arguments);} }catch(e){}
  // Attribute / navigation sinks.
  try{ var sa=Element.prototype.setAttribute; Element.prototype.setAttribute=function(n,v){ if(/^(href|src|srcdoc|action|formaction|data)$/i.test(n)) rec("setAttribute("+n+")",v); return sa.apply(this,arguments);} }catch(e){}
  setProp(HTMLElement.prototype,"srcdoc",function(v){ rec("iframe.srcdoc",v); });
  // jQuery.html(), if jQuery is present.
  try{ if(window.jQuery&&jQuery.fn&&jQuery.fn.html){ var jh=jQuery.fn.html; jQuery.fn.html=function(v){ if(typeof v==="string") rec("jQuery.html",v); return jh.apply(this,arguments);} } }catch(e){}
  // (Prototype-pollution is checked at collection time, after page scripts run.)
  // Extra source: deliver the canary via postMessage so message handlers that
  // sink event.data are exercised.
  try{ window.setTimeout(function(){ try{ window.postMessage(CANARY,"*"); }catch(e){} }, 250); }catch(e){}
})();`
