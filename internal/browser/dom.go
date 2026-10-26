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

// domProbeURL places the canary where client-side code will read it, returning
// the URL to load. It handles single-page-app hash-routes specially: a target
// like ".../#/search?q=1" must keep its route (#/search) and carry the canary
// in the route's own query (#/search?q=CANARY) — overwriting the whole fragment
// would navigate the SPA away from the vulnerable component and miss the sink.
// Prototype-pollution gadgets are always added to the real query so a page's
// query parser merges them.
func domProbeURL(target, canary string) (string, error) {
	u, err := url.Parse(target)
	if err != nil {
		return "", err
	}
	frag := u.Fragment

	q := u.Query()
	for k := range q {
		q.Set(k, canary)
	}
	// Only seed a default ?q= on a plain page; for a hash-route the canary goes
	// into the route's query instead (handled below).
	if len(q) == 0 && !strings.HasPrefix(frag, "/") {
		q.Set("q", canary)
	}
	q.Set("__proto__[lanternfishpp]", "LANTERNFISHPP")
	q.Set("constructor[prototype][lanternfishpp]", "LANTERNFISHPP")
	u.RawQuery = q.Encode()

	// Build everything up to the fragment with net/url, then append the fragment
	// by hand so its "/", "?" and "=" are not percent-encoded (which would break
	// the SPA route).
	u.Fragment = ""
	base := u.String()

	var fragOut string
	switch {
	case frag == "":
		// Classic page: canary in the hash for location.hash / history sinks.
		fragOut = canary
	case strings.Contains(frag, "?"):
		// Hash-route with a query: inject the canary into its query values.
		route, rawq, _ := strings.Cut(frag, "?")
		fq, _ := url.ParseQuery(rawq)
		for k := range fq {
			fq.Set(k, canary)
		}
		if len(fq) == 0 {
			fq.Set("q", canary)
		}
		fragOut = route + "?" + fq.Encode()
	case strings.HasPrefix(frag, "/"):
		// Hash-route path with no query: give it one carrying the canary.
		fragOut = frag + "?q=" + canary
	default:
		fragOut = canary
	}
	return base + "#" + fragOut, nil
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

	probeURL, err := domProbeURL(target, canary)
	if err != nil {
		return nil, err
	}

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
  // Location / navigation sinks (javascript: URLs or canary in a redirect).
  try{ var la=location.assign; location.assign=function(u){ rec("location.assign",u); return la.apply(this,arguments);} }catch(e){}
  try{ var lr=location.replace; location.replace=function(u){ rec("location.replace",u); return lr.apply(this,arguments);} }catch(e){}
  try{ var wo=window.open; window.open=function(u){ rec("window.open",u); return wo.apply(this,arguments);} }catch(e){}
  ["HTMLAnchorElement","HTMLAreaElement"].forEach(function(n){ try{ setProp(window[n].prototype,"href",function(v){ rec(n+".href",v); }); }catch(e){} });
  ["HTMLScriptElement","HTMLIFrameElement","HTMLImageElement","HTMLEmbedElement"].forEach(function(n){ try{ setProp(window[n].prototype,"src",function(v){ rec(n+".src",v); }); }catch(e){} });
  // Additional HTML-parsing sinks.
  try{ var ccf=Range.prototype.createContextualFragment; Range.prototype.createContextualFragment=function(s){ rec("createContextualFragment",s); return ccf.apply(this,arguments);} }catch(e){}
  try{ var dpp=DOMParser.prototype.parseFromString; DOMParser.prototype.parseFromString=function(s){ rec("DOMParser.parseFromString",s); return dpp.apply(this,arguments);} }catch(e){}
  try{ if(window.ShadowRoot) setProp(ShadowRoot.prototype,"innerHTML",function(v){ rec("ShadowRoot.innerHTML",v); }); }catch(e){}
  // jQuery manipulation sinks (html + the insert/replace/attr family), if present.
  try{ if(window.jQuery&&jQuery.fn){
    ["html","append","prepend","before","after","replaceWith","wrap","wrapAll","wrapInner"].forEach(function(m){ var o=jQuery.fn[m]; if(o){ jQuery.fn[m]=function(v){ if(typeof v==="string") rec("jQuery."+m,v); return o.apply(this,arguments);} } });
    var oa=jQuery.fn.attr; if(oa){ jQuery.fn.attr=function(n,v){ if(typeof v==="string"&&/^(href|src|srcdoc)$/i.test(n)) rec("jQuery.attr("+n+")",v); return oa.apply(this,arguments);} }
  } }catch(e){}
  // (Prototype-pollution is checked at collection time, after page scripts run.)
  // Extra sources: window.name (readable by page scripts) and postMessage in
  // both string and structured forms, so handlers that sink event.data or
  // event.data.<field> are exercised.
  try{ window.name=CANARY; }catch(e){}
  try{ window.setTimeout(function(){ try{ window.postMessage(CANARY,"*"); window.postMessage({data:CANARY,message:CANARY,url:CANARY},"*"); }catch(e){} }, 250); }catch(e){}
})();`
