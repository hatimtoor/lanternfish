package mcp

// toolDefs is the static tool catalog advertised via tools/list. Schemas are
// intentionally compact; each maps to a case in runTool.
var toolDefs = []map[string]any{
	{
		"name":        "scan_url",
		"description": "Run passive and active vulnerability checks against one URL (query/body parameters are fuzzed). Returns issues found and records them in the session.",
		"inputSchema": obj(props{
			"url":  str("Absolute target URL, e.g. https://host/path?param=value"),
			"fast": boolean("Skip wait-heavy checks (out-of-band + time-based inference) for a quicker scan (default false)"),
		}, "url"),
	},
	{
		"name":        "auto_scan",
		"description": "Autopilot: point at one URL and run the whole workflow automatically — scope to the host, enable out-of-band checks, scan the seed, crawl and actively audit every in-scope request, optionally drive a headless browser for JS endpoints and DOM-XSS, and return every issue found grouped by severity. Use this when asked to just 'test' or 'scan' a site end to end.",
		"inputSchema": obj(props{
			"target":    str("Absolute seed URL, e.g. https://host/"),
			"fast":      boolean("Skip wait-heavy checks for a quicker pass (default false)"),
			"browser":   boolean("Also run a headless-browser crawl and DOM-XSS if a browser is present (default false)"),
			"max_pages": num("Crawl page budget (default 100)"),
			"max_depth": num("Crawl link depth (default 3)"),
		}, "target"),
	},
	{
		"name":        "explain_check",
		"description": "Explain a finding for a learner: what the vulnerability is, why it matters, how to confirm it by hand, how to exploit it safely in a lab, how to fix it, and free resources. Pass a check id (e.g. the 'check' field of an issue). Omit 'check' to list the ids that have an explanation.",
		"inputSchema": obj(props{
			"check": str("The check id to explain (e.g. reflected-xss, sqli-error, blind-ssrf). Omit to list available ids."),
		}),
	},
	{
		"name":        "set_live_audit",
		"description": "Turn automatic active scanning of in-scope proxy traffic on or off. When on, every in-scope request seen through the proxy is scanned in the background, so browsing a target feeds the scanner with no manual step. Requires a scope (an include rule) to be set first.",
		"inputSchema": obj(props{
			"enabled": boolean("true to enable live auto-audit, false to disable"),
		}, "enabled"),
	},
	{
		"name":        "replay_request",
		"description": "Send a single HTTP request (like a manual repeater) and return the response. Recorded in history.",
		"inputSchema": obj(props{
			"method":  str("HTTP method (default GET)"),
			"url":     str("Absolute target URL"),
			"headers": objFree("Request headers as a name->value object"),
			"body":    str("Request body (optional)"),
		}, "url"),
	},
	{
		"name":        "list_history",
		"description": "List recorded HTTP transactions (proxy, repeater, scanner), newest first.",
		"inputSchema": obj(props{"limit": num("Max entries (0 = all)")}),
	},
	{
		"name":        "get_message",
		"description": "Get the full request and response of one history entry by id.",
		"inputSchema": obj(props{"id": num("History entry id")}, "id"),
	},
	{
		"name":        "intruder",
		"description": "Positional Intruder attack over a raw HTTP request template whose payload positions are marked with §...§. type is sniper, batteringram, pitchfork, or clusterbomb. payload_sets is a list of payload lists (one per position for pitchfork/clusterbomb; the first is used for sniper/batteringram). Optional grep_extract regex captures a value from each response.",
		"inputSchema": obj(props{
			"scheme":       str("http or https"),
			"host":         str("Target host[:port]"),
			"template":     str("Raw HTTP request with §...§ payload positions"),
			"type":         str("sniper | batteringram | pitchfork | clusterbomb"),
			"payload_sets": map[string]any{"type": "array", "description": "List of payload lists (one per position)", "items": map[string]any{"type": "array", "items": map[string]any{"type": "string"}}},
			"grep_extract": str("Optional regex; first group captured per response"),
		}, "host", "template", "type"),
	},
	{
		"name":        "annotate_message",
		"description": "Add a note and/or flag to a history entry (organizer), for later review.",
		"inputSchema": obj(props{"id": num("History entry id"), "note": str("Note text"), "flagged": boolean("Flag for review")}, "id"),
	},
	{
		"name":        "list_flagged",
		"description": "List history entries that are flagged or have a note (the organizer).",
		"inputSchema": obj(props{}),
	},
	{
		"name":        "test_scope",
		"description": "Test whether a URL is in the current target scope (scope regex tester).",
		"inputSchema": obj(props{"url": str("Absolute URL to test")}, "url"),
	},
	{
		"name":        "schedule_scan",
		"description": "Schedule a recurring scan of a URL every interval_sec seconds (min 10).",
		"inputSchema": obj(props{"url": str("Target URL"), "interval_sec": num("Interval in seconds")}, "url"),
	},
	{
		"name":        "list_schedules",
		"description": "List active recurring scans.",
		"inputSchema": obj(props{}),
	},
	{
		"name":        "unschedule",
		"description": "Stop and remove a recurring scan by id.",
		"inputSchema": obj(props{"id": num("Schedule id")}, "id"),
	},
	{
		"name":        "export_report",
		"description": "Render all findings as a report. format is json, xml, html, or text.",
		"inputSchema": obj(props{"format": str("json | xml | html | text")}),
	},
	{
		"name":        "csrf_poc",
		"description": "Generate a CSRF proof-of-concept HTML page for a request (auto-submitting form for form-encoded, fetch() otherwise).",
		"inputSchema": obj(props{
			"method": str("HTTP method"), "url": str("Target URL"),
			"content_type": str("Request Content-Type"), "body": str("Request body"),
		}, "url"),
	},
	{
		"name":        "clickjack_poc",
		"description": "Generate a clickjacking proof-of-concept page that frames a URL under a decoy overlay (works only if the target allows framing).",
		"inputSchema": obj(props{"url": str("Target URL to frame"), "opacity": num("iframe opacity 0..1 (default 0.1)")}, "url"),
	},
	{
		"name":        "run_macro",
		"description": "Run a login/session macro: a sequence of requests through a cookie jar, optionally extracting a token via regex. The resulting cookies and/or extracted header are applied as session auth so later scans are authenticated.",
		"inputSchema": obj(props{
			"steps":         map[string]any{"type": "array", "description": "Ordered requests", "items": map[string]any{"type": "object"}},
			"extract_regex": str("Optional regex applied to the final response; first group captured"),
			"extract_into":  str("Header name to set with the extracted value, e.g. Authorization"),
			"use_cookies":   boolean("Carry cookies into the session (default true)"),
		}, "steps"),
	},
	{
		"name":        "decode",
		"description": "Decoder/encoder transform. op is one of base64-encode, base64-decode, url-encode, url-decode, hex-encode, hex-decode, html-encode, html-decode, ascii-hex-encode, ascii-hex-decode, md5, sha1, sha256, smart-decode.",
		"inputSchema": obj(props{"input": str("Text to transform"), "op": str("Operation name")}, "input", "op"),
	},
	{
		"name":        "compare",
		"description": "Diff two texts (e.g. two responses). mode is line or word.",
		"inputSchema": obj(props{"a": str("First text"), "b": str("Second text"), "mode": str("line | word")}, "a", "b"),
	},
	{
		"name":        "sequence",
		"description": "Estimate the randomness of a set of tokens (session IDs, CSRF tokens) via per-position Shannon entropy.",
		"inputSchema": obj(props{"tokens": arr("Token strings to analyze")}, "tokens"),
	},
	{
		"name":        "dom_xss",
		"description": "Probe a page for DOM-based XSS: a canary is placed in the URL and dangerous DOM sinks (innerHTML, document.write, eval, setTimeout) are instrumented in a headless browser; sink hits are reported.",
		"inputSchema": obj(props{"url": str("Page URL to probe")}, "url"),
	},
	{
		"name":        "browser_crawl",
		"description": "Crawl a JavaScript-rendered page in a headless browser (executes scripts), discovering links, forms, and fetch/XHR endpoints a static crawler misses. In-scope results are fetched and recorded.",
		"inputSchema": obj(props{"url": str("Seed URL to render and crawl")}, "url"),
	},
	{
		"name":        "crawl_site",
		"description": "Crawl in-scope pages from seed URLs, discovering links and forms (recorded in the session). Set audit=true to actively scan every discovered request.",
		"inputSchema": obj(props{
			"seeds":     arr("Seed URLs to start from"),
			"max_pages": num("Max pages to fetch (default 100)"),
			"max_depth": num("Max link depth (default 3)"),
			"audit":     boolean("Also run active checks on discovered requests"),
		}, "seeds"),
	},
	{
		"name":        "fuzz",
		"description": "Intruder-style fuzzer: substitute each payload for the marker in url/headers/body, send all requests, and return per-payload status/length/timing. Default marker is FUZZ.",
		"inputSchema": obj(props{
			"method":   str("HTTP method (default GET)"),
			"url":      str("Target URL, may contain the marker"),
			"headers":  objFree("Headers; names/values may contain the marker"),
			"body":     str("Body; may contain the marker"),
			"marker":   str("Placeholder replaced by payloads (default FUZZ)"),
			"payloads": arr("Payload strings to try"),
		}, "url", "payloads"),
	},
	{
		"name":        "save_project",
		"description": "Save the full session (history, issues, scope) to a JSON project file.",
		"inputSchema": obj(props{"path": str("File path to write")}, "path"),
	},
	{
		"name":        "load_project",
		"description": "Load a session from a JSON project file, replacing current state.",
		"inputSchema": obj(props{"path": str("File path to read")}, "path"),
	},
	{
		"name":        "list_issues",
		"description": "List all vulnerability issues found so far, most severe first.",
		"inputSchema": obj(props{}),
	},
	{
		"name":        "get_sitemap",
		"description": "Get the host/path sitemap derived from observed traffic.",
		"inputSchema": obj(props{}),
	},
	{
		"name":        "set_scope",
		"description": "Modify the target scope. action is include, exclude, or clear. host may use a wildcard like *.example.com.",
		"inputSchema": obj(props{
			"action":      str("include | exclude | clear"),
			"host":        str("Host or wildcard (for include/exclude)"),
			"path_prefix": str("Optional path prefix to scope to"),
		}, "action"),
	},
	{
		"name":        "intercept_toggle",
		"description": "Turn request interception on or off. When on, in-scope proxied requests are held until forwarded or dropped.",
		"inputSchema": obj(props{"enabled": boolean("true to enable interception")}, "enabled"),
	},
	{
		"name":        "intercept_list",
		"description": "List currently held (intercepted) requests awaiting a decision.",
		"inputSchema": obj(props{}),
	},
	{
		"name":        "intercept_forward",
		"description": "Forward a held request. Optionally replace it by passing a full raw HTTP request in raw.",
		"inputSchema": obj(props{
			"id":  num("Held request id"),
			"raw": str("Optional edited raw HTTP request to send instead"),
		}, "id"),
	},
	{
		"name":        "intercept_drop",
		"description": "Drop a held request without sending it.",
		"inputSchema": obj(props{"id": num("Held request id")}, "id"),
	},
	{
		"name":        "set_auth_header",
		"description": "Set (empty value deletes) a header injected into scanner/crawler/replayer requests for authenticated testing, e.g. Cookie or Authorization.",
		"inputSchema": obj(props{
			"name":  str("Header name, e.g. Authorization or Cookie"),
			"value": str("Header value; empty removes it"),
		}, "name"),
	},
	{
		"name":        "list_auth_headers",
		"description": "List the headers injected into tool-originated requests.",
		"inputSchema": obj(props{}),
	},
	{
		"name":        "list_rewrite_rules",
		"description": "List the proxy match-and-replace rules.",
		"inputSchema": obj(props{}),
	},
	{
		"name":        "add_rewrite_rule",
		"description": "Add a match-and-replace rule applied to proxied requests. target is url, header, or body; pattern is a regular expression.",
		"inputSchema": obj(props{
			"target":      str("url | header | body"),
			"pattern":     str("Regular expression to match"),
			"replacement": str("Replacement string"),
		}, "target", "pattern"),
	},
	{
		"name":        "remove_rewrite_rule",
		"description": "Remove a match-and-replace rule by id.",
		"inputSchema": obj(props{"id": num("Rule id")}, "id"),
	},
	{
		"name":        "list_extensions",
		"description": "List registered extension webhooks.",
		"inputSchema": obj(props{}),
	},
	{
		"name":        "add_extension",
		"description": "Register an extension webhook. Each observed transaction is POSTed to url as JSON; the webhook may return {\"issues\":[...]} to add findings.",
		"inputSchema": obj(props{
			"url":  str("Webhook URL that receives transactions"),
			"name": str("Short name for the extension"),
		}, "url"),
	},
	{
		"name":        "remove_extension",
		"description": "Remove an extension webhook by id.",
		"inputSchema": obj(props{"id": num("Extension id")}, "id"),
	},
	{
		"name":        "list_websockets",
		"description": "List observed WebSocket messages proxied through Lanternfish (direction, opcode, text).",
		"inputSchema": obj(props{}),
	},
	{
		"name":        "list_interactions",
		"description": "List out-of-band (OAST) callbacks received, used to confirm blind vulnerabilities like blind SSRF.",
		"inputSchema": obj(props{}),
	},
	{
		"name":        "stats",
		"description": "Return quick counts: history size, issues, held requests.",
		"inputSchema": obj(props{}),
	},
}

type props map[string]any

func obj(p props, required ...string) map[string]any {
	m := map[string]any{"type": "object", "properties": map[string]any(p)}
	if len(required) > 0 {
		m["required"] = required
	}
	return m
}
func str(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }
func num(desc string) map[string]any { return map[string]any{"type": "integer", "description": desc} }
func boolean(desc string) map[string]any {
	return map[string]any{"type": "boolean", "description": desc}
}
func objFree(desc string) map[string]any {
	return map[string]any{"type": "object", "description": desc, "additionalProperties": map[string]any{"type": "string"}}
}
func arr(desc string) map[string]any {
	return map[string]any{"type": "array", "description": desc, "items": map[string]any{"type": "string"}}
}
