// Command lanternfish is a CLI-first web application security testing engine:
// an intercepting proxy, a request replayer, and an active/passive scanner.
//
// Lanternfish is an independent, clean-room tool. It implements publicly documented
// security-testing techniques and does not incorporate code from any
// proprietary product.
package main

import (
	"context"
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"lanternfish/internal/app"
	"lanternfish/internal/ca"
	"lanternfish/internal/client"
	"lanternfish/internal/httpmsg"
	"lanternfish/internal/kb"
	"lanternfish/internal/labs"
	"lanternfish/internal/oast"
	"lanternfish/internal/openapi"
	"lanternfish/internal/proxy"
	"lanternfish/internal/replay"
	"lanternfish/internal/report"
	"lanternfish/internal/scan"
	"lanternfish/internal/scan/checks"
	"lanternfish/internal/service"
	"lanternfish/internal/session"
)

// version is the build version. It defaults to "dev" for local builds and is
// stamped with the release tag at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		welcome()
		os.Exit(0)
	}
	switch os.Args[1] {
	case "proxy":
		cmdProxy(os.Args[2:])
	case "serve":
		cmdServe(os.Args[2:])
	case "gui":
		cmdGUI(os.Args[2:])
	case "mcp":
		cmdMCP(os.Args[2:])
	case "scan":
		cmdScan(os.Args[2:])
	case "explain":
		cmdExplain(os.Args[2:])
	case "bench":
		cmdBench(os.Args[2:])
	case "guide":
		cmdGuide(os.Args[2:])
	case "auto":
		cmdAuto(os.Args[2:])
	case "openapi":
		cmdOpenAPI(os.Args[2:])
	case "crawl":
		cmdCrawl(os.Args[2:])
	case "replay":
		cmdReplay(os.Args[2:])
	case "lab":
		cmdLab(os.Args[2:])
	case "learn":
		cmdLearn(os.Args[2:])
	case "collaborator":
		cmdCollaborator(os.Args[2:])
	case "ca":
		cmdCA(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Println("lanternfish", version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

// welcome is shown when lanternfish is run with no arguments: a friendly orientation
// for a newcomer, then the full usage.
func welcome() {
	fmt.Print(`Lanternfish ` + version + ` — a free web security testing toolkit.

New here? Start with these three:
  lanternfish lab                       launch a safe, legal practice range in your browser
  lanternfish guide http://127.0.0.1:9000/lab/xss?name=world
                                  a narrated, step-by-step first assessment
  lanternfish explain reflected-xss     learn what a finding means and how to fix it

Authorized testing only: use Lanternfish against systems you own or are explicitly
permitted to test. The lab above is yours and safe to attack.

`)
	usage()
}

func usage() {
	fmt.Fprint(os.Stderr, `lanternfish `+version+` — CLI web security testing engine

usage:
  lanternfish gui     [--proxy :8080]                         native desktop window (proxy + GUI)
  lanternfish serve   [--proxy :8080] [--ui 127.0.0.1:8081]  proxy + web GUI in the browser
  lanternfish mcp     [--proxy :8080] [--insecure]            MCP server over stdio for an LLM (+proxy)
  lanternfish proxy   [--addr :8080] [--insecure]             start intercepting proxy only
  lanternfish scan    <url> [--insecure] [--json] [--fast]    active+passive scan of a URL
  lanternfish auto    <url> [--browser] [--fast] [--json]     autopilot: crawl + audit everything, one command
  lanternfish openapi <spec> --base <url> [--auth-header H]   scan every endpoint in an OpenAPI/Swagger spec (great for APIs)
  lanternfish explain <check> | --list                        explain a finding: why it matters, how to confirm/fix
  lanternfish bench   <spec.json> [--fast] [--json]           score detection + false positives against a labeled benchmark
  lanternfish lab     [--addr 127.0.0.1:9000]                  practice range: legal, vulnerable challenges to learn on
  lanternfish learn   [challenge]                              the learning curriculum (ordered path; or one challenge's solution)
  lanternfish guide   <url>                                    narrated, step-by-step first assessment (great for learning)
  lanternfish crawl   <seed> [--audit] [--max N] [--json]     crawl a site; optionally audit findings
  lanternfish replay  <url> [--method GET] [--data ..]        send one request, show response
  lanternfish ca      [--dir DIR] [--out FILE]                print/export the local CA cert
  lanternfish collaborator [--addr :80] [--control :8085]     run a hosted out-of-band collaborator server
  lanternfish version

config dir defaults to the OS user config dir under "lanternfish".

Authorized testing only: use Lanternfish against systems you own or are explicitly
permitted to test.
`)
}

func configDir(override string) string {
	if override != "" {
		return override
	}
	base, err := os.UserConfigDir()
	if err != nil || base == "" {
		base, _ = os.Getwd()
	}
	return filepath.Join(base, "lanternfish")
}

// ---- proxy ----

func cmdProxy(args []string) {
	fs := newFlagSet("proxy")
	addr := fs.String("addr", "127.0.0.1:8080", "listen address (use 0.0.0.0:8080 to expose on the network — only if you must)")
	dir := fs.String("dir", "", "config dir (CA storage)")
	insecure := fs.Bool("insecure", false, "skip upstream TLS verification")
	passive := fs.Bool("passive", true, "run passive checks on observed traffic")
	autoAudit := fs.Bool("auto-audit", false, "actively scan in-scope traffic as it is observed (requires --scope)")
	scopeHost := fs.String("scope", "", "restrict interception/auto-audit to this host (repeatable, comma-separated)")
	mustParse(fs, args)

	authority, err := ca.Load(configDir(*dir))
	if err != nil {
		log.Fatalf("load CA: %v", err)
	}
	up := client.New(client.Options{InsecureSkipVerify: *insecure, FollowRedirects: false, Timeout: 30 * time.Second})
	logger := log.New(os.Stderr, "[lanternfish] ", 0)
	sess := session.New()
	for _, h := range strings.Split(*scopeHost, ",") {
		if h = strings.TrimSpace(h); h != "" {
			sess.Scope.Include(h, "")
		}
	}
	p := proxy.New(authority, up, sess, logger)

	if *autoAudit {
		svc := service.New(sess, *insecure)
		if err := svc.SetLiveAudit(true); err != nil {
			log.Fatalf("auto-audit: %v", err)
		}
		p.OnTransaction(func(tx *httpmsg.Transaction) { svc.MaybeAudit(tx) })
		logger.Printf("auto-audit: on; in-scope traffic will be actively scanned")
	}

	if *passive {
		eng := scan.NewEngine(checks.Passive(), nil)
		p.OnTransaction(func(tx *httpmsg.Transaction) {
			col := scan.NewCollector()
			eng.Passive(tx, col)
			for _, is := range col.Issues() {
				sess.AddIssues(is)
				logger.Printf("passive: [%s] %s (%s)", is.SeverityStr, is.Name, is.URL)
			}
		})
	}
	p.OnTransaction(func(tx *httpmsg.Transaction) {
		code := 0
		if tx.Response != nil {
			code = tx.Response.StatusCode
		}
		logger.Printf("%s %s -> %d", tx.Request.Method, tx.Request.AbsoluteURL(), code)
	})

	srv := p.Server(*addr)
	logger.Printf("listening on %s", *addr)
	logger.Printf("trust the CA: curl -x %s http://lanternfish.ca/cert -o lanternfish-ca.pem (or: lanternfish ca --out lanternfish-ca.pem)", *addr)

	go func() {
		stop := make(chan os.Signal, 1)
		signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
		<-stop
		logger.Printf("shutting down")
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	if err := srv.ListenAndServe(); err != nil && err.Error() != "http: Server closed" {
		log.Fatalf("proxy: %v", err)
	}
}

// ---- front-ends (serve / gui / mcp) ----

func cmdServe(args []string) {
	fs := newFlagSet("serve")
	proxyAddr := fs.String("proxy", "127.0.0.1:8080", "proxy listen address (loopback by default)")
	uiAddr := fs.String("ui", "127.0.0.1:8081", "web GUI/API listen address")
	dir := fs.String("dir", "", "config dir (CA storage)")
	insecure := fs.Bool("insecure", false, "skip upstream TLS verification")
	mustParse(fs, args)
	logger := log.New(os.Stderr, "[lanternfish] ", 0)
	if err := app.RunServe(app.Options{ProxyAddr: *proxyAddr, UIAddr: *uiAddr, ConfigDir: configDir(*dir), Insecure: *insecure}, logger); err != nil {
		log.Fatalf("serve: %v", err)
	}
}

func cmdGUI(args []string) {
	fs := newFlagSet("gui")
	proxyAddr := fs.String("proxy", "127.0.0.1:8080", "proxy listen address (loopback by default)")
	dir := fs.String("dir", "", "config dir (CA storage)")
	insecure := fs.Bool("insecure", false, "skip upstream TLS verification")
	mustParse(fs, args)
	runtime.LockOSThread() // the native window must own the main OS thread
	logger := log.New(os.Stderr, "[lanternfish] ", 0)
	if err := app.RunGUI(app.Options{ProxyAddr: *proxyAddr, ConfigDir: configDir(*dir), Insecure: *insecure}, logger); err != nil {
		log.Fatalf("gui: %v", err)
	}
}

func cmdMCP(args []string) {
	fs := newFlagSet("mcp")
	proxyAddr := fs.String("proxy", "", "optional proxy listen address (empty = no proxy)")
	dir := fs.String("dir", "", "config dir (CA storage)")
	insecure := fs.Bool("insecure", false, "skip upstream TLS verification")
	mustParse(fs, args)
	logger := log.New(os.Stderr, "[lanternfish] ", 0) // stdout is the MCP channel
	if err := app.RunMCP(app.Options{ProxyAddr: *proxyAddr, ConfigDir: configDir(*dir), Insecure: *insecure}, os.Stdin, os.Stdout, logger); err != nil {
		log.Fatalf("mcp: %v", err)
	}
}

// ---- scan ----

// parseOOB interprets the --oob flag value. It returns the provider name, an
// optional explicit interactsh server, and whether interactsh was selected.
func parseOOB(v string) (provider, server string, interactsh bool) {
	v = strings.TrimSpace(v)
	if strings.HasPrefix(v, "interactsh") {
		s := strings.TrimPrefix(strings.TrimPrefix(v, "interactsh"), ":")
		return "interactsh", s, true
	}
	return "local", "", false
}

// newInteractsh builds a public Interactsh client (auto-pick when server == "").
func newInteractsh(server string) (*oast.Interactsh, error) {
	if server == "" {
		return oast.NewInteractshAuto()
	}
	return oast.NewInteractsh(server)
}

func cmdScan(args []string) {
	fs := newFlagSet("scan")
	insecure := fs.Bool("insecure", false, "skip upstream TLS verification")
	asJSON := fs.Bool("json", false, "emit JSON report to stdout")
	conc := fs.Int("concurrency", 10, "max concurrent active probes")
	fast := fs.Bool("fast", false, "skip wait-heavy checks (out-of-band + time-based inference)")
	http3 := fs.Bool("http3", false, "speak HTTP/3 (QUIC) to the target")
	oob := fs.String("oob", "local", "out-of-band provider: local (loopback listener) or interactsh[:server] (public, zero-setup, works against remote targets)")
	yes := fs.Bool("yes", false, "skip the authorization confirmation (for non-interactive use)")
	failOn := fs.String("fail-on", "", "exit non-zero if an issue of this severity or higher is found (low|medium|high|critical)")
	pos := mustParse(fs, args)

	target := firstArg(pos)
	if target == "" {
		log.Fatal("scan: a target URL is required")
	}
	u, err := url.Parse(target)
	if err != nil || !u.IsAbs() {
		log.Fatalf("scan: invalid URL %q", target)
	}
	if !confirmAuthorized(target, *yes) {
		log.Fatal("scan: aborted — authorization not confirmed")
	}

	up := client.New(client.Options{InsecureSkipVerify: *insecure, FollowRedirects: false, HTTP3: *http3})
	active := checks.Active()
	if *fast {
		active = checks.ActiveFast()
	}
	eng := scan.NewEngine(checks.Passive(), active).WithRequestChecks(checks.Request())
	eng.Concurrency = *conc
	col := scan.NewCollector()
	started := time.Now()

	// Live progress to stderr (throttled) so a long scan is not a silent wait.
	// Skipped when emitting JSON to keep stdout/stderr clean for piping.
	if !*asJSON {
		var pmu sync.Mutex
		var last time.Time
		eng.OnProgress = func(done, total int) {
			pmu.Lock()
			defer pmu.Unlock()
			now := time.Now()
			if done < total && now.Sub(last) < 150*time.Millisecond {
				return
			}
			last = now
			fmt.Fprintf(os.Stderr, "\rscanning: %d/%d probes", done, total)
			if done >= total {
				fmt.Fprintln(os.Stderr)
			}
		}
	}

	ctx, cancel := signalContext()
	defer cancel()

	// Full mode attaches an out-of-band provider so blind checks (SSRF, blind
	// SQLi/cmdi, XXE) can observe callbacks. Fast mode skips it along with those
	// checks. "local" is a loopback listener (fine for a target that can reach
	// this machine, e.g. your own box); "interactsh" uses a public server so
	// callbacks fire from remote third-party targets with no setup.
	if !*fast {
		if prov, server, isIsh := parseOOB(*oob); isIsh {
			if c, err := newInteractsh(server); err == nil {
				ctx = scan.WithInteractor(ctx, c)
				log.Printf("out-of-band: using public Interactsh server %q (callbacks for blind findings route through it)", c.Server())
			} else {
				log.Printf("warning: interactsh unavailable (%v); blind checks limited", err)
			}
		} else {
			_ = prov
			o := oast.New("")
			if _, err := o.Start("127.0.0.1:0"); err == nil {
				defer o.Close()
				ctx = scan.WithInteractor(ctx, o)
			} else {
				log.Printf("warning: out-of-band listener unavailable, blind checks limited: %v", err)
			}
		}
	}

	base := &httpmsg.Request{
		Method: "GET", URL: u, Scheme: u.Scheme, Host: u.Host,
		Header: defaultHeaders(),
	}

	// Seed with a baseline fetch so passive checks see the landing response.
	if resp, err := up.Send(ctx, base); err == nil {
		eng.Passive(&httpmsg.Transaction{Request: base, Response: resp}, col)
	} else {
		log.Printf("warning: baseline request failed: %v", err)
	}

	eng.Audit(ctx, up, base, col)

	rep := report.Build(version, target, started, col.Issues())
	if *asJSON {
		if err := rep.WriteJSON(os.Stdout); err != nil {
			log.Fatalf("write json: %v", err)
		}
	} else {
		rep.WriteText(os.Stdout)
	}

	if *failOn != "" && exceeds(rep, *failOn) {
		os.Exit(1)
	}
}

// ---- auto (autopilot) ----

func cmdAuto(args []string) {
	fs := newFlagSet("auto")
	insecure := fs.Bool("insecure", false, "skip upstream TLS verification")
	asJSON := fs.Bool("json", false, "emit the full autopilot result as JSON")
	fast := fs.Bool("fast", false, "skip wait-heavy checks (out-of-band + time-based)")
	useBrowser := fs.Bool("browser", false, "also run a headless-browser crawl + DOM-XSS if a browser is present")
	maxPages := fs.Int("max", 100, "crawl page budget")
	depth := fs.Int("depth", 3, "crawl link depth")
	reportFile := fs.String("report", "", "write an HTML report of all issues to this file")
	authHeader := fs.String("auth-header", "", "an auth header to send on every request, e.g. \"Authorization: Bearer <token>\"")
	cookie := fs.String("cookie", "", "a Cookie header value to send for authenticated scanning")
	yes := fs.Bool("yes", false, "skip the authorization confirmation (for non-interactive use)")
	pos := mustParse(fs, args)

	target := firstArg(pos)
	if target == "" {
		log.Fatal("auto: a target URL is required")
	}
	if u, err := url.Parse(target); err != nil || !u.IsAbs() {
		log.Fatalf("auto: invalid URL %q", target)
	}
	if !confirmAuthorized(target, *yes) {
		log.Fatal("auto: aborted — authorization not confirmed")
	}

	sess := session.New()
	if *authHeader != "" {
		if name, val, ok := strings.Cut(*authHeader, ":"); ok {
			sess.SetAuthHeader(strings.TrimSpace(name), strings.TrimSpace(val))
		}
	}
	if *cookie != "" {
		sess.SetAuthHeader("Cookie", *cookie)
	}
	svc := service.New(sess, *insecure)
	ctx, cancel := signalContext()
	defer cancel()

	res, err := svc.Autopilot(ctx, service.AutopilotParams{
		Target: target, Fast: *fast, Browser: *useBrowser, MaxPages: *maxPages, MaxDepth: *depth,
	})
	if err != nil {
		log.Fatalf("auto: %v", err)
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(res)
	} else {
		fmt.Printf("Autopilot on %s (%s)\n\n", res.Target, res.Duration)
		for _, ph := range res.Phases {
			fmt.Printf("  [%-7s] %-14s %s\n", ph.Status, ph.Name, ph.Detail)
		}
		fmt.Printf("\ncrawled %d page(s), audited %d request(s)\n", res.PagesCrawled, res.RequestsAudited)
		rep := report.Build(version, target, time.Now(), res.Issues)
		fmt.Printf("\nfound %d issue(s):\n\n", len(res.Issues))
		rep.WriteText(os.Stdout)
	}

	if *reportFile != "" {
		if out, err := svc.ExportReport("html"); err != nil {
			log.Printf("report: %v", err)
		} else if err := os.WriteFile(*reportFile, []byte(out), 0o644); err != nil {
			log.Printf("report: write %s: %v", *reportFile, err)
		} else {
			fmt.Printf("\nwrote HTML report to %s\n", *reportFile)
		}
	}
}

// ---- explain (teach a finding) ----

func cmdExplain(args []string) {
	fs := newFlagSet("explain")
	list := fs.Bool("list", false, "list every finding that has an explanation")
	asJSON := fs.Bool("json", false, "emit the explanation as JSON")
	pos := mustParse(fs, args)

	if *list {
		keys := kb.Keys()
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Println(k)
		}
		return
	}
	check := firstArg(pos)
	if check == "" {
		log.Fatal("explain: a check id is required (see: lanternfish explain --list)")
	}
	e, ok := kb.Lookup(check)
	if !ok {
		log.Fatalf("explain: no explanation for %q (see: lanternfish explain --list)", check)
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(e)
		return
	}
	printExplain(os.Stdout, e)
}

// printExplain renders a KB entry as readable text.
func printExplain(w *os.File, e kb.Entry) {
	fmt.Fprintf(w, "%s\n\n", e.Title)
	section := func(label, body string) {
		if body != "" {
			fmt.Fprintf(w, "%s\n  %s\n\n", label, body)
		}
	}
	section("What it is", e.What)
	section("Why it matters", e.Why)
	section("How to confirm", e.Confirm)
	section("How to exploit (in a lab you own)", e.Exploit)
	section("How to fix", e.Fix)
	if len(e.Refs) > 0 {
		fmt.Fprintln(w, "Learn more (free)")
		for _, r := range e.Refs {
			fmt.Fprintf(w, "  %s\n", r)
		}
	}
}

// ---- crawl ----

func cmdCrawl(args []string) {
	fs := newFlagSet("crawl")
	insecure := fs.Bool("insecure", false, "skip upstream TLS verification")
	audit := fs.Bool("audit", false, "actively scan discovered requests")
	maxPages := fs.Int("max", 100, "max pages to crawl")
	depth := fs.Int("depth", 3, "max link depth")
	asJSON := fs.Bool("json", false, "emit JSON")
	pos := mustParse(fs, args)

	seed := firstArg(pos)
	if seed == "" {
		log.Fatal("crawl: a seed URL is required")
	}
	u, err := url.Parse(seed)
	if err != nil || !u.IsAbs() {
		log.Fatalf("crawl: invalid URL %q", seed)
	}
	sess := session.New()
	// Scope to the seed host so the crawl stays on-target.
	sess.Scope.Include(u.Hostname(), "")
	svc := service.New(sess, *insecure)

	ctx, cancel := signalContext()
	defer cancel()
	res := svc.Crawl(ctx, service.CrawlParams{Seeds: []string{seed}, MaxPages: *maxPages, MaxDepth: *depth, Audit: *audit})

	if *asJSON {
		out := map[string]any{"crawl": res, "issues": sess.Issues()}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
		return
	}
	fmt.Printf("crawled %s: visited %d page(s), found %d URL(s), %d form(s)\n", seed, res.PagesVisited, len(res.URLsFound), res.Forms)
	if *audit {
		rep := report.Build(version, seed, time.Now(), sess.Issues())
		fmt.Printf("\naudit found %d issue(s):\n\n", res.IssuesFound)
		rep.WriteText(os.Stdout)
	}
}

// ---- replay ----

func cmdReplay(args []string) {
	fs := newFlagSet("replay")
	method := fs.String("method", "GET", "HTTP method")
	data := fs.String("data", "", "request body (sets form content-type if not overridden)")
	insecure := fs.Bool("insecure", false, "skip upstream TLS verification")
	follow := fs.Bool("follow", false, "follow redirects")
	http3 := fs.Bool("http3", false, "speak HTTP/3 (QUIC) to the target")
	pos := mustParse(fs, args)

	target := firstArg(pos)
	if target == "" {
		log.Fatal("replay: a target URL is required")
	}
	u, err := url.Parse(target)
	if err != nil || !u.IsAbs() {
		log.Fatalf("replay: invalid URL %q", target)
	}

	hdr := defaultHeaders()
	var body []byte
	if *data != "" {
		body = []byte(*data)
		if hdr.Get("Content-Type") == "" {
			hdr.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}
	req := &httpmsg.Request{
		Method: strings.ToUpper(*method), URL: u, Scheme: u.Scheme, Host: u.Host,
		Header: hdr, Body: body,
	}

	up := client.New(client.Options{InsecureSkipVerify: *insecure, FollowRedirects: *follow, HTTP3: *http3})
	ctx, cancel := signalContext()
	defer cancel()

	resp, err := replay.Once(ctx, up, req)
	if err != nil {
		log.Fatalf("replay: %v", err)
	}
	fmt.Print(replay.Render(req, resp))
}

// ---- guide (narrated first assessment) ----

func cmdGuide(args []string) {
	fs := newFlagSet("guide")
	insecure := fs.Bool("insecure", false, "skip upstream TLS verification")
	noBrowser := fs.Bool("no-browser", false, "skip the headless-browser phase")
	yes := fs.Bool("yes", false, "skip the authorization confirmation (for non-interactive use)")
	pos := mustParse(fs, args)

	target := firstArg(pos)
	if target == "" {
		log.Fatal("guide: a target URL is required (try: lanternfish lab, then lanternfish guide http://127.0.0.1:9000/)")
	}
	if u, err := url.Parse(target); err != nil || !u.IsAbs() {
		log.Fatalf("guide: invalid URL %q", target)
	}

	step := func(n int, title, body string) {
		fmt.Printf("\n[%d/5] %s\n%s\n", n, title, indent(body))
	}
	fmt.Printf("Lanternfish guided assessment of %s\n", target)
	fmt.Println("This walks the basic flow a security analyst follows and explains each step.")

	if !confirmAuthorized(target, *yes) {
		fmt.Println("\nStopped. Run again once you have authorization (or use `lanternfish lab` to practice legally).")
		return
	}

	step(1, "Scope", "Decide exactly what you are allowed to test. Lanternfish will limit itself to the target's host so it does not wander onto systems you have no permission for. Scope is the single most important discipline in this work.")
	step(2, "Map", "Discover the application's pages, forms, and parameters by crawling from the start URL. You cannot test what you have not found, so mapping comes before attacking.")
	step(3, "Test", "Probe every input that mapping found with passive and active checks. Lanternfish runs this now; blind checks use an out-of-band listener. This can take a little while.")

	sess := session.New()
	svc := service.New(sess, *insecure)
	ctx, cancel := signalContext()
	defer cancel()
	res, err := svc.Autopilot(ctx, service.AutopilotParams{Target: target, Browser: !*noBrowser})
	if err != nil {
		log.Fatalf("guide: %v", err)
	}
	fmt.Printf("    ...done: crawled %d page(s), audited %d request(s) in %s.\n", res.PagesCrawled, res.RequestsAudited, res.Duration)

	step(4, "Review", "Read the findings worst-first and understand each one before acting. Confidence matters: 'certain' is confirmed, 'tentative' needs manual checking.")
	order := []string{"critical", "high", "medium", "low", "info"}
	fmt.Printf("    Found %d issue(s): ", len(res.Issues))
	parts := []string{}
	for _, s := range order {
		if n := res.Counts[s]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, s)) //nolint
		}
	}
	if len(parts) == 0 {
		fmt.Println("none.")
	} else {
		fmt.Println(strings.Join(parts, ", ") + ".")
	}
	if top := mostSevere(res.Issues); top != nil {
		fmt.Printf("\n    Most important finding: %s (%s) on %s\n", top.Name, top.SeverityStr, top.URL)
		if e, ok := kb.Lookup(top.Check); ok {
			fmt.Printf("%s\n", indent("Why it matters: "+e.Why))
			fmt.Printf("%s\n", indent("Confirm it yourself: "+e.Confirm))
			if len(e.Refs) > 0 {
				fmt.Printf("%s\n", indent("Learn more: "+e.Refs[0]))
			}
			fmt.Printf("%s\n", indent("Tip: run `lanternfish explain "+top.Check+"` for the full lesson."))
		}
	}

	reportPath := "lanternfish-report.html"
	if out, err := svc.ExportReport("html"); err == nil {
		if werr := os.WriteFile(reportPath, []byte(out), 0o644); werr == nil {
			step(5, "Report", "Write up what you found, how to reproduce it, and how to fix it. A clear report is what turns testing into something others can act on, and it is evidence of your skill. Lanternfish wrote one for you:")
			fmt.Printf("    %s\n", reportPath)
		}
	}
	fmt.Println("\nThat is the whole loop: scope, map, test, review, report. Practice it on `lanternfish lab` until it is second nature.")
}

func confirmAuthorized(target string, skip bool) bool {
	if skip || !isInteractive() {
		return true
	}
	fmt.Printf("\nYou are about to actively test %s.\nOnly continue if you own it or have explicit written permission. Continue? [y/N] ", target)
	var ans string
	_, _ = fmt.Scanln(&ans)
	ans = strings.ToLower(strings.TrimSpace(ans))
	return ans == "y" || ans == "yes"
}

func mostSevere(issues []*scan.Issue) *scan.Issue {
	var top *scan.Issue
	for _, is := range issues {
		if top == nil || is.Severity > top.Severity {
			top = is
		}
	}
	return top
}

func indent(s string) string {
	return "    " + strings.ReplaceAll(wrap(s, 76), "\n", "\n    ")
}

// wrap soft-wraps s at width columns on spaces.
func wrap(s string, width int) string {
	words := strings.Fields(s)
	var b strings.Builder
	col := 0
	for i, w := range words {
		if i > 0 {
			if col+1+len(w) > width {
				b.WriteByte('\n')
				col = 0
			} else {
				b.WriteByte(' ')
				col++
			}
		}
		b.WriteString(w)
		col += len(w)
	}
	return b.String()
}

// ---- openapi (spec-driven API scanning) ----

func cmdOpenAPI(args []string) {
	fs := newFlagSet("openapi")
	base := fs.String("base", "", "base URL the API is served at, e.g. https://api.example.com")
	authHeader := fs.String("auth-header", "", "an auth header to send, e.g. \"Authorization: Bearer <token>\"")
	cookie := fs.String("cookie", "", "a Cookie header value to send for authenticated scanning")
	insecure := fs.Bool("insecure", false, "skip upstream TLS verification")
	fast := fs.Bool("fast", false, "skip wait-heavy checks")
	asJSON := fs.Bool("json", false, "emit a JSON report")
	reportFile := fs.String("report", "", "write an HTML report of all issues to this file")
	yes := fs.Bool("yes", false, "skip the authorization confirmation")
	pos := mustParse(fs, args)

	specPath := firstArg(pos)
	if specPath == "" {
		log.Fatal("openapi: a spec file or URL is required")
	}
	if *base == "" {
		log.Fatal("openapi: --base <url> is required (where the API is served)")
	}
	if u, err := url.Parse(*base); err != nil || !u.IsAbs() {
		log.Fatalf("openapi: invalid --base %q", *base)
	}

	var data []byte
	if strings.HasPrefix(specPath, "http://") || strings.HasPrefix(specPath, "https://") {
		up := client.New(client.Options{InsecureSkipVerify: *insecure, FollowRedirects: true})
		su, _ := url.Parse(specPath)
		resp, err := up.Send(context.Background(), &httpmsg.Request{Method: "GET", URL: su, Scheme: su.Scheme, Host: su.Host, Header: defaultHeaders()})
		if err != nil {
			log.Fatalf("openapi: fetch spec: %v", err)
		}
		data = resp.Body
	} else {
		b, err := os.ReadFile(specPath)
		if err != nil {
			log.Fatalf("openapi: %v", err)
		}
		data = b
	}

	ops, err := openapi.Parse(data)
	if err != nil {
		log.Fatalf("openapi: %v", err)
	}
	if len(ops) == 0 {
		log.Fatal("openapi: no operations found in the spec")
	}
	if !confirmAuthorized(*base, *yes) {
		log.Fatal("openapi: aborted — authorization not confirmed")
	}

	sess := session.New()
	if hu, err := url.Parse(*base); err == nil {
		sess.Scope.Include(hu.Hostname(), "")
	}
	if *authHeader != "" {
		if name, val, ok := strings.Cut(*authHeader, ":"); ok {
			sess.SetAuthHeader(strings.TrimSpace(name), strings.TrimSpace(val))
		}
	}
	if *cookie != "" {
		sess.SetAuthHeader("Cookie", *cookie)
	}
	svc := service.New(sess, *insecure)
	if !*fast {
		svc.EnsureOAST()
	}
	ctx, cancel := signalContext()
	defer cancel()

	baseTrim := strings.TrimRight(*base, "/")
	start := time.Now()
	total := 0
	for _, op := range ops {
		if ctx.Err() != nil {
			break
		}
		u, err := url.Parse(baseTrim + op.Path)
		if err != nil {
			continue
		}
		if len(op.Query) > 0 {
			q := u.Query()
			for k, v := range op.Query {
				q.Set(k, v)
			}
			u.RawQuery = q.Encode()
		}
		h := defaultHeaders()
		for k, v := range op.Headers {
			h.Set(k, v)
		}
		if op.ContentType != "" {
			h.Set("Content-Type", op.ContentType)
		}
		req := &httpmsg.Request{Method: op.Method, URL: u, Scheme: u.Scheme, Host: u.Host, Header: h, Body: []byte(op.Body)}
		if _, err := svc.ScanRequestMode(ctx, req, *fast); err == nil {
			total++
		}
	}

	issues := sess.Issues()
	if *asJSON {
		rep := report.Build(version, baseTrim, start, issues)
		_ = rep.WriteJSON(os.Stdout)
	} else {
		fmt.Printf("Scanned %d of %d documented operation(s) from the spec in %s.\n\n",
			total, len(ops), time.Since(start).Round(time.Millisecond))
		rep := report.Build(version, baseTrim, start, issues)
		fmt.Printf("Found %d issue(s):\n\n", len(issues))
		rep.WriteText(os.Stdout)
	}
	if *reportFile != "" {
		if out, err := svc.ExportReport("html"); err == nil {
			_ = os.WriteFile(*reportFile, []byte(out), 0o644)
			fmt.Printf("\nwrote HTML report to %s\n", *reportFile)
		}
	}
}

// ---- learn (curriculum) ----

func cmdLearn(args []string) {
	fs := newFlagSet("learn")
	pos := mustParse(fs, args)

	// Order the challenges easy -> medium -> hard as a learning path.
	rank := map[string]int{"easy": 0, "medium": 1, "hard": 2}
	ordered := append([]labs.Challenge(nil), labs.Challenges...)
	sort.SliceStable(ordered, func(i, j int) bool { return rank[ordered[i].Difficulty] < rank[ordered[j].Difficulty] })

	if id := firstArg(pos); id != "" {
		for _, c := range ordered {
			if c.ID == id {
				fmt.Printf("%s  [%s · %s]\n\n", c.Title, c.OWASP, c.Difficulty)
				fmt.Printf("Goal\n  %s\n\n", wrap(c.Objective, 76))
				fmt.Printf("Brief\n%s\n\n", indent(c.Brief))
				fmt.Printf("Solution\n%s\n\n", indent(c.Solution))
				fmt.Printf("Learn more (free)\n  %s\n", c.Resource)
				return
			}
		}
		log.Fatalf("learn: no challenge %q (run `lanternfish learn` for the list)", id)
	}

	fmt.Println("Lanternfish learning path — work top to bottom.")
	fmt.Println("Start the range with `lanternfish lab`, solve each in your browser, then")
	fmt.Println("`lanternfish learn <id>` for the worked solution.")
	fmt.Println()
	for i, c := range ordered {
		fmt.Printf("%2d. %-28s %s\n", i+1, c.Title+" ("+c.ID+")", c.OWASP)
		fmt.Printf("    %-28s %s\n", "["+c.Difficulty+"]", oneLineWrap(c.Objective))
	}
	fmt.Printf("\n%d challenges covering the OWASP Top 10. Free lessons linked per topic.\n", len(ordered))
}

// oneLineWrap trims an objective to a single readable line.
func oneLineWrap(s string) string {
	if len(s) > 90 {
		return s[:87] + "..."
	}
	return s
}

// ---- lab (practice range) ----

func cmdLab(args []string) {
	fs := newFlagSet("lab")
	addr := fs.String("addr", "127.0.0.1:9000", "loopback listen address")
	mustParse(fs, args)
	if !strings.HasPrefix(*addr, "127.0.0.1") && !strings.HasPrefix(*addr, "localhost") {
		log.Fatal("lab: refusing to bind the deliberately-vulnerable practice range to a non-loopback address")
	}
	base := "http://" + *addr
	fmt.Printf("Lanternfish Labs (practice range) on %s/\n", base)
	fmt.Println("Open it in your browser, or point Lanternfish at the challenges. Loopback only.")
	fmt.Printf("Try: lanternfish auto %s/lab/xss?name=world\n", base)
	srv := &http.Server{Addr: *addr, Handler: labs.Handler(base)}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("lab: %v", err)
	}
}

// ---- collaborator (hosted out-of-band server) ----

func cmdCollaborator(args []string) {
	fs := newFlagSet("collaborator")
	addr := fs.String("addr", ":80", "interaction listener address (targets call back here)")
	control := fs.String("control", ":8085", "control API address (scanners poll here)")
	domain := fs.String("domain", "", "public base URL to advertise, e.g. http://oast.example.com (default: inferred)")
	secret := fs.String("secret", "", "shared secret required to poll the control API (default: random)")
	dns := fs.Bool("dns", false, "also run the DNS collaborator")
	dnsAddr := fs.String("dns-addr", ":53", "DNS listen address")
	dnsZone := fs.String("dns-zone", "", "DNS zone delegated to this host, e.g. oast.example.com")
	dnsIP := fs.String("dns-ip", "", "A record to answer with (default: resolver's view)")
	mustParse(fs, args)

	sec := *secret
	if sec == "" {
		sec = randomToken()
	}
	srv := oast.New(*domain)
	base, err := srv.Start(*addr)
	if err != nil {
		log.Fatalf("collaborator: interaction listener: %v", err)
	}
	ctrlAddr, err := srv.ServeControl(*control, sec)
	if err != nil {
		log.Fatalf("collaborator: control API: %v", err)
	}
	fmt.Printf("Lanternfish collaborator running.\n\n")
	fmt.Printf("  interaction base : %s\n", base)
	fmt.Printf("  control API      : http://%s\n", ctrlAddr)
	fmt.Printf("  secret           : %s\n", sec)
	if *dns {
		if bound, err := srv.StartDNS(*dnsAddr, *dnsZone, *dnsIP); err != nil {
			log.Printf("DNS collaborator unavailable (%s): %v", *dnsAddr, err)
		} else {
			fmt.Printf("  DNS collaborator : %s (zone %s)\n", bound, *dnsZone)
		}
	}
	fmt.Printf("\nPoint a scanner at it with:\n")
	fmt.Printf("  set LANTERNFISH_COLLABORATOR_URL=%s\n", chooseAdvertised(*domain, base))
	fmt.Printf("  set LANTERNFISH_COLLABORATOR_CONTROL=http://<this-host>%s\n", *control)
	fmt.Printf("  set LANTERNFISH_COLLABORATOR_SECRET=%s\n", sec)
	fmt.Printf("\nExpose --addr publicly so targets can reach it. Authorized testing only.\n")

	ctx, cancel := signalContext()
	defer cancel()
	<-ctx.Done()
	_ = srv.Close()
}

func chooseAdvertised(domain, base string) string {
	if domain != "" {
		return domain
	}
	return base
}

func randomToken() string {
	b := make([]byte, 16)
	if _, err := crand.Read(b); err != nil {
		return "change-me"
	}
	return hex.EncodeToString(b)
}

// ---- ca ----

func cmdCA(args []string) {
	fs := newFlagSet("ca")
	dir := fs.String("dir", "", "config dir (CA storage)")
	out := fs.String("out", "", "write the CA cert to this file instead of stdout")
	mustParse(fs, args)

	authority, err := ca.Load(configDir(*dir))
	if err != nil {
		log.Fatalf("load CA: %v", err)
	}
	if *out != "" {
		if err := os.WriteFile(*out, authority.CertPEM(), 0o644); err != nil {
			log.Fatalf("write cert: %v", err)
		}
		fmt.Printf("wrote CA certificate to %s\n", *out)
		return
	}
	os.Stdout.Write(authority.CertPEM())
}

// ---- helpers ----

func defaultHeaders() http.Header {
	h := http.Header{}
	h.Set("User-Agent", "lanternfish/"+version)
	h.Set("Accept", "*/*")
	return h
}

func exceeds(r *report.Report, threshold string) bool {
	rank := map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
	t, ok := rank[strings.ToLower(threshold)]
	if !ok {
		return false
	}
	for _, is := range r.Issues {
		if rank[is.SeverityStr] >= t {
			return true
		}
	}
	return false
}

// isInteractive reports whether stdin is a terminal (so prompting makes sense).
// Cross-platform: works the same on Windows and Linux via the char-device bit.
func isInteractive() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func signalContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		stop := make(chan os.Signal, 1)
		signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
		<-stop
		cancel()
	}()
	return ctx, cancel
}
