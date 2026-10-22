// Package app wires the Lanternfish engine into runnable front-ends (native GUI,
// browser GUI, MCP) so both the CLI and the standalone app binary share one
// implementation.
package app

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"lanternfish/internal/api"
	"lanternfish/internal/ca"
	"lanternfish/internal/client"
	"lanternfish/internal/desktop"
	"lanternfish/internal/ext"
	"lanternfish/internal/httpmsg"
	"lanternfish/internal/mcp"
	"lanternfish/internal/oast"
	"lanternfish/internal/proxy"
	"lanternfish/internal/scan"
	"lanternfish/internal/scan/checks"
	"lanternfish/internal/service"
	"lanternfish/internal/session"
)

// Options configures a front-end run.
type Options struct {
	ProxyAddr string
	UIAddr    string
	ConfigDir string
	Insecure  bool
}

// builtinExtensions returns the native extensions to load. The sample is only
// loaded when LANTERNFISH_EXT_DEMO is set, so default runs are unchanged. Add your
// own extensions here (or behind their own env flags).
func builtinExtensions() []ext.NativeExtension {
	var out []ext.NativeExtension
	if os.Getenv("LANTERNFISH_EXT_DEMO") != "" {
		out = append(out, ext.SampleExtension{})
	}
	return out
}

// Stack holds the shared engine pieces.
type Stack struct {
	Sess *session.Session
	Prox *proxy.Proxy
	Svc  *service.Service
	Auth *ca.Authority
}

// BuildStack assembles the engine and wires passive scanning onto proxy traffic.
func BuildStack(dir string, insecure bool, logger *log.Logger) (*Stack, error) {
	authority, err := ca.Load(dir)
	if err != nil {
		return nil, err
	}
	sess := session.New()
	up := client.New(client.Options{InsecureSkipVerify: insecure, FollowRedirects: false, Timeout: 30 * time.Second})
	p := proxy.New(authority, up, sess, logger)

	eng := scan.NewEngine(checks.Passive(), nil)
	p.OnTransaction(func(tx *httpmsg.Transaction) {
		col := scan.NewCollector()
		eng.Passive(tx, col)
		sess.AddIssues(col.Issues()...)
	})

	svc := service.New(sess, insecure)

	// Extensions: external webhooks that receive each transaction.
	extMgr := ext.New(sess)
	svc.Ext = extMgr
	p.OnTransaction(func(tx *httpmsg.Transaction) { extMgr.Dispatch(tx) })

	// Live auto-audit: when enabled (and a scope is set), actively scan each
	// in-scope request seen through the proxy, so browsing drives the scanner.
	p.OnTransaction(func(tx *httpmsg.Transaction) { svc.MaybeAudit(tx) })

	// Native extensions: register any in-process extensions, then wire their
	// proxy request/response editors onto the proxy. (Scan checks are applied
	// to the engines by svc.UseExtension.)
	for _, e := range builtinExtensions() {
		svc.UseExtension(e)
	}
	for _, f := range svc.Reg.RequestEditors() {
		p.AddRequestEditor(f)
	}
	for _, f := range svc.Reg.ResponseEditors() {
		p.AddResponseEditor(f)
	}

	// Out-of-band provider: prefer a hosted collaborator when configured
	// (LANTERNFISH_COLLABORATOR_URL/_CONTROL/_SECRET), otherwise a local listener.
	var oastSrv *oast.Server
	if r, ok := oast.RemoteFromEnv(); ok {
		svc.SetInteractor(r)
		logger.Printf("using hosted collaborator at %s", os.Getenv("LANTERNFISH_COLLABORATOR_URL"))
	} else {
		oastSrv = oast.New("")
		if base, err := oastSrv.Start("127.0.0.1:0"); err == nil {
			svc.OAST = oastSrv
			svc.SetInteractor(oastSrv)
			logger.Printf("out-of-band listener on %s", base)
		} else {
			logger.Printf("out-of-band listener unavailable: %v", err)
		}
	}
	// Optional DNS collaborator: set LANTERNFISH_OAST_DOMAIN to a zone delegated to
	// this host. LANTERNFISH_OAST_DNS_ADDR (default :53) and LANTERNFISH_OAST_IP tune it.
	if domain := os.Getenv("LANTERNFISH_OAST_DOMAIN"); domain != "" && oastSrv != nil {
		dnsAddr := os.Getenv("LANTERNFISH_OAST_DNS_ADDR")
		if dnsAddr == "" {
			dnsAddr = ":53"
		}
		if bound, err := oastSrv.StartDNS(dnsAddr, domain, os.Getenv("LANTERNFISH_OAST_IP")); err != nil {
			logger.Printf("DNS collaborator unavailable (%s): %v", dnsAddr, err)
		} else {
			logger.Printf("DNS collaborator on %s for zone %s", bound, domain)
		}
	}

	return &Stack{Sess: sess, Prox: p, Svc: svc, Auth: authority}, nil
}

// StartProxy launches the proxy listener in the background.
func (st *Stack) StartProxy(addr string, logger *log.Logger) {
	srv := st.Prox.Server(addr)
	go func() {
		logger.Printf("proxy listening on %s", addr)
		if err := srv.ListenAndServe(); err != nil && err.Error() != "http: Server closed" {
			logger.Printf("proxy error: %v", err)
		}
	}()
}

// startUI binds the web API/GUI to addr ("" = ephemeral loopback) and returns
// the URL it is serving on.
func (st *Stack) startUI(addr string, logger *log.Logger) (string, error) {
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", err
	}
	srv := &http.Server{Handler: api.New(st.Svc).Handler()}
	go func() {
		if err := srv.Serve(ln); err != nil && err.Error() != "http: Server closed" {
			logger.Printf("ui server: %v", err)
		}
	}()
	return fmt.Sprintf("http://%s/", ln.Addr().String()), nil
}

// RunServe starts the proxy and serves the GUI in the browser (blocking).
func RunServe(opt Options, logger *log.Logger) error {
	st, err := BuildStack(opt.ConfigDir, opt.Insecure, logger)
	if err != nil {
		return err
	}
	st.StartProxy(opt.ProxyAddr, logger)
	ui := opt.UIAddr
	if ui == "" {
		ui = "127.0.0.1:8081"
	}
	url, err := st.startUI(ui, logger)
	if err != nil {
		return err
	}
	logger.Printf("web GUI on %s", url)
	logger.Printf("set your browser proxy to %s; trust the CA via: lanternfish ca --out lanternfish-ca.pem", opt.ProxyAddr)
	select {} // serve until interrupted
}

// RunGUI starts the proxy + engine and opens a standalone native window.
// It must run on the main OS thread (the caller locks it).
func RunGUI(opt Options, logger *log.Logger) error {
	st, err := BuildStack(opt.ConfigDir, opt.Insecure, logger)
	if err != nil {
		return err
	}
	st.StartProxy(opt.ProxyAddr, logger)
	url, err := st.startUI("", logger)
	if err != nil {
		return err
	}
	logger.Printf("proxy on %s; trust the CA via: lanternfish ca --out lanternfish-ca.pem", opt.ProxyAddr)
	logger.Printf("opening standalone window at %s", url)

	// Preferred: a true native WebView2 window owned by this process.
	if err := desktop.RunNative(url, "Lanternfish"); err == nil {
		return nil
	} else {
		logger.Printf("native window unavailable (%v); falling back to app window", err)
	}
	// Fallback: chromeless app window via an installed browser runtime.
	profile := filepath.Join(opt.ConfigDir, "webview-profile")
	proc, windowed, lerr := desktop.Launch(url, profile)
	if lerr != nil {
		return lerr
	}
	if windowed && proc != nil {
		_, _ = proc.Wait()
		return nil
	}
	select {} // browser fallback: keep serving
}

// RunMCP serves the MCP protocol over the given streams, with an optional proxy.
func RunMCP(opt Options, in io.Reader, out io.Writer, logger *log.Logger) error {
	st, err := BuildStack(opt.ConfigDir, opt.Insecure, logger)
	if err != nil {
		return err
	}
	if opt.ProxyAddr != "" {
		st.StartProxy(opt.ProxyAddr, logger)
	}
	return mcp.New(st.Svc, in, out).Serve(context.Background())
}
