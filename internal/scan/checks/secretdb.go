package checks

import (
	"regexp"
	"strings"

	"lanternfish/internal/httpmsg"
	"lanternfish/internal/scan"
)

// regexPassive is a data-driven passive check: it flags the first match of a
// pattern in the response body (and, when wantHeaders, the response headers).
// Each entry in the tables below registers as its own check, mirroring how
// Burp tracks each secret/disclosure type as a distinct issue.
type regexPassive struct {
	id       string
	name     string
	cwe      string
	sev      scan.Severity
	conf     scan.Confidence
	re       *regexp.Regexp
	headers  bool
	redactIt bool
	// Optional overrides; when empty the secret-detection wording is used (so
	// the many secret rules stay concise). Fingerprint rules set these so they
	// do not inherit "this is a leaked secret" text.
	detail      string
	remediation string
}

func (r regexPassive) ID() string { return r.id }

func (r regexPassive) Passive(tx *httpmsg.Transaction) []*scan.Issue {
	if tx.Response == nil {
		return nil
	}
	hay := tx.Response.BodyString()
	if r.headers {
		var sb strings.Builder
		for k, vs := range tx.Response.Header {
			for _, v := range vs {
				sb.WriteString(k + ": " + v + "\n")
			}
		}
		hay = sb.String() + hay
	}
	m := r.re.FindString(hay)
	if m == "" {
		return nil
	}
	ev := m
	if r.redactIt {
		ev = redact(m)
	}
	detail := r.detail
	if detail == "" {
		detail = r.name + " was found in the response. Secrets must never be returned to clients."
	}
	rem := r.remediation
	if rem == "" {
		rem = "Remove the value from responses, rotate it, and keep secrets server-side."
	}
	return []*scan.Issue{{
		Check: r.id, Name: r.name, URL: tx.Request.AbsoluteURL().String(),
		Severity: r.sev, Confidence: r.conf,
		Detail:      detail,
		Remediation: rem,
		Evidence:    ev, CWE: orCWE(r.cwe, "CWE-200"),
	}}
}

func orCWE(c, d string) string {
	if c == "" {
		return d
	}
	return c
}

func rp(id, name, pattern string) regexPassive {
	return regexPassive{id: "secret-" + id, name: name, cwe: "CWE-798", sev: scan.SeverityHigh,
		conf: scan.ConfidenceFirm, re: regexp.MustCompile(pattern), redactIt: true}
}

// secretRules is a data-driven database of credential patterns (gitleaks-style,
// public prefixes). Kept specific to minimize false positives.
var secretRules = []regexPassive{
	rp("gitlab-pat", "GitLab personal access token", `glpat-[0-9A-Za-z_\-]{20}`),
	rp("stripe-secret", "Stripe secret key", `sk_live_[0-9a-zA-Z]{24,}`),
	rp("stripe-restricted", "Stripe restricted key", `rk_live_[0-9a-zA-Z]{24,}`),
	rp("stripe-pub", "Stripe publishable key", `pk_live_[0-9a-zA-Z]{24,}`),
	rp("twilio-sid", "Twilio account SID", `AC[0-9a-fA-F]{32}`),
	rp("twilio-key", "Twilio API key", `SK[0-9a-fA-F]{32}`),
	rp("sendgrid", "SendGrid API key", `SG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}`),
	rp("mailgun", "Mailgun API key", `key-[0-9a-zA-Z]{32}`),
	rp("mailchimp", "Mailchimp API key", `[0-9a-f]{32}-us[0-9]{1,2}`),
	rp("google-oauth", "Google OAuth client ID", `[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`),
	rp("gcp-sa", "GCP service account key", `"type":\s*"service_account"`),
	rp("firebase", "Firebase cloud messaging key", `AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}`),
	rp("npm", "npm access token", `npm_[0-9A-Za-z]{36}`),
	rp("pypi", "PyPI upload token", `pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}`),
	rp("square-access", "Square access token", `sq0atp-[0-9A-Za-z_\-]{22}`),
	rp("square-secret", "Square OAuth secret", `sq0csp-[0-9A-Za-z_\-]{43}`),
	rp("paypal-braintree", "PayPal/Braintree access token", `access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}`),
	rp("shopify-token", "Shopify access token", `shpat_[a-fA-F0-9]{32}`),
	rp("shopify-shared", "Shopify shared secret", `shpss_[a-fA-F0-9]{32}`),
	rp("shopify-private", "Shopify private app token", `shppa_[a-fA-F0-9]{32}`),
	rp("shopify-custom", "Shopify custom app token", `shpca_[a-fA-F0-9]{32}`),
	rp("facebook-token", "Facebook access token", `EAACEdEose0cBA[0-9A-Za-z]+`),
	rp("openai", "OpenAI API key", `sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}`),
	rp("anthropic", "Anthropic API key", `sk-ant-[A-Za-z0-9]{2,}-[A-Za-z0-9_\-]{90,}`),
	rp("digitalocean", "DigitalOcean token", `dop_v1_[a-f0-9]{64}`),
	rp("newrelic", "New Relic API key", `NRAK-[A-Z0-9]{27}`),
	rp("datadog", "Datadog API key", `(?i)dd[_-]?api[_-]?key["'\s:=]+[a-f0-9]{32}`),
	rp("doppler", "Doppler token", `dp\.pt\.[a-zA-Z0-9]{43}`),
	rp("grafana", "Grafana service account token", `glsa_[A-Za-z0-9]{32}_[a-f0-9]{8}`),
	rp("hashicorp-vault", "HashiCorp Vault token", `hvs\.[A-Za-z0-9_\-]{90,}`),
	rp("hubspot", "HubSpot API key", `pat-(?:na|eu)1-[0-9a-fA-F\-]{36}`),
	rp("intercom", "Intercom access token", `dG9r[A-Za-z0-9+/=]{50,}`),
	rp("linear", "Linear API key", `lin_api_[0-9A-Za-z]{40}`),
	rp("okta", "Okta API token", `00[A-Za-z0-9_\-]{40}`),
	rp("postman", "Postman API key", `PMAK-[a-f0-9]{24}-[a-f0-9]{34}`),
	rp("pulumi", "Pulumi access token", `pul-[a-f0-9]{40}`),
	rp("segment", "Segment public key", `sgp_[A-Za-z0-9]{32}`),
	rp("sentry", "Sentry auth token", `sntrys_[A-Za-z0-9_\-]{40,}`),
	rp("telegram-bot", "Telegram bot token", `[0-9]{8,10}:AA[0-9A-Za-z_\-]{33}`),
	rp("discord-bot", "Discord bot token", `[MNO][A-Za-z0-9_\-]{23}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27}`),
	rp("discord-webhook", "Discord webhook URL", `https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+`),
	rp("slack-webhook", "Slack webhook URL", `https://hooks\.slack\.com/services/T[0-9A-Za-z]+/B[0-9A-Za-z]+/[0-9A-Za-z]+`),
	rp("dropbox", "Dropbox access token", `sl\.[A-Za-z0-9_\-]{130,}`),
	rp("atlassian", "Atlassian API token", `ATATT3[A-Za-z0-9_\-]{180,}`),
	rp("bitbucket-cred", "Bitbucket client credentials", `(?i)bitbucket[_-]?(?:client[_-]?secret|key)["'\s:=]+[A-Za-z0-9]{32,}`),
	rp("algolia", "Algolia admin key", `(?i)algolia[_-]?(?:admin[_-]?)?key["'\s:=]+[A-Za-z0-9]{32}`),
	rp("cloudinary", "Cloudinary URL with secret", `cloudinary://[0-9]+:[A-Za-z0-9_\-]+@[A-Za-z0-9_\-]+`),
	rp("jdbc", "Database connection string with password", `(?i)jdbc:[a-z]+://[^\s"']*password=[^\s"'&]+`),
	rp("basic-auth-url", "Credentials embedded in URL", `[a-zA-Z][a-zA-Z0-9+.\-]*://[^/\s:@]+:[^/\s:@]+@[^/\s]+`),
	rp("pgp-private", "PGP private key block", `-----BEGIN PGP PRIVATE KEY BLOCK-----`),
	rp("ssh-dsa", "SSH DSA private key", `-----BEGIN DSA PRIVATE KEY-----`),
	rp("ssh-ec", "SSH EC private key", `-----BEGIN EC PRIVATE KEY-----`),
	rp("pkcs8-private", "PKCS8 private key", `-----BEGIN ENCRYPTED PRIVATE KEY-----`),
	rp("age-secret", "age encryption secret key", `AGE-SECRET-KEY-1[0-9A-Z]{58}`),
	rp("rapidapi", "RapidAPI key", `(?i)x-rapidapi-key["'\s:=]+[A-Za-z0-9]{40,}`),
	rp("twitter-bearer", "Twitter/X bearer token", `AAAAAAAAAAAAAAAAAAAAA[A-Za-z0-9%]{30,}`),
	rp("azure-storage", "Azure storage connection string", `DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{80,}`),
	rp("gcp-api-legacy", "Google (gcp) API key assignment", `(?i)(?:gcp|google)[_-]?api[_-]?key["'\s:=]+AIza[0-9A-Za-z_\-]{35}`),
}

// Secrets returns the data-driven secret-detection passive checks.
func Secrets() []scan.PassiveCheck {
	out := make([]scan.PassiveCheck, 0, len(secretRules))
	for _, r := range secretRules {
		out = append(out, r)
	}
	return out
}
