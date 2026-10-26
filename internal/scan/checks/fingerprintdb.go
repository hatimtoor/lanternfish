package checks

import (
	"regexp"

	"lanternfish/internal/scan"
)

// fp builds an informational technology-fingerprint passive check. Matches are
// checked against both response headers and body.
func fp(id, name, pattern string) regexPassive {
	return regexPassive{
		id: "fingerprint-" + id, name: "Technology detected: " + name, cwe: "CWE-200",
		sev: scan.SeverityInfo, conf: scan.ConfidenceFirm,
		re: regexp.MustCompile(pattern), headers: true, redactIt: false,
		detail:      name + " was identified from the response. This is informational — it helps map the stack and look up version-specific advisories.",
		remediation: "Minimise technology/version disclosure where practical (generic Server/X-Powered-By headers) and keep the component patched.",
	}
}

// fingerprintRules detects common web technologies. Informational: useful for
// attack surface mapping and pairing with version-specific advisories.
var fingerprintRules = []regexPassive{
	fp("wordpress", "WordPress", `(?i)/wp-(content|includes)/|<meta name="generator" content="WordPress`),
	fp("drupal", "Drupal", `(?i)Drupal\.settings|X-Generator: Drupal|/sites/(default|all)/`),
	fp("joomla", "Joomla", `(?i)/media/jui/|com_content|Joomla!`),
	fp("magento", "Magento", `(?i)Mage\.Cookies|/skin/frontend/|/static/version`),
	fp("laravel", "Laravel", `(?i)laravel_session|XSRF-TOKEN`),
	fp("django", "Django", `(?i)csrfmiddlewaretoken|__admin_media_prefix__`),
	fp("rails", "Ruby on Rails", `(?i)csrf-param|_session_id|X-Runtime`),
	fp("express", "Express.js", `(?i)X-Powered-By: Express`),
	fp("aspnet", "ASP.NET", `(?i)X-AspNet-Version|ASP\.NET_SessionId|__VIEWSTATE`),
	fp("springboot", "Spring Boot", `(?i)Whitelabel Error Page|X-Application-Context`),
	fp("flask", "Flask / Werkzeug", `(?i)Werkzeug/|<title>Werkzeug Debugger`),
	fp("tomcat", "Apache Tomcat", `(?i)Apache Tomcat|Server: Apache-Coyote`),
	fp("jetty", "Eclipse Jetty", `(?i)Server: Jetty`),
	fp("nginx", "nginx", `(?i)Server: nginx`),
	fp("apache", "Apache httpd", `(?i)Server: Apache`),
	fp("iis", "Microsoft IIS", `(?i)Server: Microsoft-IIS`),
	fp("jenkins", "Jenkins", `(?i)X-Jenkins:|<title>Dashboard \[Jenkins\]`),
	fp("gitlab", "GitLab", `(?i)gon\.gitlab|<meta content="GitLab`),
	fp("grafana", "Grafana", `(?i)grafanaBootData|Grafana v`),
	fp("kibana", "Kibana", `(?i)kbn-name:|kbn-version:`),
	fp("phpmyadmin", "phpMyAdmin", `(?i)phpMyAdmin|pma_`),
	fp("cloudflare", "Cloudflare", `(?i)Server: cloudflare|cf-ray:`),
	fp("varnish", "Varnish cache", `(?i)X-Varnish:|Via:.*varnish`),
	fp("nextjs", "Next.js", `(?i)/_next/static/|__NEXT_DATA__`),
	fp("nuxt", "Nuxt.js", `(?i)__NUXT__|/_nuxt/`),
	fp("vue", "Vue.js", `(?i)data-v-[0-9a-f]{8}|vue(?:\.min)?\.js`),
	fp("react", "React", `(?i)data-reactroot|react(?:-dom)?(?:\.min)?\.js`),
	fp("php", "PHP", `(?i)X-Powered-By: PHP|PHPSESSID`),
	fp("coldfusion", "Adobe ColdFusion", `(?i)CFID=|CFTOKEN=|/CFIDE/`),
	fp("weblogic", "Oracle WebLogic", `(?i)WebLogic|/console/login/LoginForm\.jsp`),
}

// Fingerprints returns the technology-detection passive checks.
func Fingerprints() []scan.PassiveCheck {
	out := make([]scan.PassiveCheck, 0, len(fingerprintRules))
	for _, r := range fingerprintRules {
		out = append(out, r)
	}
	return out
}
