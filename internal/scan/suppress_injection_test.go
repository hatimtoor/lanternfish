package scan

import (
	"strings"
	"testing"
)

// On a SQL backend, a boolean differential ("' or '1'='1") also satisfies the
// XPath/LDAP boolean checks, which then mislabel the bug. The confirmed SQLi
// finding must win for that param, while an error-based XPath finding on a
// different param (and the SQLi itself) must survive.
func TestSuppressAmbiguousInjectionYieldsToSQLi(t *testing.T) {
	c := NewCollector()
	c.Add(&Issue{Check: "sqli-boolean-blind", Name: "SQL injection (boolean-based blind)", URL: "http://x/s?q=", Param: "q", Severity: SeverityHigh})
	c.Add(&Issue{Check: "xpath-injection", Name: "XPath injection (boolean)", URL: "http://x/s?q=", Param: "q", Severity: SeverityHigh})
	c.Add(&Issue{Check: "ldap-injection", Name: "LDAP injection (boolean)", URL: "http://x/s?q=", Param: "q", Severity: SeverityHigh})
	// Error-based XPath on a different param: distinct, must NOT be suppressed.
	c.Add(&Issue{Check: "xpath-injection", Name: "XPath injection", URL: "http://y/d?p=", Param: "p", Severity: SeverityHigh})

	got := c.Issues()
	var sawSQLi, sawXPathErr bool
	for _, is := range got {
		if (is.Check == "xpath-injection" || is.Check == "ldap-injection") && strings.Contains(is.Name, "(boolean)") {
			t.Errorf("ambiguous boolean finding should have been suppressed: %s / %s", is.Check, is.Name)
		}
		if is.Check == "sqli-boolean-blind" {
			sawSQLi = true
		}
		if is.Check == "xpath-injection" && is.Name == "XPath injection" {
			sawXPathErr = true
		}
	}
	if !sawSQLi {
		t.Error("the SQLi finding must survive")
	}
	if !sawXPathErr {
		t.Error("an error-based XPath finding on a different param must survive")
	}
	if len(got) != 2 {
		t.Errorf("expected 2 surviving findings (SQLi + error-based XPath), got %d", len(got))
	}
}

// With no SQLi finding present, a boolean XPath finding stands on its own.
func TestSuppressAmbiguousInjectionNoopWithoutSQLi(t *testing.T) {
	c := NewCollector()
	c.Add(&Issue{Check: "xpath-injection", Name: "XPath injection (boolean)", URL: "http://x/s?q=", Param: "q", Severity: SeverityHigh})
	if len(c.Issues()) != 1 {
		t.Error("a lone boolean XPath finding must be kept when no SQLi exists")
	}
}
