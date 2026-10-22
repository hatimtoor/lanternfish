package checks

import (
	"context"
	"fmt"
	"strings"

	"lanternfish/internal/httpmsg"
	"lanternfish/internal/scan"
)

// SSTI detects server-side template injection by injecting a template
// expression that evaluates a multiplication and looking for the computed
// product in the response, bracketed by a unique marker so arithmetic in the
// original page cannot cause a false positive. Techniques are public.
type SSTI struct{}

func (SSTI) ID() string { return "ssti" }

func (SSTI) Active(ctx context.Context, s scan.Sender, base *httpmsg.Request, p scan.InsertionPoint) []*scan.Issue {
	tag := randMarker("ar")
	// 7*7 = 49; distinct factors keep it unambiguous across engines.
	a, b := 73, 79
	product := a * b // 5767
	want := fmt.Sprintf("%s%d%s", tag, product, tag)

	payloads := []string{
		fmt.Sprintf("%s${%d*%d}%s", tag, a, b, tag),       // JSP EL / Spring
		fmt.Sprintf("%s{{%d*%d}}%s", tag, a, b, tag),      // Jinja2 / Twig / Angular
		fmt.Sprintf("%s#{%d*%d}%s", tag, a, b, tag),       // Ruby / Thymeleaf
		fmt.Sprintf("%s<%%= %d*%d %%>%s", tag, a, b, tag), // ERB
	}
	for _, pl := range payloads {
		if ctx.Err() != nil {
			return nil
		}
		resp, err := s.Send(ctx, p.Mutate(pl))
		if err != nil || resp == nil {
			continue
		}
		if strings.Contains(resp.BodyString(), want) {
			return []*scan.Issue{{
				Check: "ssti", Name: "Server-side template injection",
				URL: base.AbsoluteURL().String(), Param: p.Name,
				Severity: scan.SeverityHigh, Confidence: scan.ConfidenceFirm,
				Detail:      fmt.Sprintf("Parameter %q evaluated a template expression: the injected %q produced %q in the response, indicating the value is rendered by a server-side template engine.", p.Name, pl, want),
				Remediation: "Do not place user input into template source. Pass it as sandboxed data/parameters to the template instead.",
				Evidence:    excerpt(resp.BodyString(), want),
				CWE:         "CWE-1336",
			}}
		}
	}
	return nil
}
