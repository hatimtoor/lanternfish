package checks

import (
	"context"
	"strings"

	"lanternfish/internal/httpmsg"
	"lanternfish/internal/scan"
)

// GraphQLIntrospection is a request-level check that sends an introspection
// query and reports if the endpoint answers with its schema — a common
// information-disclosure misconfiguration on production GraphQL APIs.
type GraphQLIntrospection struct{}

func (GraphQLIntrospection) ID() string { return "graphql-introspection" }

const introspectionQuery = `{"query":"{__schema{queryType{name} types{name kind}}}"}`

func (GraphQLIntrospection) Request(ctx context.Context, s scan.Sender, base *httpmsg.Request) []*scan.Issue {
	// Only probe plausible GraphQL endpoints to limit noise.
	path := strings.ToLower(base.AbsoluteURL().Path)
	if !strings.Contains(path, "graphql") && !strings.Contains(path, "/gql") {
		return nil
	}
	probe := base.Clone()
	probe.Method = "POST"
	probe.Header.Set("Content-Type", "application/json")
	probe.Body = []byte(introspectionQuery)
	resp, err := s.Send(ctx, probe)
	if err != nil || resp == nil {
		return nil
	}
	body := resp.BodyString()
	url := base.AbsoluteURL().String()
	var issues []*scan.Issue
	if strings.Contains(body, `"__schema"`) || (strings.Contains(body, `"queryType"`) && strings.Contains(body, `"types"`)) {
		issues = append(issues, &scan.Issue{
			Check: "graphql-introspection", Name: "GraphQL introspection enabled",
			URL:      url,
			Severity: scan.SeverityLow, Confidence: scan.ConfidenceFirm,
			Detail:      "The GraphQL endpoint answered an introspection query with its schema, exposing all types, queries, and mutations to attackers for API mapping.",
			Remediation: "Disable introspection in production, or restrict it to authenticated/privileged clients.",
			Evidence:    excerpt(body, "__schema"), CWE: "CWE-200",
		})
	}

	// Field suggestions leak the schema even when introspection is disabled:
	// a misspelled field provokes a "Did you mean ..." hint naming the real one.
	sProbe := base.Clone()
	sProbe.Method = "POST"
	sProbe.Header.Set("Content-Type", "application/json")
	sProbe.Body = []byte(`{"query":"{ __typenam }"}`)
	if r, err := s.Send(ctx, sProbe); err == nil && r != nil {
		sb := r.BodyString()
		if strings.Contains(sb, "Did you mean") && strings.Contains(sb, "__typename") {
			issues = append(issues, &scan.Issue{
				Check: "graphql-suggestions", Name: "GraphQL field suggestions enabled",
				URL:      url,
				Severity: scan.SeverityLow, Confidence: scan.ConfidenceFirm,
				Detail:      "The endpoint returned a \"Did you mean\" field suggestion for a misspelled field, leaking schema details even if introspection is disabled — an attacker can reconstruct the schema field by field.",
				Remediation: "Disable field suggestions in production (e.g. a validation rule that strips 'Did you mean' hints).",
				Evidence:    excerpt(sb, "Did you mean"), CWE: "CWE-200",
			})
		}
	}

	// Query batching lets an attacker send many operations in one request,
	// defeating per-request rate limits (credential stuffing, 2FA brute force).
	bProbe := base.Clone()
	bProbe.Method = "POST"
	bProbe.Header.Set("Content-Type", "application/json")
	bProbe.Body = []byte(`[{"query":"{__typename}"},{"query":"{__typename}"}]`)
	if r, err := s.Send(ctx, bProbe); err == nil && r != nil {
		bb := strings.TrimSpace(r.BodyString())
		if strings.HasPrefix(bb, "[") && strings.Count(bb, `"data"`) >= 2 {
			issues = append(issues, &scan.Issue{
				Check: "graphql-batching", Name: "GraphQL query batching enabled",
				URL:      url,
				Severity: scan.SeverityLow, Confidence: scan.ConfidenceFirm,
				Detail:      "The endpoint executed a batched array of queries in a single request, returning multiple results. This lets an attacker run many operations per request and bypass per-request rate limiting (e.g. brute forcing logins or 2FA codes).",
				Remediation: "Disable array-based query batching, or apply rate limiting per operation rather than per request.",
				Evidence:    excerpt(bb, `"data"`), CWE: "CWE-770",
			})
		}
	}
	return issues
}
