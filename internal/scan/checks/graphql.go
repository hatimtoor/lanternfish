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
	if strings.Contains(body, `"__schema"`) || (strings.Contains(body, `"queryType"`) && strings.Contains(body, `"types"`)) {
		return []*scan.Issue{{
			Check: "graphql-introspection", Name: "GraphQL introspection enabled",
			URL:      base.AbsoluteURL().String(),
			Severity: scan.SeverityLow, Confidence: scan.ConfidenceFirm,
			Detail:      "The GraphQL endpoint answered an introspection query with its schema, exposing all types, queries, and mutations to attackers for API mapping.",
			Remediation: "Disable introspection in production, or restrict it to authenticated/privileged clients.",
			Evidence:    excerpt(body, "__schema"), CWE: "CWE-200",
		}}
	}
	return nil
}
