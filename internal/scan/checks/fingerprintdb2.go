package checks

// Additional technology fingerprints, appended to the database.
func init() {
	fingerprintRules = append(fingerprintRules,
		fp("woocommerce", "WooCommerce", `(?i)woocommerce|/wp-content/plugins/woocommerce/`),
		fp("ghost", "Ghost CMS", `(?i)<meta name="generator" content="Ghost|/ghost/api/`),
		fp("craftcms", "Craft CMS", `(?i)CraftSessionId|X-Powered-By: Craft CMS`),
		fp("typo3", "TYPO3", `(?i)/typo3(?:conf|temp)/|<meta name="generator" content="TYPO3`),
		fp("sitecore", "Sitecore", `(?i)/sitecore/|SC_ANALYTICS_GLOBAL_COOKIE`),
		fp("aem", "Adobe Experience Manager", `(?i)/etc/designs/|/content/dam/|cq:`),
		fp("akamai", "Akamai", `(?i)X-Akamai-|akamai`),
		fp("imperva", "Imperva/Incapsula", `(?i)incap_ses|visid_incap|X-Iinfo`),
		fp("bigip", "F5 BIG-IP", `(?i)BIGipServer|TS[0-9a-f]{8}=`),
		fp("squarespace", "Squarespace", `(?i)static1\.squarespace\.com|Squarespace`),
		fp("wix", "Wix", `(?i)X-Wix-|static\.wixstatic\.com`),
		fp("zendesk", "Zendesk", `(?i)\.zendesk\.com|zendesk`),
		fp("hubspot-cms", "HubSpot CMS", `(?i)hs-scripts\.com|__hstc`),
		fp("shopify-store", "Shopify storefront", `(?i)cdn\.shopify\.com|X-ShopId|Shopify`),
		fp("cloudfront", "AWS CloudFront", `(?i)X-Amz-Cf-Id:|Via:.*cloudfront`),
		fp("fastly-cdn", "Fastly CDN", `(?i)X-Served-By:.*cache|Fastly-`),
		fp("gunicorn", "Gunicorn", `(?i)Server: gunicorn`),
		fp("uvicorn", "Uvicorn/FastAPI", `(?i)Server: uvicorn`),
		fp("kong", "Kong API gateway", `(?i)Via:.*kong|X-Kong-`),
		fp("graphql-ep", "GraphQL endpoint", `(?i)"data":\s*\{.*"__typename"|graphiql`),
	)
}
