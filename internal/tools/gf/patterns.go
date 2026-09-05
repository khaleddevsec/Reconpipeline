// Package gf defines the pattern catalogue, regular expressions, and false positive suppressions for Reconpipeline.
package gf

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// PatternDefinition encapsulates a pattern's identification rules, category, and evaluation criteria.
type PatternDefinition struct {
	Name          string
	Category      PatternCategory
	OutFile       string
	SecurityFocus string
	Flags         string
	PatternStr    string
	Regex         *regexp.Regexp
	PathRegex     *regexp.Regexp
	IsPathPattern bool
}

// GFPatternJSON represents the structure expected by standard gf CLI tool.
type GFPatternJSON struct {
	Flags   string `json:"flags"`
	Pattern string `json:"pattern"`
}

// Static asset regex to filter out false positive noise for parameter candidates.
var staticAssetRegex = regexp.MustCompile(`(?i)\.(css|woff|woff2|ttf|eot|png|jpg|jpeg|gif|svg|ico|webp|avif|mp4|mp3|avi|mov|webm)(\?.*)?$`)

// Tracking parameters that shouldn't trigger vulnerability candidates on their own.
var trackingParamRegex = regexp.MustCompile(`^(?i)(utm_source|utm_medium|utm_campaign|utm_term|utm_content|fbclid|gclid|_ga|mc_cid|mc_eid)$`)

// Definitions for all Pattern Intelligence targets across 12 categories.
var definitions = []PatternDefinition{
	// ─── 1. Vulnerability Candidates (Original 5 Preserved) ───────────────────
	{
		Name:          "xss",
		Category:      CategoryVulnerability,
		OutFile:       "xss.txt",
		SecurityFocus: "Cross-Site Scripting parameter reflection candidates",
		Flags:         "-iE",
		PatternStr:    `(\?|&)(access_token|action|admin|adm|alter|app|auth|authentication|backup|b|base|bot|browse|buy|callback|category|change|char|checkout|city|clear|code|command|config|confirm|contact|content|continue|control|create|database|db|debug|delete|dest|dir|direction|display|do|domain|download|edit|email|end|enter|error|eval|exec|exit|export|field|file|filter|find|first|flush|format|forward|from|goto|grant|group|handle|hash|head|help|history|host|id|image|img|include|index|insert|into|item|join|key|lang|language|last|link|load|log|login|logout|lookup|mail|make|master|message|mode|modify|module|name|nav|navigation|new|next|num|number|open|order|out|page|pass|password|path|phone|pid|post|preview|price|print|process|profile|query|read|redirect|ref|refresh|register|remove|report|request|reset|response|return|role|root|run|save|scan|search|select|send|service|session|set|setup|show|site|sort|source|sql|src|start|state|status|stop|sub|submit|table|tag|target|task|test|theme|title|to|token|topic|total|track|transfer|type|uid|update|upload|url|user|username|val|valid|validate|value|var|view|vote|web|window|zip)=`,
	},
	{
		Name:          "sqli",
		Category:      CategoryVulnerability,
		OutFile:       "sqli.txt",
		SecurityFocus: "SQL Injection query manipulation candidates",
		Flags:         "-iE",
		PatternStr:    `(\?|&)(id|select|insert|update|delete|drop|union|order|group|limit|waitfor|benchmark|sleep|table|column|admin|auth|token|query|sort|order_by|filter|dir|search|field|row|page|column_name)=`,
	},
	{
		Name:          "lfi",
		Category:      CategoryVulnerability,
		OutFile:       "lfi.txt",
		SecurityFocus: "Local File Inclusion & Path traversal candidates",
		Flags:         "-iE",
		PatternStr:    `(\?|&)(file|document|folder|root|path|pg|style|pdf|template|php_path|doc|page|include|location|read|view|item|dir|load|filename)=`,
	},
	{
		Name:          "ssrf",
		Category:      CategoryVulnerability,
		OutFile:       "ssrf.txt",
		SecurityFocus: "Server-Side Request Forgery outbound URL candidates",
		Flags:         "-iE",
		PatternStr:    `(\?|&)(dest|redirect|uri|path|continue|url|window|next|data|reference|site|html|val|validate|domain|callback|return|page|feed|host|port|to|out|view|dir|show|navigation|open)=`,
	},
	{
		Name:          "redirect",
		Category:      CategoryVulnerability,
		OutFile:       "redirect.txt",
		SecurityFocus: "Open Redirect & external forward candidates",
		Flags:         "-iE",
		PatternStr:    `(\?|&)(redirect|url|next|target|dest|destination|uri|path|continue|return|checkout_url|goto|link|view|to|out|image_url|next_url|return_url|redirect_url|forward)=`,
	},

	// ─── 1b. Additional Vulnerability Candidates ──────────────────────────────
	{
		Name:          "rfi",
		Category:      CategoryVulnerability,
		OutFile:       "rfi.txt",
		SecurityFocus: "Remote File Inclusion parameter candidates",
		Flags:         "-iE",
		PatternStr:    `(\?|&)(include|require|page|file|doc|load|folder|path|src|url|template|view)=(https?|ftp|php)://`,
	},
	{
		Name:          "ssti",
		Category:      CategoryVulnerability,
		OutFile:       "ssti.txt",
		SecurityFocus: "Server-Side Template Injection expression candidates",
		Flags:         "-iE",
		PatternStr:    `(\?|&)(template|tmpl|render|view|layout|preview|expr|expression|tpl|theme|model)=`,
	},
	{
		Name:          "xxe",
		Category:      CategoryVulnerability,
		OutFile:       "xxe.txt",
		SecurityFocus: "XML External Entity parsing input candidates",
		Flags:         "-iE",
		PatternStr:    `(\?|&)(xml|load|parse|doc|content|request|data|payload|xml_data|xmldoc)=`,
	},
	{
		Name:          "cmdi",
		Category:      CategoryVulnerability,
		OutFile:       "cmdi.txt",
		SecurityFocus: "OS Command Injection execution parameter candidates",
		Flags:         "-iE",
		PatternStr:    `(\?|&)(cmd|exec|command|run|ping|query|host|ip|eval|shell|code|process|cli|arg|args)=`,
	},
	{
		Name:          "traversal",
		Category:      CategoryVulnerability,
		OutFile:       "traversal.txt",
		SecurityFocus: "Path traversal / Directory traversal indicators",
		Flags:         "-iE",
		PatternStr:    `(\.\./|\.\.\\|%2e%2e%2f|%2e%2e\/|%2e%2e%5c|\.\.%2f)`,
		IsPathPattern: true,
	},
	{
		Name:          "crlf",
		Category:      CategoryVulnerability,
		OutFile:       "crlf.txt",
		SecurityFocus: "CRLF Injection & HTTP response splitting candidates",
		Flags:         "-iE",
		PatternStr:    `(\?|&)(url|redirect|next|dest|file|log|item|uri|view|return|header)=`,
	},
	{
		Name:          "proto-pollution",
		Category:      CategoryVulnerability,
		OutFile:       "proto-pollution.txt",
		SecurityFocus: "Prototype Pollution parameter candidates",
		Flags:         "-iE",
		PatternStr:    `(\?|&)(__proto__|constructor|prototype)(\[|\.|=)`,
	},
	{
		Name:          "deserialization",
		Category:      CategoryVulnerability,
		OutFile:       "deserialization.txt",
		SecurityFocus: "Object Deserialization payload parameter candidates",
		Flags:         "-iE",
		PatternStr:    `(\?|&)(state|data|session|serialized|obj|object|payload|viewstate|__viewstate|token)=`,
	},

	// ─── 2. API Intelligence ──────────────────────────────────────────────────
	{
		Name:          "api-rest",
		Category:      CategoryAPI,
		OutFile:       "api-rest.txt",
		SecurityFocus: "REST API endpoints & versioned resources",
		Flags:         "-iE",
		PatternStr:    `/(api|rest|endpoints)/v[0-9]+|/api/|/rest/|/v[0-9]+/`,
		IsPathPattern: true,
	},
	{
		Name:          "api-graphql",
		Category:      CategoryAPI,
		OutFile:       "api-graphql.txt",
		SecurityFocus: "GraphQL endpoints & query consoles",
		Flags:         "-iE",
		PatternStr:    `/(graphql|graph|gql|query|v1/graphql|v2/graphql)(\?|$|/)`,
		IsPathPattern: true,
	},
	{
		Name:          "api-swagger",
		Category:      CategoryAPI,
		OutFile:       "api-swagger.txt",
		SecurityFocus: "Swagger / OpenAPI schema & interactive UI docs",
		Flags:         "-iE",
		PatternStr:    `/(swagger|swagger-ui|api-docs|v2/api-docs|v3/api-docs|openapi\.json|openapi\.yaml|swagger\.json)(\?|$|/)`,
		IsPathPattern: true,
	},
	{
		Name:          "api-websocket",
		Category:      CategoryAPI,
		OutFile:       "api-websocket.txt",
		SecurityFocus: "WebSocket communication endpoints",
		Flags:         "-iE",
		PatternStr:    `^(wss?://|https?://.*/(ws|websocket|socket\.io|cable|stream|socket)(/|$))`,
		IsPathPattern: true,
	},

	// ─── 3. Authentication Intelligence ───────────────────────────────────────
	{
		Name:          "auth-login",
		Category:      CategoryAuth,
		OutFile:       "auth-login.txt",
		SecurityFocus: "Authentication & Login portals",
		Flags:         "-iE",
		PatternStr:    `/(login|signin|sign-in|authenticate|session|auth/login)(\?|$|/)`,
		IsPathPattern: true,
	},
	{
		Name:          "auth-reset",
		Category:      CategoryAuth,
		OutFile:       "auth-reset.txt",
		SecurityFocus: "Password recovery & reset workflows",
		Flags:         "-iE",
		PatternStr:    `/(reset-password|forgot-password|password/reset|recover|change-password)(\?|$|/)`,
		IsPathPattern: true,
	},
	{
		Name:          "auth-mfa",
		Category:      CategoryAuth,
		OutFile:       "auth-mfa.txt",
		SecurityFocus: "Multi-factor authentication checkpoints",
		Flags:         "-iE",
		PatternStr:    `/(mfa|2fa|totp|verify-otp|verify-mfa|two-factor)(\?|$|/)`,
		IsPathPattern: true,
	},
	{
		Name:          "auth-oauth",
		Category:      CategoryAuth,
		OutFile:       "auth-oauth.txt",
		SecurityFocus: "OAuth 2.0, OIDC, and SSO identity provider delegations",
		Flags:         "-iE",
		PatternStr:    `/(oauth|sso|saml|oidc|auth/callback|oauth/callback|authorize)(\?|$|/)`,
		IsPathPattern: true,
	},
	{
		Name:          "auth-register",
		Category:      CategoryAuth,
		OutFile:       "auth-register.txt",
		SecurityFocus: "Account registration & user sign-up entrypoints",
		Flags:         "-iE",
		PatternStr:    `/(register|signup|sign-up|join|create-account)(\?|$|/)`,
		IsPathPattern: true,
	},

	// ─── 4. Authorization / Resource Candidates ───────────────────────────────
	{
		Name:          "idor-candidate",
		Category:      CategoryAuthorization,
		OutFile:       "idor-candidate.txt",
		SecurityFocus: "Authorization candidate: direct object reference parameter/path",
		Flags:         "-iE",
		PatternStr:    `(?i)((\?|&)(id|user_id|account_id|org_id|uid|member_id|doc_id|order_id|profile_id|uuid)=[0-9a-fA-F-]+|/(users?|accounts?|orgs?|profiles?|orders?|invoices?|members?|docs?)/[0-9a-fA-F-]+)`,
	},

	// ─── 5. Administrative Intelligence ──────────────────────────────────────
	{
		Name:          "admin",
		Category:      CategoryAdmin,
		OutFile:       "admin.txt",
		SecurityFocus: "Administrative management panels & restricted consoles",
		Flags:         "-iE",
		PatternStr:    `/(admin|administrator|manage|management|dashboard|superadmin|controlpanel|adm|portal/admin)(\?|$|/)`,
		IsPathPattern: true,
	},

	// ─── 6. Debug & Development Intelligence ─────────────────────────────────
	{
		Name:          "debug",
		Category:      CategoryDebug,
		OutFile:       "debug.txt",
		SecurityFocus: "Diagnostic, test, and debug exposure endpoints",
		Flags:         "-iE",
		PatternStr:    `/(debug|debugger|test|testing|trace|profiler|debugbar|phpinfo)(\?|$|/)`,
		IsPathPattern: true,
	},
	{
		Name:          "actuator",
		Category:      CategoryDebug,
		OutFile:       "actuator.txt",
		SecurityFocus: "Spring Boot Actuator & Application metric monitoring",
		Flags:         "-iE",
		PatternStr:    `/(actuator|actuator/health|actuator/env|actuator/beans|actuator/metrics|metrics|health|healthz|livez|readyz)(\?|$|/)`,
		IsPathPattern: true,
	},

	// ─── 7. Sensitive File Intelligence ───────────────────────────────────────
	{
		Name:          "sensitive-env",
		Category:      CategorySensitiveFile,
		OutFile:       "sensitive-env.txt",
		SecurityFocus: "Environment configuration & credential leakage candidates",
		Flags:         "-iE",
		PatternStr:    `(\.env|\.env\.local|\.env\.production|\.env\.staging|\.env\.bak|env\.json)(\?|$)`,
		IsPathPattern: true,
	},
	{
		Name:          "sensitive-git",
		Category:      CategorySensitiveFile,
		OutFile:       "sensitive-git.txt",
		SecurityFocus: "Version control metadata repository exposure",
		Flags:         "-iE",
		PatternStr:    `(\.git/|\.gitignore|\.git/HEAD|\.git/config|\.git/index)(\?|$)`,
		IsPathPattern: true,
	},
	{
		Name:          "sensitive-sql",
		Category:      CategorySensitiveFile,
		OutFile:       "sensitive-sql.txt",
		SecurityFocus: "Database export, dump, and script candidates",
		Flags:         "-iE",
		PatternStr:    `(\.(sql|db|sqlite|sqlite3|dump)|dump\.sql|backup\.sql)(\?|$)`,
		IsPathPattern: true,
	},
	{
		Name:          "sensitive-log",
		Category:      CategorySensitiveFile,
		OutFile:       "sensitive-log.txt",
		SecurityFocus: "System, access, and application execution logs",
		Flags:         "-iE",
		PatternStr:    `(\.(log)|access\.log|error\.log|debug\.log|server\.log)(\?|$)`,
		IsPathPattern: true,
	},
	{
		Name:          "sensitive-config",
		Category:      CategorySensitiveFile,
		OutFile:       "sensitive-config.txt",
		SecurityFocus: "Application & server configuration files",
		Flags:         "-iE",
		PatternStr:    `/(web\.config|config\.json|config\.yaml|config\.yml|settings\.py|database\.yml|wp-config\.php|server\.xml)(\?|$)`,
		IsPathPattern: true,
	},

	// ─── 8. Backup & Legacy Intelligence ──────────────────────────────────────
	{
		Name:          "backup",
		Category:      CategoryBackup,
		OutFile:       "backup.txt",
		SecurityFocus: "Backup archives and file copies",
		Flags:         "-iE",
		PatternStr:    `(\.(bak|backup|old|orig|save|zip|tar|tar\.gz|tgz|rar)|backup\.zip|backup\.tar)(\?|$)`,
		IsPathPattern: true,
	},
	{
		Name:          "legacy",
		Category:      CategoryBackup,
		OutFile:       "legacy.txt",
		SecurityFocus: "Deprecated, legacy, and temporary endpoints",
		Flags:         "-iE",
		PatternStr:    `/(old|legacy|temp|tmp|v0|bak|archive|deprecated)/`,
		IsPathPattern: true,
	},

	// ─── 9. Secret & Credential Indicator ─────────────────────────────────────
	{
		Name:          "secret-token",
		Category:      CategorySecret,
		OutFile:       "secret-token.txt",
		SecurityFocus: "Exposed session or authentication token parameter candidates",
		Flags:         "-iE",
		PatternStr:    `(\?|&)(access_token|auth_token|bearer|session_token|jwt|token)=[a-zA-Z0-9_\.\-]{8,}`,
	},
	{
		Name:          "secret-key",
		Category:      CategorySecret,
		OutFile:       "secret-key.txt",
		SecurityFocus: "Exposed secret, password, or API key parameter candidates",
		Flags:         "-iE",
		PatternStr:    `(\?|&)(api_key|apikey|client_secret|private_key|secret|password|passwd|auth_key)=[a-zA-Z0-9_\.\-]{8,}`,
	},

	// ─── 10. Cloud Infrastructure Intelligence ────────────────────────────────
	{
		Name:          "cloud-s3",
		Category:      CategoryCloud,
		OutFile:       "cloud-s3.txt",
		SecurityFocus: "Amazon Web Services S3 bucket references",
		Flags:         "-iE",
		PatternStr:    `(s3\.amazonaws\.com|\.s3-[a-z0-9-]+\.amazonaws\.com|s3://)`,
		IsPathPattern: true,
	},
	{
		Name:          "cloud-azure",
		Category:      CategoryCloud,
		OutFile:       "cloud-azure.txt",
		SecurityFocus: "Microsoft Azure storage blobs and cloud apps",
		Flags:         "-iE",
		PatternStr:    `(\.blob\.core\.windows\.net|\.azurewebsites\.net|\.cloudapp\.azure\.com)`,
		IsPathPattern: true,
	},
	{
		Name:          "cloud-gcp",
		Category:      CategoryCloud,
		OutFile:       "cloud-gcp.txt",
		SecurityFocus: "Google Cloud Platform storage and Firebase endpoints",
		Flags:         "-iE",
		PatternStr:    `(storage\.googleapis\.com|\.firebaseio\.com|\.appspot\.com)`,
		IsPathPattern: true,
	},
	{
		Name:          "cloud-cloudfront",
		Category:      CategoryCloud,
		OutFile:       "cloud-cloudfront.txt",
		SecurityFocus: "Amazon CloudFront CDN distributions",
		Flags:         "-iE",
		PatternStr:    `\.cloudfront\.net`,
		IsPathPattern: true,
	},

	// ─── 11. File Operations Intelligence ─────────────────────────────────────
	{
		Name:          "file-upload",
		Category:      CategoryFileOps,
		OutFile:       "file-upload.txt",
		SecurityFocus: "File upload receivers & multi-part forms",
		Flags:         "-iE",
		PatternStr:    `/(upload|file-upload|uploader|import|attach|attachment)(\?|$|/)`,
		IsPathPattern: true,
	},
	{
		Name:          "file-download",
		Category:      CategoryFileOps,
		OutFile:       "file-download.txt",
		SecurityFocus: "File download, fetch, and document export handlers",
		Flags:         "-iE",
		PatternStr:    `/(download|export|getfile|fetch|download\.php|export\.php)(\?|$|/)`,
		IsPathPattern: true,
	},
}

// compiledDefinitions holds compiled regexes for rapid scanning.
var compiledDefinitions []PatternDefinition

func init() {
	compiledDefinitions = make([]PatternDefinition, len(definitions))
	for i, def := range definitions {
		re := regexp.MustCompile(fmt.Sprintf("(?i)%s", def.PatternStr))
		def.Regex = re
		compiledDefinitions[i] = def
	}
}

// GetAllDefinitions returns all pattern definitions.
func GetAllDefinitions() []PatternDefinition {
	return compiledDefinitions
}

// FindDefinition returns the PatternDefinition for the given pattern name.
func FindDefinition(name string) (PatternDefinition, bool) {
	for _, def := range compiledDefinitions {
		if strings.EqualFold(def.Name, name) {
			return def, true
		}
	}
	return PatternDefinition{}, false
}

// IsStaticNoise checks if a URL points to static CSS/JS/images/fonts that should be suppressed for query fuzzing.
func IsStaticNoise(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return staticAssetRegex.MatchString(rawURL)
	}
	return staticAssetRegex.MatchString(u.Path)
}

// ExtractParamName extracts the parameter name matched in the URL query string.
func ExtractParamName(rawURL string, patternDef *PatternDefinition) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	q := u.Query()
	for p := range q {
		// If tracking noise, ignore
		if trackingParamRegex.MatchString(p) {
			continue
		}
		// Test if this param matches
		paramCheck := fmt.Sprintf("?%s=", p)
		if patternDef.Regex.MatchString(paramCheck) {
			return p
		}
	}
	return ""
}

// EnsurePatternFiles populates JSON pattern files into ~/.gf, ~/.config/gf, and .reconpipeline/patterns.
func EnsurePatternFiles() {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "/root"
	}

	dirs := []string{
		filepath.Join(home, ".gf"),
		filepath.Join(home, ".config", "gf"),
		filepath.Join(home, ".reconpipeline", "patterns"),
	}

	for _, d := range dirs {
		_ = os.MkdirAll(d, 0750)
		for _, def := range compiledDefinitions {
			p := filepath.Join(d, def.Name+".json")
			if _, err := os.Stat(p); os.IsNotExist(err) {
				content := fmt.Sprintf(`{"flags":"%s","pattern":"%s"}`+"\n", def.Flags, strings.ReplaceAll(def.PatternStr, `"`, `\"`))
				_ = os.WriteFile(p, []byte(content), 0640)
			}
		}
	}
}
