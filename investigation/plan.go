package investigation

import (
	"regexp"
	"strings"
)

// BuildPlan uses documented templates. Finding text only selects a family; it
// cannot issue instructions, introduce new URLs, or establish an attack fact.
func BuildPlan(f FindingContext) Plan {
	text := strings.ToLower(f.Name + " " + f.VulnClass + " " + f.Summary)
	family := "generic"
	switch {
	case containsAny(text, "ssrf", "server-side request", "서버 측 요청", "서버측 요청"):
		family = "ssrf"
	case containsAny(text, "remote code", "command injection", "코드 실행", "명령 실행", "명령어 삽입") || regexp.MustCompile(`\brce\b`).MatchString(text):
		family = "code_execution"
	case containsAny(text, "authentication", "credential", "authentication bypass", "인증 우회", "인증 실패", "계정 탈취", "brute force"):
		family = "authentication"
	case containsAny(text, "information", "disclosure", "exposure", "directory", "listing", "정보 노출", "정보노출", "리스팅", "파일 노출", "/ftp"):
		family = "information_exposure"
	}
	refs := []Reference{
		{Title: "CTID Vulnerability Mapping Methodology", URL: "https://ctid.mitre.org/mappings/about/methodology/cve-methodology/"},
		{Title: "NIST SP 800-61r3", URL: "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf"},
	}
	base := Hypothesis{ID: "path_access", Title: "Vulnerable route access trail", Statement: "Vulnerable paths may have been requested during the investigation. Access history alone does not confirm exploit success or infringement.", Preconditions: []string{"Verify that the vulnerability was present in the asset path at the time of investigation."}, RequiredLogs: []string{"Web server or reverse proxy request logs"}, RequiredFields: []string{"Timestamp", "Target Assets", "Request Path"}, Hunt: "Find the request that matches the selected asset, duration, and path, and display the known ARTEX verification request separately.", BenignAlternatives: []string{"Normal access of administrators and users", "Checking approved vulnerabilities", "Search engines or requests for monitoring"}, NextSteps: []string{"Check whether you are exposed and your access control settings at the time", "Contrast the method, session, response of the original request and the approved check schedule"}, References: refs}
	hs := []Hypothesis{base}
	switch family {
	case "information_exposure":
		hs = append(hs, Hypothesis{ID: "multi_path", Title: "Request flow to multiple subfiles", Statement: "You may have requested multiple subpaths for a short time from the same session or origin from the same log origin. The same IP does not mean the same attacker.", Preconditions: []string{"Multiple files or sub-resources exist in the target path", "The session or origin field is present in the actual request log"}, RequiredLogs: []string{"Web request logs by route", "Transfer Complete/Response Byte Log"}, RequiredFields: []string{"Timestamp", "Request Path", "Session or Departure", "Target Assets"}, Hunt: "Check if two or more different sub-routes are observed within ten minutes at the same file origin and session (if not, the origin) is observed. Do not count alarm redundancy as the number of requests.", BenignAlternatives: []string{"Loading multiple resources in a normal browser", "Shared Proxy·NAT", "Licensed collection and back-up work"}, NextSteps: []string{"Check the requested file content and sensitivity", "Check the transmission completion·Byte·Certificate status to determine the actual delivery range"}, References: refs}, Hypothesis{ID: "exposed_credentials", Title: "Subsequent abuse of exposure information", Statement: "If the exposed file contains a valid credentials at the time, you need to investigate the subsequent use of the account.", Preconditions: []string{"Verify credentials from the actual contents of the exposed file", "Make sure that the license is valid at the time of investigation.", "Get account identifiers and authentication logs"}, RequiredLogs: []string{"File content or archive at the time", "Authentication·Account Audit Log"}, RequiredFields: []string{"Account", "Authentication time", "Certification Results", "Session", "Departure"}, Hunt: "Contrast login and permission changes based on verified accounts. We do not estimate account theft by exposing information or the same IP alone.", BenignAlternatives: []string{"Normal use of account holders", "Example credentials that have already been discarded"}, NextSteps: []string{"Secure file preserves and authentication logs", "Check your account representatives and your activities for approval"}, References: refs})
	case "authentication":
		hs = append(hs, Hypothesis{ID: "account_misuse", Title: "Authentication bypass·Account usage investigation", Statement: "If the authentication vulnerability is actually exploited, there may be traces of normal authentication flow and other session issuance and permission use.", Preconditions: []string{"Identify Vulnerable Authentication Paths and Necessary Conditions", "Secure account and session audit log"}, RequiredLogs: []string{"Authentication Success/Failure Log", "Session issuance and permission change logs"}, RequiredFields: []string{"Account", "Session", "Timestamp", "Certification Results", "Permissions"}, Hunt: "Contrast vulnerable path requests and account activity with real session and account identifiers, and verify approval.", BenignAlternatives: []string{"Normal login retretish", "SSO·Service Account Activities"}, NextSteps: []string{"After securing the verification log, check the account manager", "Contrast the approval record of permission changes"}, References: refs})
	case "code_execution":
		hs = append(hs, Hypothesis{ID: "host_execution", Title: "Follow-up process·Persistence trail investigation", Statement: "If the code is actually executed on the server, you should investigate the web process subprocesses and file and network activity.", Preconditions: []string{"Check execution conditions and affected servers", "Get host audits or EDR resources"}, RequiredLogs: []string{"EDR/Process Creation Log", "File change·Network connection log"}, RequiredFields: []string{"Host", "Process ID", "Parental process", "Command line", "Timestamp"}, Hunt: "Contrast the child processes of the web process with the host identifier of the file and the external connection. HTTP response does not confirm code execution success.", BenignAlternatives: []string{"Run normal external commands for your application", "Distribution·backup·management work"}, NextSteps: []string{"Secure original evidence of EDR·Host", "Contrasting deployment and administrator work history"}, References: refs})
	case "ssrf":
		hs = append(hs, Hypothesis{ID: "server_egress", Title: "Investigated server-side follow-up requests", Statement: "If server-side request induction actually occurred, you can investigate the connection from the server and the record of the request.", Preconditions: []string{"Check for Vulnerable Requests and Server Identifiers", "Get server departure connection data"}, RequiredLogs: []string{"Server DNS, Proxies, Network Transmission Logs", "Request service access log"}, RequiredFields: []string{"Departure Host", "Destinations", "Timestamp", "Request ID or Process"}, Hunt: "Compare input requests and server sending events with the request ID, process, and time. The causal relationship is not determined by the proximity of time alone.", BenignAlternatives: []string{"Normal URL Preview·Web Hook", "Regular server-to-server communication"}, NextSteps: []string{"Secure transmission and destination audit logs", "Check the actual response and access control of sensitive objects"}, References: refs})
	default:
		hs = append(hs, Hypothesis{ID: "impact_review", Title: "Vulnerability Impact and Subsequent Behavior Manual Investigation", Statement: "Subsequent attacks cannot be determined in the current classification. Check the vulnerability-enacting conditions and effects, and then select the required logs.", Preconditions: []string{"Check the actual conditions of the vulnerability and the status of the asset at that time"}, RequiredLogs: []string{"Application Audit Log", "Authentication or host logs to fit the impact"}, RequiredFields: []string{"Assets", "Timestamp", "Request·session·Account identifier"}, Hunt: "Get data to confirm the connection between the observation request and the actual impact.", BenignAlternatives: []string{"Use normal functions", "Approved Test"}, NextSteps: []string{"Check the scope of vulnerability impact", "Elaborate required logs and fields"}, References: refs})
	}
	return Plan{EngineVersion: EngineVersion, Method: "Evidence-based conditional survey templates", Family: family, Summary: "Investigate the expected attack path and observed behavior separately. Subsequent exploits must be based on established conditions and evidence.", Hypotheses: hs, Limitations: []string{"The plan is an investigation template tailored to the classification of vulnerabilities and is not an LLM analysis or actual infringement judgment.", "Vulnerability and past vulnerabilities may differ.", "Automatic analysis covers destination/path access and limited multi-path request flow. Authentication, host, and transmission correlation analysis requires manual review."}}
}
func containsAny(s string, values ...string) bool {
	for _, v := range values {
		if strings.Contains(s, v) {
			return true
		}
	}
	return false
}
