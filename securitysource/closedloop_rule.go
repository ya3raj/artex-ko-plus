package securitysource

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Autumn-27/artex/closedloop"
	"github.com/Autumn-27/artex/investigation"
)

const ClosedLoopRuleEngine = "splunk-shadow-exact-contains-v1"
const maxClosedLoopSearchBytes = 64 << 10
const baselineShadowField = "_aegis_shadow_baseline"
const candidateShadowField = "_aegis_shadow_candidate"

// ClosedLoopRuleEvent reports an ad hoc rule evaluation, never an emitted alert.
// Raw retains the exact returned native result object, including original _raw.
type ClosedLoopRuleEvent struct {
	EventID    string          `json:"event_id"`
	OccurredAt time.Time       `json:"occurred_at"`
	Baseline   string          `json:"baseline"`
	Candidate  string          `json:"candidate"`
	Raw        json.RawMessage `json:"raw"`
}

type ClosedLoopSearchResult struct {
	Engine              string                       `json:"engine"`
	Scope               string                       `json:"scope"`
	Query               string                       `json:"query"`
	BaselineRuleSHA256  string                       `json:"baseline_rule_sha256"`
	CandidateRuleSHA256 string                       `json:"candidate_rule_sha256"`
	CorrelationID       string                       `json:"correlation_id"`
	WindowStart         time.Time                    `json:"window_start"`
	WindowEnd           time.Time                    `json:"window_end"`
	QueryStartedAt      time.Time                    `json:"query_started_at"`
	QueryFinishedAt     time.Time                    `json:"query_finished_at"`
	CollectedAt         time.Time                    `json:"collected_at"`
	Complete            bool                         `json:"complete"`
	Truncated           int                          `json:"truncated"`
	TotalRows           int                          `json:"total_rows"`
	Warnings            []string                     `json:"warnings"`
	ErrorCode           string                       `json:"error_code,omitempty"`
	HTTPStatus          int                          `json:"http_status,omitempty"`
	Events              []ClosedLoopRuleEvent        `json:"events"`
	Files               []investigation.FileEvidence `json:"files"`
	Upload              *UploadProvenance            `json:"upload,omitempty"`
}

// ClosedLoopRuleFields is a behavioral-field allowlist. Execution IDs, labels,
// sensor identities and observation timestamps cannot become rule conditions.
// It is also the contract used by proposal generation and managed lab deployment.
func ClosedLoopRuleFields(mapping investigation.Mapping) []string {
	set := map[string]bool{}
	for _, f := range []string{mapping.Target, mapping.Path, mapping.SourceIP, mapping.User,
		mapping.Session, mapping.Action, mapping.Status, mapping.Bytes, mapping.EventKind,
		mapping.ResponseComplete, "method", "rule_id", "matched_rules", "message",
		"transaction_complete", "request_target", "query_string"} {
		if f != "" && fieldName.MatchString(f) && !closedLoopReservedField(f, mapping) {
			set[f] = true
		}
	}
	out := make([]string, 0, len(set))
	for f := range set {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

func closedLoopReservedField(f string, m investigation.Mapping) bool {
	fold := strings.ToLower(f)
	if strings.HasPrefix(fold, "_aegis_") {
		return true
	}
	for _, reserved := range []string{m.EventID, m.VerificationID, m.Timestamp, "id", "event_id",
		"label", "ground_truth", "artex_verification_id", "correlation_id", "request_uid",
		"audit_event_id", "alert_id", "_raw", "_time", "timestamp", "event_epoch",
		"occurred_at", "baseline_alert_at", "candidate_alert_at", "alert_created_at",
		"source", "host", "index", "sourcetype", "_cd", "_bkt", "splunk_server",
		"rule_sha256", "detection_rule_id", "detection_engine"} {
		if reserved != "" && strings.EqualFold(f, reserved) {
			return true
		}
	}
	return false
}

func validateClosedLoopRules(mapping investigation.Mapping, rules ...closedloop.Rule) error {
	allowed := map[string]bool{}
	for _, f := range ClosedLoopRuleFields(mapping) {
		allowed[f] = true
	}
	for _, rule := range rules {
		if err := closedloop.ValidateRule(rule); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalid, err)
		}
		if !utf8.ValidString(rule.Name) || strings.ContainsAny(rule.Name, "\x00\r\n") {
			return fmt.Errorf("%w: Check the rule name", ErrInvalid)
		}
		for _, branch := range rule.Any {
			for _, cond := range branch.All {
				if !allowed[cond.Field] || !utf8.ValidString(cond.Value) || strings.ContainsAny(cond.Value, "\x00\r\n") {
					return fmt.Errorf("%w : Rules can only use allowed action fields and UTF-8 literal values", ErrInvalid)
				}
			}
		}
	}
	return nil
}

func validateClosedLoopScope(c Config, q Query, scope investigation.Scope, mapping investigation.Mapping) error {
	if !correlationName.MatchString(q.CorrelationID) || q.Start.IsZero() || !q.End.After(q.Start) ||
		q.End.Sub(q.Start) > 24*time.Hour || !q.Start.Equal(scope.Start) || !q.End.Equal(scope.End) {
		return fmt.Errorf("%w : Requires the same execution UUID and up to twenty-four hours of the same lookup interval", ErrInvalid)
	}
	if mapping.VerificationID != c.CorrelationField || mapping.Target == "" || mapping.Path == "" || scope.PathPrefix == "" {
		return fmt.Errorf("%w : Run UUID·Target·Range Range Requires original field mapping", ErrInvalid)
	}
	if err := investigation.ValidateScope(scope, time.Now().UTC()); err != nil {
		return err
	}
	return investigation.ValidateMapping(mapping)
}

// BuildClosedLoopRuleSearch compiles structured rules into one bounded search.
// Both rules evaluate the same complete scoped audit input. Matching predicates
// never replace the mandatory index/source/target/path/correlation/time bounds.
func BuildClosedLoopRuleSearch(c Config, q Query, scope investigation.Scope, mapping investigation.Mapping, baseline, candidate closedloop.Rule) (string, error) {
	var err error
	c, err = Validate(c)
	if err != nil {
		return "", err
	}
	if err = validateClosedLoopScope(c, q, scope, mapping); err != nil {
		return "", err
	}
	if err = validateClosedLoopRules(mapping, baseline, candidate); err != nil {
		return "", err
	}
	search, err := BuildInvestigationSearch(c, scope, mapping, []string{c.AuditSourcetype})
	if err != nil {
		return "", err
	}
	suffix := " | head " + strconv.Itoa(investigation.MaxRows+1)
	search = strings.TrimSuffix(search, suffix)
	search += " | where mvcount('" + c.CorrelationField + "') = 1 AND '" + c.CorrelationField + "' = " + investigationLiteral(q.CorrelationID)
	fields := []string{}
	for _, rule := range []closedloop.Rule{baseline, candidate} {
		for _, branch := range rule.Any {
			for _, cond := range branch.All {
				fields = append(fields, cond.Field)
				if flag := closedLoopTruncationField(cond.Field); flag != "" {
					fields = append(fields, flag)
				}
			}
		}
	}
	search += splunkDeduplicateFields(fields...)
	search += compileClosedLoopRule(baseline, "b", baselineShadowField)
	search += compileClosedLoopRule(candidate, "c", candidateShadowField)
	// Remove only compiler-owned intermediates; retain every native source field.
	search += " | fields - _aegis_shadow_b_cond_* _aegis_shadow_b_branch_* _aegis_shadow_c_cond_* _aegis_shadow_c_branch_*" + suffix
	if len(search) > maxClosedLoopSearchBytes {
		return "", fmt.Errorf("%w : The generated search expression must be less than 64 KiB. Please reduce the rules", ErrInvalid)
	}
	return search, nil
}

func compileClosedLoopRule(rule closedloop.Rule, kind, output string) string {
	var conditions, branches []string
	var hits, unknowns []string
	for i, branch := range rule.Any {
		var falseTerms, unknownTerms []string
		for j, cond := range branch.All {
			name := fmt.Sprintf("_aegis_shadow_%s_cond_%d_%d", kind, i, j)
			value, expected := "tostring('"+cond.Field+"')", cond.Value
			if !cond.CaseSensitive {
				value = "lower(" + value + ")"
				expected = strings.ToLower(expected)
			}
			predicate := value + " = " + investigationLiteral(expected)
			if cond.Op == "contains" {
				predicate = "match(" + value + ", " + investigationLiteral(regexp.QuoteMeta(expected)) + ")"
			}
			unknown := fmt.Sprintf("isnull('%s') OR mvcount('%s') != 1", cond.Field, cond.Field)
			if flag := closedLoopTruncationField(cond.Field); flag != "" {
				unknown += fmt.Sprintf(" OR lower(tostring('%s')) = \"true\" OR tostring('%s') = \"1\"", flag, flag)
			}
			conditions = append(conditions, fmt.Sprintf(`"%s"=case(%s, -1, %s, 1, true(), 0)`, name, unknown, predicate))
			falseTerms = append(falseTerms, "'"+name+"' = 0")
			unknownTerms = append(unknownTerms, "'"+name+"' = -1")
		}
		name := fmt.Sprintf("_aegis_shadow_%s_branch_%d", kind, i)
		branches = append(branches, fmt.Sprintf(`"%s"=case(%s, 0, %s, -1, true(), 1)`, name, strings.Join(falseTerms, " OR "), strings.Join(unknownTerms, " OR ")))
		hits = append(hits, "'"+name+"' = 1")
		unknowns = append(unknowns, "'"+name+"' = -1")
	}
	return " | eval " + strings.Join(conditions, ", ") + " | eval " + strings.Join(branches, ", ") +
		fmt.Sprintf(` | eval "%s"=case(%s, "match", %s, "unknown", true(), "no_match")`, output, strings.Join(hits, " OR "), strings.Join(unknowns, " OR "))
}

func newClosedLoopResult(q Query, baseline, candidate closedloop.Rule, scope string) *ClosedLoopSearchResult {
	b, _ := json.Marshal(baseline)
	c, _ := json.Marshal(candidate)
	return &ClosedLoopSearchResult{Engine: ClosedLoopRuleEngine, Scope: scope,
		BaselineRuleSHA256: closedloop.Hash(b), CandidateRuleSHA256: closedloop.Hash(c),
		CorrelationID: q.CorrelationID, WindowStart: q.Start.UTC(), WindowEnd: q.End.UTC(),
		Events: []ClosedLoopRuleEvent{}, Files: []investigation.FileEvidence{}, Warnings: []string{}}
}

func (out *ClosedLoopSearchResult) warn(warning string) {
	out.Complete = false
	for _, previous := range out.Warnings {
		if previous == warning {
			return
		}
	}
	if len(out.Warnings) < 30 {
		out.Warnings = append(out.Warnings, warning)
	}
}

// FetchClosedLoopRules executes only the generated read-only export search with
// existing reader credentials. Partial/failing query evidence is returned along
// with the error so callers can persist the failed attempt without claiming a miss.
func FetchClosedLoopRules(ctx context.Context, c Config, auth Credentials, q Query, scope investigation.Scope, mapping investigation.Mapping, baseline, candidate closedloop.Rule) (*ClosedLoopSearchResult, error) {
	var err error
	c, err = Validate(c)
	if err != nil {
		return nil, err
	}
	if err = ValidateCredentials(auth); err != nil {
		return nil, err
	}
	search, err := BuildClosedLoopRuleSearch(c, q, scope, mapping, baseline, candidate)
	if err != nil {
		return nil, err
	}
	out := newClosedLoopResult(q, baseline, candidate, "splunk_shadow_rule_evaluation")
	out.Query = search
	out.Warnings = append(out.Warnings, "shadow_matches_are_not_emitted_alerts", "search_completion_does_not_prove_sensor_coverage")
	body, err := closedLoopExport(ctx, c, auth, scope, search, out)
	if len(body) > 0 || err == nil {
		out.Files = append(out.Files, investigation.FileEvidence{Name: "splunk-shadow-export.jsonl", SHA256: closedloop.Hash(body), Bytes: len(body), Content: string(body)})
	}
	if err != nil {
		return out, err
	}
	results, rows, complete, warnings, err := parseInvestigationExport(body)
	out.TotalRows = rows
	out.Complete = complete
	for _, warning := range warnings {
		out.warn(warning)
	}
	if err != nil {
		out.ErrorCode = "invalid_export"
		out.warn("Splunk search response failed to interpret. Please check source response")
		return out, err
	}
	out.Files[0].Rows = rows
	out.Files = append(out.Files, investigation.FileEvidence{Name: "splunk-shadow-events.jsonl", SHA256: closedloop.Hash(results), Bytes: len(results), Rows: rows, Content: string(results)})
	if rows > investigation.MaxRows {
		out.Truncated += rows - investigation.MaxRows
	}
	// Unlike historical hunting, a live no-match needs a completed terminal
	// envelope even for zero rows. Empty/diagnostic-only HTTP 200 is inconclusive.
	if rows == 0 && !closedLoopTerminal(body) {
		out.warn("No completion indication of Splunk search failed to confirm the completeness of the empty result")
	}
	mapping.Timestamp = "_time"
	collection, err := investigation.ParseFiles([]investigation.InputFile{{Name: "splunk-shadow-events.jsonl", Content: string(results)}}, scope, mapping, complete, false, []string{q.CorrelationID})
	if err != nil {
		out.ErrorCode = "invalid_events"
		out.warn("Splunk failed to check the scope and field mapping of the original event")
		return out, err
	}
	if !collection.Complete {
		out.warn("Among the returned events, there are items that cannot be checked for scope, fields, and limits.")
	}
	out.Truncated += collection.Stats.Truncated
	if collection.Stats.UnrelatedTarget+collection.Stats.UnrelatedPath+collection.Stats.OutsideWindow > 0 {
		out.warn("Events outside the target, route, and time range have been returned.")
	}
	seen := map[string]string{}
	for _, event := range collection.Events {
		if event.VerificationID != q.CorrelationID {
			out.warn("Set execution UUID and other events have been returned")
			continue
		}
		fields, fallback, err := closedLoopObjects([]byte(event.Raw))
		if err != nil || closedLoopScalar(fields["index"]) != c.Index || closedLoopScalar(fields["sourcetype"]) != c.AuditSourcetype {
			out.warn("Audit log source or original event format could not be verified")
			continue
		}
		base, cand := closedLoopScalar(fields[baselineShadowField]), closedLoopScalar(fields[candidateShadowField])
		if closedLoopPayloadTruncated(fields, fallback) {
			out.warn("The original request field has been truncated from the collector. The rule result for the entire request cannot be determined.")
		}
		if base != matchClosedLoopRule(fields, fallback, baseline) || cand != matchClosedLoopRule(fields, fallback, candidate) {
			out.warn("The results of the Splunk rule and the condition determination of the source field do not match")
			base, cand = "unknown", "unknown"
		}
		id := closedLoopEventID(fields, fallback, mapping, c.Index, []byte(event.Raw))
		hash := closedloop.Hash([]byte(event.Raw))
		if previous, exists := seen[id]; exists {
			if previous != hash {
				out.warn("Different logs were returned to the same original event ID")
			}
			continue
		}
		seen[id] = hash
		out.Events = append(out.Events, ClosedLoopRuleEvent{EventID: id, OccurredAt: event.Timestamp, Baseline: base, Candidate: cand, Raw: json.RawMessage(event.Raw)})
	}
	return out, nil
}

func closedLoopTerminal(body []byte) bool {
	scan := bufio.NewScanner(bytes.NewReader(body))
	scan.Buffer(make([]byte, 4096), maxResponseBytes)
	terminal := false
	for scan.Scan() {
		if len(bytes.TrimSpace(scan.Bytes())) == 0 {
			continue
		}
		var row struct {
			LastRow bool `json:"lastrow"`
			Preview bool `json:"preview"`
		}
		if decodeInvestigationEnvelope(scan.Bytes(), &row) != nil || row.Preview {
			return false
		}
		terminal = row.LastRow
	}
	return terminal && scan.Err() == nil
}

// Reuse the connector's TLS pin/PKI/redirect/proxy/time limits, but retain a
// bounded successful-response prefix on read/size failures for explicit export.
// Non-200 response bodies are discarded: they are not native log evidence and
// may contain authentication or server diagnostics that must not enter the UI.
func closedLoopExport(ctx context.Context, c Config, auth Credentials, scope investigation.Scope, search string, out *ClosedLoopSearchResult) ([]byte, error) {
	out.QueryStartedAt = time.Now().UTC()
	defer func() {
		out.QueryFinishedAt = time.Now().UTC()
		out.CollectedAt = out.QueryFinishedAt
	}()
	form := url.Values{"search": {search}, "output_mode": {"json"}, "preview": {"false"},
		"output_time_format": {splunkOutputTimeFormat}, "earliest_time": {investigationEpoch(scope.Start)}, "latest_time": {investigationEpoch(scope.End)}}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/services/search/v2/jobs/export", strings.NewReader(form.Encode()))
	if err != nil {
		out.ErrorCode = "invalid_request"
		return nil, errors.New("Failed to create security log lookup request")
	}
	if auth.Token != "" {
		r.Header.Set("Authorization", "Bearer "+auth.Token)
	} else {
		r.SetBasicAuth(auth.Username, auth.Password)
	}
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Accept", "application/json")
	h := client(c)
	defer h.CloseIdleConnections()
	res, err := h.Do(r)
	if err != nil {
		out.ErrorCode = "connection_failed"
		out.warn("Splunk connection or lookup request not completed")
		if ctx.Err() != nil {
			out.ErrorCode = "request_cancelled"
			return nil, ctx.Err()
		}
		return nil, errors.New("Splunk connection failed. Please check address, certificate, network")
	}
	defer res.Body.Close()
	out.HTTPStatus = res.StatusCode
	if res.StatusCode != http.StatusOK {
		out.ErrorCode = "http_error"
		out.warn("Splunk has refused a search request")
		return nil, fmt.Errorf("Splunk lookup rejected with HTTP %d. Please check your connection account and search permissions", res.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, maxResponseBytes+1))
	if len(body) > maxResponseBytes {
		out.Truncated++
		out.ErrorCode = "response_limit"
		out.warn("Splunk response exceeded 4 MiB. Saved responses are some")
		return body[:maxResponseBytes], errors.New("Splunk response exceeded 4 MiB. Please reduce the search range")
	}
	if err != nil {
		out.ErrorCode = "response_interrupted"
		out.warn("I didn't read the Splunk response to the end. The saved responses are some")
		return body, errors.New("I didn't read the Splunk response to the end")
	}
	if !utf8.Valid(body) || bytes.ContainsRune(body, 0) {
		out.ErrorCode = "invalid_encoding"
		out.warn("Not the UTF-8 log format that Splunk responses support")
		return nil, errors.New("Splunk response must be UTF-8 without NUL")
	}
	return body, nil
}

func closedLoopObjects(raw []byte) (map[string]any, map[string]any, error) {
	decode := func(raw []byte) (map[string]any, error) {
		if len(raw) > investigation.MaxRecordBytes || !utf8.Valid(raw) {
			return nil, errors.New("invalid record")
		}
		d := json.NewDecoder(bytes.NewReader(raw))
		d.UseNumber()
		count := 0
		value, err := readUploadJSONValue(d, 0, &count)
		if err != nil {
			return nil, err
		}
		object, ok := value.(map[string]any)
		if !ok {
			return nil, errors.New("invalid object")
		}
		if _, err = d.Token(); err != io.EOF {
			return nil, errors.New("trailing JSON")
		}
		return object, nil
	}
	fields, err := decode(raw)
	if err != nil {
		return nil, nil, err
	}
	var fallback map[string]any
	if value, ok := fields["_raw"].(string); ok && strings.HasPrefix(strings.TrimSpace(value), "{") {
		fallback, err = decode([]byte(value))
		if err != nil {
			return nil, nil, err
		}
	}
	return fields, fallback, nil
}

func closedLoopValue(fields, fallback map[string]any, key string) any {
	value := field(fields, key)
	if value == nil {
		value = field(fallback, key)
	}
	return value
}

func closedLoopScalar(value any) string {
	text, _ := closedLoopScalarOK(value)
	return text
}

func closedLoopScalarOK(value any) (string, bool) {
	switch value := value.(type) {
	case string:
		return value, true
	case json.Number:
		return value.String(), true
	case bool:
		return strconv.FormatBool(value), true
	case []any:
		// Automatic extraction + spath can repeat one scalar. Conflicting
		// multivalues remain unknown rather than selecting a favorable value.
		if len(value) == 0 {
			return "", false
		}
		first, ok := closedLoopScalarOK(value[0])
		if _, nested := value[0].([]any); nested {
			return "", false
		}
		if !ok {
			return "", false
		}
		for _, child := range value[1:] {
			if _, nested := child.([]any); nested {
				return "", false
			}
			text, valid := closedLoopScalarOK(child)
			if !valid || text != first {
				return "", false
			}
		}
		return first, true
	}
	return "", false
}

func matchClosedLoopRule(fields, fallback map[string]any, rule closedloop.Rule) string {
	unknown := false
	for _, branch := range rule.Any {
		branchUnknown, branchFalse := false, false
		for _, cond := range branch.All {
			if flag := closedLoopTruncationField(cond.Field); flag != "" && closedLoopTrue(closedLoopValue(fields, fallback, flag)) {
				branchUnknown = true
				continue
			}
			value, ok := closedLoopScalarOK(closedLoopValue(fields, fallback, cond.Field))
			if !ok {
				branchUnknown = true
				continue
			}
			expected := cond.Value
			if !cond.CaseSensitive {
				value, expected = strings.ToLower(value), strings.ToLower(expected)
			}
			hit := value == expected
			if cond.Op == "contains" {
				hit = strings.Contains(value, expected)
			}
			branchFalse = branchFalse || !hit
		}
		if !branchFalse && !branchUnknown {
			return "match"
		}
		unknown = unknown || !branchFalse && branchUnknown
	}
	if unknown {
		return "unknown"
	}
	return "no_match"
}

func closedLoopTruncationField(field string) string {
	switch field {
	case "path", "request_target", "query_string":
		return field + "_truncated"
	}
	return ""
}

func closedLoopTrue(value any) bool {
	text, ok := closedLoopScalarOK(value)
	return ok && (strings.EqualFold(text, "true") || text == "1")
}

func closedLoopPayloadTruncated(fields, fallback map[string]any) bool {
	for _, f := range []string{"path_truncated", "request_target_truncated", "query_string_truncated"} {
		if closedLoopTrue(closedLoopValue(fields, fallback, f)) {
			return true
		}
	}
	return false
}

func closedLoopEventID(fields, fallback map[string]any, mapping investigation.Mapping, index string, raw []byte) string {
	// Prefer source's native event ID so it joins to audit_event_id in alerts.
	if id := closedLoopScalar(closedLoopValue(fields, fallback, mapping.EventID)); id != "" {
		return id
	}
	if id := closedLoopScalar(fields["_cd"]); id != "" {
		return index + ":" + closedLoopScalar(fields["splunk_server"]) + ":" + closedLoopScalar(fields["_bkt"]) + ":" + id
	}
	return "sha256:" + closedloop.Hash(raw)
}

// EvaluateClosedLoopFile evaluates previously collected uploaded audit evidence.
// It preserves the original upload provenance; it does not call Splunk, emit an
// alert, run an attack, or infer that uploading a matching log means detection.
func EvaluateClosedLoopFile(c Config, q Query, scope investigation.Scope, mapping investigation.Mapping, baseline, candidate closedloop.Rule, evidence *Evidence) (*ClosedLoopSearchResult, error) {
	if evidence == nil || evidence.Upload == nil {
		return nil, fmt.Errorf("%w Original upload proof is required", ErrInvalid)
	}
	if err := validateClosedLoopScope(c, q, scope, mapping); err != nil {
		return nil, err
	}
	if err := validateClosedLoopRules(mapping, baseline, candidate); err != nil {
		return nil, err
	}
	if len(evidence.Upload.Files) == 0 || len(evidence.Upload.Files) > 2 {
		return nil, fmt.Errorf("%w : Original audit·alert upload file is required", ErrInvalid)
	}
	total := 0
	for _, file := range evidence.Upload.Files {
		total += len(file.Content)
		if total > MaxUploadBytes || file.Bytes != len(file.Content) || file.SHA256 != closedloop.Hash([]byte(file.Content)) {
			return nil, fmt.Errorf("%w : The original text, size, and sash of the upload file cannot be checked", ErrInvalid)
		}
	}
	// Result sanitization/export must never mutate the stored original upload.
	uploadJSON, err := json.Marshal(evidence.Upload)
	if err != nil {
		return nil, fmt.Errorf("%w: Failed to preserve upload evidence", ErrInvalid)
	}
	var upload UploadProvenance
	if err = json.Unmarshal(uploadJSON, &upload); err != nil {
		return nil, fmt.Errorf("%w: Failed to preserve upload evidence", ErrInvalid)
	}
	out := newClosedLoopResult(q, baseline, candidate, "file_rule_evaluation")
	out.Engine = "file-shadow-exact-contains-v1"
	out.Complete, out.CollectedAt, out.Upload = evidence.Complete, evidence.CollectedAt, &upload
	out.Warnings = append(out.Warnings, "file_matches_are_not_emitted_alerts", "upload_provenance_attested_by_uploader")
	for _, warning := range evidence.Warnings {
		out.warn(warning)
	}
	if evidence.WindowStart.After(q.Start) || evidence.WindowEnd.Before(q.End) {
		out.warn("Upload evidence does not include the entire execution lookup interval")
	}
	out.Truncated = evidence.Upload.Stats.Truncated
	seen := map[string]string{}
	for _, event := range evidence.Events {
		if event.Kind != "audit" {
			continue
		}
		out.TotalRows++
		if out.TotalRows > investigation.MaxEvents {
			out.Truncated++
			out.warn("Exceeded the event retention limit for file rule evaluation")
			continue
		}
		fields, fallback, err := closedLoopObjects(event.Raw)
		if err != nil {
			out.warn("Failed to interpret file original event")
			continue
		}
		if event.CorrelationID != q.CorrelationID || event.OccurredAt.Before(q.Start) || !event.OccurredAt.Before(q.End) ||
			closedLoopScalar(closedLoopValue(fields, fallback, mapping.VerificationID)) != q.CorrelationID ||
			!investigation.MatchTarget(closedLoopScalar(closedLoopValue(fields, fallback, mapping.Target)), scope.Target) ||
			!investigation.MatchPath(closedLoopScalar(closedLoopValue(fields, fallback, mapping.Path)), scope.PathPrefix) {
			out.warn("There are file events that do not match the execution UUID, destination, path, and visual range")
			continue
		}
		if previous, exists := seen[event.ID]; exists {
			if previous != closedloop.Hash(event.Raw) {
				out.warn("The same file event ID has different logs")
			}
			continue
		}
		seen[event.ID] = closedloop.Hash(event.Raw)
		if closedLoopPayloadTruncated(fields, fallback) {
			out.warn("The file source request field has been sleak. The result of the rule for the entire request cannot be determined.")
		}
		out.Events = append(out.Events, ClosedLoopRuleEvent{EventID: event.ID, OccurredAt: event.OccurredAt,
			Baseline: matchClosedLoopRule(fields, fallback, baseline), Candidate: matchClosedLoopRule(fields, fallback, candidate), Raw: append(json.RawMessage(nil), event.Raw...)})
	}
	return out, nil
}
