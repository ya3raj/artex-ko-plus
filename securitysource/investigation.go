package securitysource

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/investigation"
)

// BuildInvestigationSearch generates only a bounded, read-only historical
// search. Its values never become SPL commands or search-language wildcards.
// Time bounds are submitted separately to the export endpoint by the fetcher.
func BuildInvestigationSearch(c Config, scope investigation.Scope, mapping investigation.Mapping, sourcetypes []string) (string, error) {
	c, err := Validate(c)
	if err != nil {
		return "", err
	}
	if err = investigation.ValidateScope(scope, time.Now().UTC()); err != nil {
		return "", err
	}
	if err = investigation.ValidateMapping(mapping); err != nil {
		return "", err
	}
	effectiveMapping := mapping
	effectiveMapping.Timestamp = "_time"
	if err = investigation.ValidateMapping(effectiveMapping); err != nil {
		return "", err
	}
	if mapping.Target == "" || (scope.PathPrefix != "" && mapping.Path == "") {
		return "", fmt.Errorf("%w : Map Splunk target fields and route fields required for the path range", ErrInvalid)
	}
	if len(sourcetypes) == 0 {
		sourcetypes = []string{c.AuditSourcetype, c.AlertSourcetype}
	}
	if len(sourcetypes) > 8 {
		return "", fmt.Errorf("%w : The probe sourcetype can select up to eight", ErrInvalid)
	}
	parts := make([]string, 0, len(sourcetypes))
	seen := make(map[string]bool)
	for _, st := range sourcetypes {
		if !sourceName.MatchString(st) || seen[st] {
			return "", fmt.Errorf("%w : Enter a sourcetype name without duplicates", ErrInvalid)
		}
		seen[st] = true
		parts = append(parts, "sourcetype="+investigationLiteral(st))
	}

	// A hostname scope includes all its ports; an explicitly supplied port is
	// retained. The bounded regexp is generated from literal validated values.
	// Hostnames inside full HTTP URLs and ordinary host fields are supported.
	parsedTarget, _ := url.Parse("//" + scope.Target) // Scope validation succeeded.
	host := strings.TrimSuffix(strings.ToLower(parsedTarget.Hostname()), ".")
	port := parsedTarget.Port()
	if port != "" {
		number, _ := strconv.Atoi(port)
		port = strconv.Itoa(number)
	}
	authority := regexp.QuoteMeta(host)
	if strings.Contains(host, ":") {
		authority = `\[` + authority + `\]`
	} else {
		authority += `\.?`
	}
	httpAuthority, httpsAuthority, bareAuthority := authority, authority, authority
	if port == "" {
		httpAuthority += `(?::[0-9]+)?`
		httpsAuthority = httpAuthority
		bareAuthority = httpAuthority
	} else {
		portPattern := `:0*` + port
		bareAuthority += portPattern
		httpAuthority += portPattern
		httpsAuthority += portPattern
		if port == "80" {
			httpAuthority = authority + `(?::0*80)?`
		}
		if port == "443" {
			httpsAuthority = authority + `(?::0*443)?`
		}
	}
	targetPattern := `(?i)^(?:http://` + httpAuthority + `(?:[/?#].*)?|https://` + httpsAuthority + `(?:[/?#].*)?|` + bareAuthority + `)$`
	// Preserve native extraction and provenance for plain-text as well as JSON
	// logs. Duplicate extraction of one value must not turn a scoped field into
	// an ambiguous array; genuine conflicting values remain ambiguous.
	// Search/export time is always Splunk's canonical _time, including when a
	// saved collection is rebuilt later for an investigation follow-up.
	uniqueFields := splunkDeduplicateFields(mapping.EventID,
		mapping.Target, mapping.Path, mapping.SourceIP, mapping.User, mapping.Session,
		mapping.Action, mapping.Status, mapping.Bytes, mapping.VerificationID,
		mapping.EventKind, mapping.ResponseComplete, "_time", "sourcetype", "source", "host", "index")
	search := "search index=" + investigationLiteral(c.Index) + " (" + strings.Join(parts, " OR ") + ") | spath" + uniqueFields + " | where match(trim(tostring('" + mapping.Target + "')), " + investigationLiteral(targetPattern) + ")"
	if scope.PathPrefix != "" && scope.PathPrefix != "/" {
		prefix := strings.TrimRight(scope.PathPrefix, "/")
		// Decode once, remove URL query/fragment, and compare at a path boundary.
		// Protect literal '+' before urldecode because that function applies
		// query-style decoding whereas the domain parser uses PathUnescape.
		pathExpression := "urldecode(replace(replace(replace(tostring('" + mapping.Path + "'), \"(?i)^https?://[^/?#]*\", \"\"), \"[?#].*$\", \"\"), \"[+]\", \"%2B\"))"
		search += " | where (" + pathExpression + " = " + investigationLiteral(prefix) + " OR substr(" + pathExpression + ", 1, " + strconv.Itoa(len([]rune(prefix))+1) + ") = " + investigationLiteral(prefix+"/") + ")"
	}
	return search + " | head " + strconv.Itoa(investigation.MaxRows+1), nil
}

// SPL eval string literals use backslash escapes. Unlike search terms, regex
// patterns here are built exclusively from quoted values, and substr equality
// treats asterisks, percent signs, and underscores literally.
func investigationLiteral(value string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\r", `\r`, "\n", `\n`, "\t", `\t`).Replace(value) + `"`
}

// FetchInvestigation performs no writes in Splunk. Existing connection TLS and
// credential restrictions also apply to historical queries; unlike verification
// searches these never require an ARTEX execution UUID.
func FetchInvestigation(ctx context.Context, c Config, auth Credentials, scope investigation.Scope, mapping investigation.Mapping, sourcetypes, knownVerificationIDs []string) (investigation.Collection, error) {
	var empty investigation.Collection
	var err error
	c, err = Validate(c)
	if err != nil {
		return empty, err
	}
	if err = ValidateCredentials(auth); err != nil {
		return empty, err
	}
	search, err := BuildInvestigationSearch(c, scope, mapping, sourcetypes)
	if err != nil {
		return empty, err
	}
	return fetchInvestigationQuery(ctx, c, auth, scope, mapping, knownVerificationIDs, search)
}

// Only locally generated, validated queries reach this private transport helper.
func fetchInvestigationQuery(ctx context.Context, c Config, auth Credentials, scope investigation.Scope, mapping investigation.Mapping, knownVerificationIDs []string, search string) (investigation.Collection, error) {
	var empty investigation.Collection
	// request limits the exact export body to 4 MiB. Keeping both that body and
	// its result-only JSONL remains within the shared 8 MiB evidence bound.
	body, err := request(ctx, c, auth, "/services/search/v2/jobs/export", url.Values{
		"search": {search}, "output_mode": {"json"}, "preview": {"false"},
		"output_time_format": {splunkOutputTimeFormat},
		"earliest_time":      {investigationEpoch(scope.Start)}, "latest_time": {investigationEpoch(scope.End)},
	})
	if err != nil {
		return empty, err
	}
	results, rows, complete, warnings, err := parseInvestigationExport(body)
	if err != nil {
		return empty, err
	}
	// Splunk's selected time window refers to _time, not arbitrary timestamps
	// inside _raw. Keep the exact returned event and its time/metadata together.
	mapping.Timestamp = "_time"
	out, err := investigation.ParseFiles([]investigation.InputFile{{Name: "splunk-events.jsonl", Content: string(results)}}, scope, mapping, complete, false, knownVerificationIDs)
	if err != nil {
		return empty, err
	}
	out.SourceKind = "splunk"
	out.Query = search
	out.CollectedAt = time.Now().UTC()
	out.CoverageConfirmed = complete
	out.Complete = out.Complete && complete
	for i, warning := range out.Warnings {
		switch warning {
		case "The scope of the file's origin and inquiry depends on the uploader's confirmation. Keep the search conditions and files on the original system.":
			out.Warnings[i] = "This is the result of running the search formula generated by the saved Splunk connection. The completion of the query does not guarantee the retention period of the original log or the collection range."
		case "There is no confirmation that the full results of the investigation time and the target have been collected.":
			out.Warnings[i] = "We have not been able to verify the full collection of Splunk search responses. Check the search diagnostics and results limits."
		}
	}
	out.Warnings = append(out.Warnings, warnings...)
	if rows > investigation.MaxRows {
		out.Stats.Truncated += rows - investigation.MaxRows
	}
	sum := sha256.Sum256(body)
	out.Files = append(out.Files, investigation.FileEvidence{Name: "splunk-export.jsonl", SHA256: hex.EncodeToString(sum[:]), Bytes: len(body), Rows: rows, Content: string(body)})
	return out, nil
}

func investigationEpoch(t time.Time) string {
	return strconv.FormatInt(t.Unix(), 10) + "." + fmt.Sprintf("%09d", t.Nanosecond())
}

// The exact stream is retained separately. We extract RawMessage result bytes
// without decoding and re-encoding numbers or rewriting upstream field values.
func parseInvestigationExport(body []byte) ([]byte, int, bool, []string, error) {
	var result bytes.Buffer
	rows, complete := 0, true
	warnings := []string{}
	warn := func(message string) {
		complete = false
		for _, existing := range warnings {
			if existing == message {
				return
			}
		}
		warnings = append(warnings, message)
	}
	scan := bufio.NewScanner(bytes.NewReader(body))
	scan.Buffer(make([]byte, 4096), maxResponseBytes)
	lastResultComplete, sawTerminal := false, false
	for scan.Scan() {
		line := bytes.TrimSpace(scan.Bytes())
		if len(line) == 0 {
			continue
		}
		var row struct {
			Result   json.RawMessage `json:"result"`
			Preview  bool            `json:"preview"`
			LastRow  bool            `json:"lastrow"`
			Messages []struct {
				Type string `json:"type"`
			} `json:"messages"`
			Error json.RawMessage `json:"error"`
		}
		if err := decodeInvestigationEnvelope(line, &row); err != nil {
			return nil, 0, false, nil, errors.New("Splunk past log response format is invalid")
		}
		if len(row.Error) != 0 && string(row.Error) != "null" {
			return nil, 0, false, nil, errors.New("Splunk past log search failed")
		}
		for _, message := range row.Messages {
			switch strings.ToUpper(message.Type) {
			case "ERROR", "FATAL":
				return nil, 0, false, nil, errors.New("Splunk past log search is not complete")
			case "WARN", "WARNING":
				warn("Splunk returned a search alert. Check missing views and search limits")
			case "INFO", "DEBUG":
			default:
				warn("Failed to identify type of Splunk search diagnosis")
			}
		}
		if row.Preview {
			warn("Splunk returns preview results so you can't check the full collection")
			continue
		}
		if len(row.Result) == 0 || string(row.Result) == "null" {
			if row.LastRow {
				sawTerminal = true
			} else if len(row.Messages) == 0 {
				warn("Splunk There are items that have not been checked for search results format")
			}
			continue
		}
		if row.Result[0] != '{' {
			return nil, 0, false, nil, errors.New("Splunk Past log event format is invalid")
		}
		rows++
		sawTerminal = false
		lastResultComplete = row.LastRow
		if rows > investigation.MaxRows {
			warn("Splunk views exceeded 10,000. Narrow down your duration or path to re-equ track")
			continue
		}
		if len(row.Result) > investigation.MaxRecordBytes {
			warn("Splunk events exceeding the retention limit of 128 KiB have been excluded from the analysis")
			continue
		}
		result.Write(row.Result)
		result.WriteByte('\n')
	}
	if err := scan.Err(); err != nil {
		return nil, 0, false, nil, errors.New("Splunk past log search response has been scuttized")
	}
	if rows > 0 && !lastResultComplete && !sawTerminal {
		warn("Splunk search failed to confirm completion of the search because it did not show the last result")
	}
	// A successful empty export is a valid zero-result search. It is not a
	// claim about retained logs, sensor coverage, or whether compromise occurred.
	return result.Bytes(), rows, complete, warnings, nil
}

func decodeInvestigationEnvelope(data []byte, value any) error {
	// Reject ambiguous duplicate envelope keys before normal decoding; source
	// event duplicate-field handling is the shared domain parser's job.
	d := json.NewDecoder(bytes.NewReader(data))
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		return errors.New("invalid envelope")
	}
	seen := map[string]bool{}
	for d.More() {
		key, err := d.Token()
		if err != nil {
			return err
		}
		name, ok := key.(string)
		if !ok || seen[name] {
			return errors.New("duplicate envelope key")
		}
		seen[name] = true
		var raw json.RawMessage
		if err = d.Decode(&raw); err != nil {
			return err
		}
	}
	if _, err = d.Token(); err != nil {
		return err
	}
	if _, err = d.Token(); err != io.EOF {
		return errors.New("trailing response")
	}
	return json.Unmarshal(data, value)
}
