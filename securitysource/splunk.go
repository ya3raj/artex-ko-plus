// Package securitysource reads correlated observations from a configured SIEM.
// It never creates alerts, executes caller-supplied SPL, or changes remote rules.
package securitysource

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var ErrInvalid = errors.New("The security log connection settings are not valid")

type Config struct {
	BaseURL          string `json:"base_url"`
	Index            string `json:"index"`
	AuditSourcetype  string `json:"audit_sourcetype"`
	AlertSourcetype  string `json:"alert_sourcetype"`
	CorrelationField string `json:"correlation_field"`
	ActionField      string `json:"action_field"`
	TLSFingerprint   string `json:"tls_fingerprint"`
}
type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Token    string `json:"token"`
}
type Query struct {
	CorrelationID string
	Start, End    time.Time
}
type Event struct {
	ID            string          `json:"id"`
	Kind          string          `json:"kind"`
	CorrelationID string          `json:"correlation_id"`
	OccurredAt    time.Time       `json:"occurred_at"`
	Action        string          `json:"action"`
	Raw           json.RawMessage `json:"raw"`
	FileName      string          `json:"file_name,omitempty"`
	Line          int             `json:"line,omitempty"`
}
type Evidence struct {
	Events      []Event           `json:"events"`
	Complete    bool              `json:"complete"`
	CollectedAt time.Time         `json:"collected_at"`
	WindowStart time.Time         `json:"window_start"`
	WindowEnd   time.Time         `json:"window_end"`
	Warnings    []string          `json:"warnings"`
	Upload      *UploadProvenance `json:"upload,omitempty"`
	Diagnostics []Diagnostic      `json:"diagnostics,omitempty"`
}

var sourceName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.:-]{0,127}$`)
var fieldName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,127}$`)
var correlationName = regexp.MustCompile(`^[A-Za-z0-9-]{16,80}$`)

const maxResponseBytes = 4 << 20
const maxRows = 200

// An explicit numeric offset avoids the ambiguous timezone abbreviations used
// by Splunk's default export format. Preserve microsecond request timestamps.
const splunkOutputTimeFormat = "%Y-%m-%dT%H:%M:%S.%6N%z"

// Splunk's automatic field extraction and spath can extract the same scalar
// twice. Keep automatic fields for non-JSON sources and remove exact duplicates
// only; distinct values stay multivalued for the local parsers to reject.
// Callers validate every field name before constructing a search.
func splunkDeduplicateFields(fields ...string) string {
	seen := make(map[string]bool, len(fields))
	expressions := make([]string, 0, len(fields))
	for _, field := range fields {
		if field == "" || seen[field] {
			continue
		}
		seen[field] = true
		// eval assignment targets need double quotes; single quotes create a
		// literal quote-bearing field instead of updating the extracted field.
		expressions = append(expressions, fmt.Sprintf(`"%s"=mvdedup('%s')`, field, field))
	}
	if len(expressions) == 0 {
		return ""
	}
	return " | eval " + strings.Join(expressions, ", ")
}

func Validate(c Config) (Config, error) {
	c.BaseURL = strings.TrimRight(strings.TrimSpace(c.BaseURL), "/")
	u, e := url.Parse(c.BaseURL)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
		return c, fmt.Errorf("%w : Please enter only HTTPS management address (except route, account, and query)", ErrInvalid)
	}
	if !sourceName.MatchString(c.Index) || !sourceName.MatchString(c.AuditSourcetype) || !sourceName.MatchString(c.AlertSourcetype) || c.AuditSourcetype == c.AlertSourcetype {
		return c, fmt.Errorf("%w : Index and different audit/alert sourcetype are required", ErrInvalid)
	}
	if !fieldName.MatchString(c.CorrelationField) || !fieldName.MatchString(c.ActionField) {
		return c, fmt.Errorf("%w : Please check the name of the Correlation ID and Action field", ErrInvalid)
	}
	c.TLSFingerprint = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(c.TLSFingerprint), ":", ""))
	if c.TLSFingerprint != "" {
		b, e := hex.DecodeString(c.TLSFingerprint)
		if e != nil || len(b) != 32 {
			return c, fmt.Errorf("%w : Certificate SHA-256 must be a 64-digit hexadecimal", ErrInvalid)
		}
	}
	return c, nil
}
func ValidateCredentials(c Credentials) error {
	if c.Token != "" {
		if c.Username != "" || c.Password != "" || len(c.Token) > 8192 || strings.ContainsAny(c.Token, "\r\n\x00") {
			return fmt.Errorf("%w : Use either a token or an account authentication", ErrInvalid)
		}
		return nil
	}
	if c.Username == "" || c.Password == "" || len(c.Username) > 256 || len(c.Password) > 8192 || strings.ContainsAny(c.Username, ":\r\n\x00") || strings.ContainsRune(c.Password, 0) {
		return fmt.Errorf("%w: Requires connection account and password", ErrInvalid)
	}
	return nil
}

func client(c Config) *http.Client {
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if c.TLSFingerprint != "" {
		pin, _ := hex.DecodeString(c.TLSFingerprint)
		// A configured exact leaf-certificate pin replaces PKI validation. It
		// does not allow arbitrary self-signed certificates or redirects.
		tc.InsecureSkipVerify = true
		tc.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("No certificate")
			}
			cert := cs.PeerCertificates[0]
			sum := sha256.Sum256(cert.Raw)
			now := time.Now()
			if subtle.ConstantTimeCompare(sum[:], pin) != 1 || now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
				return errors.New("The server certificate does not match the pin that is stored or has expired")
			}
			return nil
		}
	}
	return &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{Proxy: nil, TLSClientConfig: tc, DisableKeepAlives: true, ResponseHeaderTimeout: 15 * time.Second}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
func request(ctx context.Context, c Config, auth Credentials, path string, form url.Values) ([]byte, error) {
	method := http.MethodGet
	var body io.Reader
	if form != nil {
		method = http.MethodPost
		body = strings.NewReader(form.Encode())
	}
	r, e := http.NewRequestWithContext(ctx, method, c.BaseURL+path, body)
	if e != nil {
		return nil, errors.New("Failed to create security log lookup request")
	}
	if auth.Token != "" {
		r.Header.Set("Authorization", "Bearer "+auth.Token)
	} else {
		r.SetBasicAuth(auth.Username, auth.Password)
	}
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	r.Header.Set("Accept", "application/json")
	h := client(c)
	defer h.CloseIdleConnections()
	res, e := h.Do(r)
	if e != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("Splunk connection failed. Please check address, certificate, network")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Splunk lookup rejected with HTTP %d. Please check your connection account and search permissions", res.StatusCode)
	}
	b, e := io.ReadAll(io.LimitReader(res.Body, maxResponseBytes+1))
	if e != nil {
		return nil, errors.New("I couldn't read the Splunk response to the end")
	}
	if len(b) > maxResponseBytes {
		return nil, errors.New("Splunk response exceeded 4 MiB. Please reduce the search range")
	}
	return b, nil
}

func Test(ctx context.Context, c Config, auth Credentials) error {
	c, e := Validate(c)
	if e != nil {
		return e
	}
	if e = ValidateCredentials(auth); e != nil {
		return e
	}
	b, e := request(ctx, c, auth, "/services/server/info?output_mode=json", nil)
	if e != nil {
		return e
	}
	var v struct {
		Entry []json.RawMessage `json:"entry"`
	}
	if json.Unmarshal(b, &v) != nil || len(v.Entry) == 0 {
		return errors.New("Splunk server information could not be verified")
	}
	return nil
}

func Fetch(ctx context.Context, c Config, auth Credentials, q Query) (*Evidence, error) {
	c, e := Validate(c)
	if e != nil {
		return nil, e
	}
	if e = ValidateCredentials(auth); e != nil {
		return nil, e
	}
	if !correlationName.MatchString(q.CorrelationID) || q.Start.IsZero() || !q.End.After(q.Start) || q.End.Sub(q.Start) > 24*time.Hour || q.End.After(time.Now().Add(5*time.Second)) {
		return nil, fmt.Errorf("%w : Check the execution identifier or search time range (up to 24h)", ErrInvalid)
	}
	out := &Evidence{Events: []Event{}, Complete: true, Warnings: []string{}, WindowStart: q.Start.UTC(), WindowEnd: q.End.UTC()}
	for _, s := range []struct{ kind, st string }{{"audit", c.AuditSourcetype}, {"alert", c.AlertSourcetype}} {
		// Names have restrictive allowlists, and the correlation ID is generated
		// by ARTEX. No free-form query or state-changing command is accepted.
		search := fmt.Sprintf(`search index="%s" sourcetype="%s" | spath%s | where '%s' = "%s" | head %d`, c.Index, s.st, splunkDeduplicateFields(c.CorrelationField, c.ActionField), c.CorrelationField, q.CorrelationID, maxRows+1)
		b, e := request(ctx, c, auth, "/services/search/v2/jobs/export", url.Values{"search": {search}, "output_mode": {"json"}, "output_time_format": {splunkOutputTimeFormat}, "earliest_time": {strconv.FormatFloat(float64(q.Start.UnixNano())/1e9, 'f', 6, 64)}, "latest_time": {strconv.FormatFloat(float64(q.End.UnixNano())/1e9, 'f', 6, 64)}, "preview": {"false"}})
		if e != nil {
			return nil, e
		}
		if e = parseExport(b, s.kind, c, q, out); e != nil {
			return nil, e
		}
	}
	out.CollectedAt = time.Now().UTC()
	return out, nil
}

func field(m map[string]any, name string) any {
	if v, ok := m[name]; ok {
		return v
	}
	var v any = m
	for _, p := range strings.Split(name, ".") {
		obj, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = obj[p]
	}
	return v
}
func textField(v any) string { s, _ := v.(string); return s }
func eventTime(v any) (time.Time, error) {
	s := fmt.Sprint(v)
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999999-0700"} {
		if t, e := time.Parse(layout, s); e == nil {
			return t.UTC(), nil
		}
	}
	if n, e := strconv.ParseFloat(s, 64); e == nil && n > 0 && n < 1e11 {
		return time.Unix(int64(n), int64((n-math.Floor(n))*1e9)).UTC(), nil
	}
	return time.Time{}, errors.New("The visuals are incorrect.")
}
func parseExport(b []byte, kind string, c Config, q Query, out *Evidence) error {
	scan := bufio.NewScanner(strings.NewReader(string(b)))
	scan.Buffer(make([]byte, 4096), maxResponseBytes)
	count := 0
	seen := map[string][32]byte{}
	lastResultComplete, sawTerminal := false, false
	for scan.Scan() {
		if strings.TrimSpace(scan.Text()) == "" {
			continue
		}
		var row struct {
			Result   map[string]any `json:"result"`
			Preview  bool           `json:"preview"`
			LastRow  bool           `json:"lastrow"`
			Messages []struct {
				Type string `json:"type"`
			} `json:"messages"`
			Error any `json:"error"`
		}
		decoder := json.NewDecoder(strings.NewReader(scan.Text()))
		decoder.UseNumber()
		if decoder.Decode(&row) != nil {
			return errors.New("Splunk search response format is invalid")
		}
		if row.Error != nil {
			return errors.New("Splunk search failed")
		}
		for _, msg := range row.Messages {
			switch strings.ToUpper(msg.Type) {
			case "ERROR", "FATAL":
				return errors.New("Splunk search not finished")
			case "WARN", "WARNING":
				out.Complete = false
				out.Warnings = append(out.Warnings, "Splunk returned a search alert. You should check for missing")
			case "INFO", "DEBUG":
			default:
				out.Complete = false
				out.Warnings = append(out.Warnings, "Failed to identify type of Splunk search diagnosis")
			}
		}
		if row.Preview {
			out.Complete = false
			out.Warnings = append(out.Warnings, "Splunk preview results are not judged by completed search")
			continue
		}
		if row.Result == nil {
			// An actual completed zero-result export sends only preview:false
			// and lastrow:true. It is not a missing or malformed event.
			if row.LastRow {
				sawTerminal = true
			} else if len(row.Messages) == 0 {
				out.Complete = false
				out.Warnings = append(out.Warnings, "The search result format is not confirmed, so it withholds the judgment")
			}
			continue
		}
		count++
		lastResultComplete, sawTerminal = row.LastRow, false
		if count > maxRows {
			out.Complete = false
			out.Warnings = append(out.Warnings, kind+" Searches exceed 200cases and withhold judgment")
			continue
		}
		m := row.Result
		var raw map[string]any
		if s, ok := m["_raw"].(string); ok {
			d := json.NewDecoder(strings.NewReader(s))
			d.UseNumber()
			_ = d.Decode(&raw)
		}
		correlation := field(m, c.CorrelationField)
		if correlation == nil {
			correlation = field(raw, c.CorrelationField)
		}
		t, te := eventTime(m["_time"])
		if textField(correlation) != q.CorrelationID || te != nil || t.Before(q.Start) || !t.Before(q.End) {
			out.Complete = false
			out.Warnings = append(out.Warnings, "An execution identifier or an event with an incorrect view has been returned.")
			continue
		}
		payload, e := json.Marshal(m)
		if e != nil {
			return errors.New("Log original text could not be preserved")
		}
		if len(payload) > 128<<10 || strings.Contains(string(payload), `\u0000`) {
			out.Complete = false
			out.Warnings = append(out.Warnings, "Excluded events with characters that exceed the retention limit or are not supported.")
			continue
		}
		id := textField(m["_cd"])
		sum := sha256.Sum256(payload)
		if id == "" {
			id = hex.EncodeToString(sum[:])
		}
		id = c.Index + ":" + textField(m["splunk_server"]) + ":" + textField(m["_bkt"]) + ":" + id
		if previous, exists := seen[id]; exists {
			if previous != sum {
				out.Complete = false
				out.Warnings = append(out.Warnings, "Different grounds are returned to the same event ID, pending the decision")
			}
			continue
		}
		seen[id] = sum
		a := field(m, c.ActionField)
		if a == nil {
			a = field(raw, c.ActionField)
		}
		action := "unknown"
		switch strings.ToLower(textField(a)) {
		case "block", "blocked", "deny", "denied":
			action = "blocked"
		case "allow", "allowed", "pass", "passed":
			action = "allowed"
		}
		out.Events = append(out.Events, Event{ID: id, Kind: kind, CorrelationID: q.CorrelationID, OccurredAt: t, Action: action, Raw: payload})
	}
	if scan.Err() != nil {
		return errors.New("Splunk search response has been scuttized")
	}
	if (count > 0 && !lastResultComplete && !sawTerminal) || (count == 0 && !sawTerminal) {
		out.Complete = false
		out.Warnings = append(out.Warnings, "Splunk search failed to confirm completion of the search because it did not show the last result")
	}
	return nil
}
