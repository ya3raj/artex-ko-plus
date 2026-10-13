package investigation

import (
	"bufio"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

var ErrInvalid = errors.New("Infringement investigation input is incorrect")
var fieldName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,127}$`)
var hostName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$`)

func invalid(s string) error { return fmt.Errorf("%w: %s", ErrInvalid, s) }
func ValidateScope(s Scope, now time.Time) error {
	if s.Target != strings.TrimSpace(s.Target) || strings.ContainsAny(s.Target, "/?#@\\\r\n\t ") {
		return invalid("Target, type in the host name or host:port without URL path")
	}
	if _, _, ok := targetParts(s.Target); !ok {
		return invalid("Check the destination host/port")
	}
	if len(s.PathPrefix) > 2048 || (s.PathPrefix != "" && (!strings.HasPrefix(s.PathPrefix, "/") || strings.ContainsAny(s.PathPrefix, "?#%\\\r\n\t\x00"))) {
		return invalid("Enter the path range as a decoded path starting with / (except for query and traggments)")
	}
	if !utf8.ValidString(s.PathPrefix) {
		return invalid("The path must be UTF-8")
	}
	if s.Start.IsZero() || !s.End.After(s.Start) || s.End.Sub(s.Start) > 31*24*time.Hour || s.End.After(now) {
		return invalid("The survey section is up to 31days at the time of the beginning and end of the past")
	}
	return nil
}
func ValidateMapping(m Mapping) error {
	if m.Timestamp == "" {
		return invalid("Requires visual field mapping")
	}
	seen := map[string]bool{}
	for _, f := range []string{m.Timestamp, m.EventID, m.Target, m.Path, m.SourceIP, m.User, m.Session, m.Action, m.Status, m.Bytes, m.VerificationID, m.EventKind, m.ResponseComplete} {
		if f == "" {
			continue
		}
		if !fieldName.MatchString(f) {
			return invalid("The field name must be in English, numbers, underscores, points, and hyphens in 128characters.")
		}
		if seen[f] {
			return invalid("Cannot map different semantic fields to the same source field")
		}
		seen[f] = true
	}
	return nil
}
func targetParts(value string) (string, string, bool) {
	if strings.ContainsAny(value, "\r\n\t \\") || len(value) > 1024 {
		return "", "", false
	}
	u, err := url.Parse("//" + value)
	if err != nil || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", "", false
	}
	h := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	p := u.Port()
	if net.ParseIP(h) == nil && (!hostName.MatchString(h) || strings.Contains(h, "..")) {
		return "", "", false
	}
	if p != "" {
		n, e := strconv.Atoi(p)
		if e != nil || n < 1 || n > 65535 {
			return "", "", false
		}
		p = strconv.Itoa(n)
	}
	if strings.HasSuffix(value, ":") {
		return "", "", false
	}
	return h, p, true
}

// MatchTarget accepts a host/authority or HTTP(S) URL in an event. An explicit
// scope port must also be present (or implied by an event URL's scheme).
func MatchTarget(eventTarget, scopeTarget string) bool {
	h, p, ok := targetParts(scopeTarget)
	if !ok {
		return false
	}
	eh, ep, eok := eventTargetParts(eventTarget)
	return eok && eh == h && (p == "" || ep == p)
}
func eventTargetParts(eventTarget string) (string, string, bool) {
	v := strings.TrimSpace(eventTarget)
	scheme := ""
	if strings.Contains(v, "://") {
		u, e := url.Parse(v)
		if e != nil || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") {
			return "", "", false
		}
		v = u.Host
		scheme = u.Scheme
	}
	eh, ep, eok := targetParts(v)
	if !eok {
		return "", "", false
	}
	if ep == "" {
		if scheme == "http" {
			ep = "80"
		}
		if scheme == "https" {
			ep = "443"
		}
	}
	return eh, ep, true
}
func normalizedPath(path string) (string, bool) {
	if strings.Contains(path, "://") {
		u, e := url.Parse(path)
		if e != nil || (u.Scheme != "http" && u.Scheme != "https") {
			return "", false
		}
		path = u.EscapedPath()
	}
	path = strings.SplitN(strings.SplitN(path, "?", 2)[0], "#", 2)[0]
	p, e := url.PathUnescape(path)
	if e != nil || !strings.HasPrefix(p, "/") || strings.ContainsAny(p, "\x00\r\n") {
		return "", false
	}
	return p, true
}
func MatchPath(path, prefix string) bool {
	p, ok := normalizedPath(path)
	if !ok {
		return false
	}
	prefix = strings.TrimRight(prefix, "/")
	return prefix == "" || p == prefix || strings.HasPrefix(p, prefix+"/")
}

// ParseFiles keeps original bytes and stable file+row references. Invalid rows
// cannot silently turn a search into "not observed"; limits are explicit errors
// or mark the selected collection incomplete.
func ParseFiles(files []InputFile, s Scope, m Mapping, coverageConfirmed, targetScopeConfirmed bool, knownVerificationIDs []string) (Collection, error) {
	out := Collection{SourceKind: "file", CollectedAt: time.Now().UTC(), Scope: s, Mapping: m, CoverageConfirmed: coverageConfirmed, TargetScopeConfirmed: targetScopeConfirmed, Events: []Event{}, Files: []FileEvidence{}, Complete: coverageConfirmed, Warnings: []string{}}
	if err := ValidateScope(s, out.CollectedAt); err != nil {
		return out, err
	}
	if err := ValidateMapping(m); err != nil {
		return out, err
	}
	if len(files) < 1 || len(files) > 20 {
		return out, invalid("Choose 1 to 20 files")
	}
	if !coverageConfirmed {
		out.Warnings = append(out.Warnings, "There is no confirmation that the full results of the investigation time and the target have been collected.")
	}
	out.Warnings = append(out.Warnings, "The scope of the file's origin and inquiry depends on the uploader's confirmation. Keep the search conditions and files on the original system.")
	known := map[string]bool{}
	for _, id := range knownVerificationIDs {
		if id != "" {
			known[strings.ToLower(id)] = true
		}
	}
	total := 0
	ambiguousSources := 0
	names := map[string]bool{}
	hashes := map[string]bool{}
	warn := func(message string) {
		out.Complete = false
		if len(out.Warnings) < 25 {
			out.Warnings = append(out.Warnings, message)
		}
	}
	bad := func(file string, line int, reason string) {
		out.Stats.InvalidEvents++
		warn(fmt.Sprintf("%s:%d %s", file, line, reason))
	}
	for _, f := range files {
		total += len(f.Content)
		if total > MaxUploadBytes {
			return out, invalid("The total file must be less than 8 MiB")
		}
		if strings.TrimSpace(f.Name) == "" || len(f.Name) > 255 || !utf8.ValidString(f.Name) || strings.ContainsAny(f.Name, "\x00\r\n") {
			return out, invalid("Check the file name")
		}
		if names[f.Name] {
			return out, invalid("You cannot choose to duplicate files of the same name")
		}
		names[f.Name] = true
		if !utf8.ValidString(f.Content) || strings.ContainsRune(f.Content, 0) {
			return out, invalid("The file must be UTF-8 text without NUL characters")
		}
		sum := sha256.Sum256([]byte(f.Content))
		hash := hex.EncodeToString(sum[:])
		if hashes[hash] && strings.TrimSpace(f.Content) != "" {
			return out, invalid("The same original file has been duplicated")
		}
		hashes[hash] = true
		fe := FileEvidence{Name: f.Name, SHA256: hash, Bytes: len(f.Content), Content: f.Content}
		err := readRows(f, func(fields map[string]any, raw string, line int) error {
			fe.Rows++
			out.Stats.TotalRows++
			if out.Stats.TotalRows > MaxRows {
				return invalid("The total file event must be less than one thousand")
			}
			// Splunk _raw is evidence, never instructions. A JSON object inside it
			// can supply missing extracted fields, with the same strict parser.
			var fallback map[string]any
			if rawValue, ok := fields["_raw"].(string); ok && strings.HasPrefix(strings.TrimSpace(rawValue), "{") {
				var er error
				fallback, er = decodeObject(rawValue)
				if er != nil {
					bad(f.Name, line, "_raw Unable to interpret JSON: "+er.Error())
					return nil
				}
			}
			get := func(key string) any {
				if key == "" {
					return nil
				}
				if v, ok := lookup(fields, key); ok {
					return v
				}
				v, _ := lookup(fallback, key)
				return v
			}
			when, er := parseTime(get(m.Timestamp))
			if er != nil {
				bad(f.Name, line, "The visual field cannot be interpreted as RFC 3339 or Unix seconds")
				return nil
			}
			if when.Before(s.Start) || !when.Before(s.End) {
				out.Stats.OutsideWindow++
				return nil
			}
			target, ok := textField(get(m.Target))
			if !ok {
				bad(f.Name, line, "The target field is not a string")
				return nil
			}
			if target == "" {
				out.Stats.MissingTarget++
				if !targetScopeConfirmed {
					bad(f.Name, line, "There is no target field and there is no confirmation that only the asset has been sent out")
					return nil
				}
			} else {
				if _, _, valid := eventTargetParts(target); !valid {
					bad(f.Name, line, "Unable to interpret target host/URL format")
					return nil
				}
				if !MatchTarget(target, s.Target) {
					out.Stats.UnrelatedTarget++
					return nil
				}
			}
			path, ok := textField(get(m.Path))
			if !ok {
				bad(f.Name, line, "The request path is not a string")
				return nil
			}
			if path == "" && s.PathPrefix != "" {
				bad(f.Name, line, "There is no request path required to check the route range")
				return nil
			}
			if path != "" {
				if _, valid := normalizedPath(path); !valid {
					bad(f.Name, line, "Could not interpret request path")
					return nil
				}
				if !MatchPath(path, s.PathPrefix) {
					out.Stats.UnrelatedPath++
					return nil
				}
			}
			fieldsText := []string{m.EventID, m.SourceIP, m.User, m.Session, m.Action, m.Status, m.VerificationID, m.EventKind}
			values := make([]string, len(fieldsText))
			for i, key := range fieldsText {
				values[i], ok = scalar(get(key))
				if !ok || len(values[i]) > 4096 {
					bad(f.Name, line, "Select Field "+key+" I can't interpret the value")
					return nil
				}
			}
			ref := fmt.Sprintf("%s:%d", hash, fe.Rows)
			id := values[0]
			if id == "" {
				id = ref
			}
			st, stOK := textField(fields["sourcetype"])
			src, sourceAmbiguous, srcOK := sourceMetadata(fields["source"])
			host, hostOK := textField(fields["host"])
			index, indexOK := textField(fields["index"])
			if !stOK || !srcOK || !hostOK || !indexOK {
				bad(f.Name, line, "Log Source Metadata is not a string")
				return nil
			}
			sourceKey, _ := json.Marshal([]string{f.Name, st, src, host, index})
			if sourceAmbiguous {
				// JSON payloads can also have a source key. Splunk may merge it
				// with indexed metadata. Keep the scoped event and every raw
				// value, but never pick one origin or join these records as a flow.
				sourceKey, _ = json.Marshal([]string{f.Name, st, src, host, index, ref})
			}
			source := string(sourceKey)
			e := Event{Ref: ref, ID: id, Timestamp: when, Target: target, Path: path, SourceIP: values[1], User: values[2], Session: values[3], Action: values[4], Status: values[5], VerificationID: values[6], EventKind: strings.ToLower(values[7]), FileName: f.Name, Source: source, Line: line, Raw: raw}
			e.SourceAmbiguous = sourceAmbiguous
			if b := get(m.Bytes); b != nil && b != "" {
				bv, valid := scalar(b)
				n, er := strconv.ParseInt(bv, 10, 64)
				if !valid || er != nil || n < 0 {
					bad(f.Name, line, "The transfer byte field is not a negative integer")
					return nil
				}
				e.Bytes = &n
			}
			if b := get(m.ResponseComplete); b != nil && b != "" {
				var val bool
				switch v := b.(type) {
				case bool:
					val = v
				case string:
					var er error
					val, er = strconv.ParseBool(v)
					if er != nil {
						bad(f.Name, line, "Unable to interpret the completed response field as a bullion")
						return nil
					}
				default:
					bad(f.Name, line, "Unable to interpret the completed response field as a bullion")
					return nil
				}
				e.ResponseComplete = &val
			}
			if e.VerificationID != "" {
				if known[strings.ToLower(e.VerificationID)] {
					e.KnownARTEX = true
					out.Stats.KnownARTEX++
				} else {
					out.Stats.UnrecognizedMarkers++
				}
			}
			if len(out.Events) >= MaxEvents {
				out.Stats.Truncated++
				out.Complete = false
				return nil
			}
			out.Events = append(out.Events, e)
			out.Stats.Selected++
			if sourceAmbiguous {
				ambiguousSources++
			}
			return nil
		})
		if err != nil {
			return out, fmt.Errorf("%w (%s)", err, f.Name)
		}
		out.Files = append(out.Files, fe)
	}
	if out.Stats.Truncated > 0 {
		warn(fmt.Sprintf("The selection event limit exceeded %d 2000cases and was not included in the analysis. Please narrow down the duration and route to collect again.", out.Stats.Truncated))
	}
	if ambiguousSources > 0 {
		out.Complete = false
		out.Warnings = append(out.Warnings, fmt.Sprintf("There are different source values in the source field of the event %d . The source and individual behavior were preserved and excluded from the request flow connection from the same source. See the Splunk metadata and JSON internal source fields.", ambiguousSources))
	}
	if out.Stats.MissingTarget > 0 && targetScopeConfirmed {
		out.Warnings = append(out.Warnings, "Events without a target field use the asset range that the uploader has verified. The event itself is not a proven asset.")
	}
	if out.Stats.UnrecognizedMarkers > 0 {
		out.Warnings = append(out.Warnings, "There is a verification mark that does not match the known ARTEX execution. The markings alone did not exclude it from the check traffic.")
	}
	return out, nil
}

func scalar(v any) (string, bool) {
	switch x := v.(type) {
	case nil:
		return "", true
	case string:
		return x, true
	case json.Number:
		return x.String(), true
	default:
		return "", false
	}
}
func textField(v any) (string, bool) {
	if v == nil {
		return "", true
	}
	s, ok := v.(string)
	return s, ok
}

// Only provenance source metadata admits a bounded string array. Scope,
// identity, action and time fields remain strictly scalar. Equal duplicates
// have one unambiguous value; conflicting values are preserved, never chosen.
func sourceMetadata(v any) (string, bool, bool) {
	if s, ok := textField(v); ok {
		return s, false, true
	}
	values, ok := v.([]any)
	if !ok || len(values) == 0 || len(values) > 32 {
		return "", false, false
	}
	unique := []string{}
	seen := map[string]bool{}
	for _, value := range values {
		s, valid := value.(string)
		if !valid || len(s) > 4096 {
			return "", false, false
		}
		if !seen[s] {
			unique = append(unique, s)
			seen[s] = true
		}
	}
	if len(unique) == 1 {
		return unique[0], false, true
	}
	b, _ := json.Marshal(unique)
	return string(b), true, true
}
func lookup(m map[string]any, key string) (any, bool) {
	if v, ok := m[key]; ok {
		return v, true
	}
	var v any = m
	for _, p := range strings.Split(key, ".") {
		mm, ok := v.(map[string]any)
		if !ok {
			return nil, false
		}
		v, ok = mm[p]
		if !ok {
			return nil, false
		}
	}
	return v, true
}
func parseTime(v any) (time.Time, error) {
	s, ok := scalar(v)
	if !ok || s == "" {
		return time.Time{}, errors.New("missing")
	}
	// Splunk export is explicitly requested with a numeric offset (%z). Do not
	// guess the offset of default export timezone abbreviations such as CST.
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999999-0700"} {
		if t, e := time.Parse(layout, s); e == nil {
			return t.UTC(), nil
		}
	}
	n, e := strconv.ParseFloat(s, 64)
	if e != nil || math.IsNaN(n) || math.IsInf(n, 0) || n < 0 || n > 253402300799 {
		return time.Time{}, errors.New("timestamp")
	}
	whole, frac := math.Modf(n)
	return time.Unix(int64(whole), int64(frac*1e9)).UTC(), nil
}

func readRows(f InputFile, visit func(map[string]any, string, int) error) error {
	content := strings.TrimPrefix(f.Content, "\ufeff")
	trim := strings.TrimSpace(content)
	if strings.HasSuffix(strings.ToLower(f.Name), ".csv") {
		r := csv.NewReader(strings.NewReader(content))
		header, e := r.Read()
		if e == io.EOF {
			return nil
		}
		if e != nil {
			return invalid("Unable to read CSV header")
		}
		seen := map[string]bool{}
		for _, h := range header {
			if h == "" || seen[h] {
				return invalid("There is an empty field or duplicate field in the CSV header")
			}
			seen[h] = true
		}
		for {
			start := r.InputOffset()
			row, e := r.Read()
			if e == io.EOF {
				return nil
			}
			if e != nil {
				return invalid("CSV row format is not valid")
			}
			end := r.InputOffset()
			if end-start > MaxRecordBytes {
				return invalid("One event must be 128 KiB or less.")
			}
			line, _ := r.FieldPos(0)
			fields := map[string]any{}
			for i, v := range row {
				fields[header[i]] = v
			}
			if e = visit(fields, content[start:end], line); e != nil {
				return e
			}
		}
	}
	if strings.HasPrefix(trim, "[") {
		d := json.NewDecoder(strings.NewReader(content))
		d.UseNumber()
		if _, e := d.Token(); e != nil {
			return invalid("Could not read JSON array")
		}
		for d.More() {
			start := d.InputOffset()
			var raw json.RawMessage
			if e := d.Decode(&raw); e != nil {
				return invalid("JSON array entry is invalid")
			}
			if len(raw) > MaxRecordBytes {
				return invalid("One event must be 128 KiB or less.")
			}
			fields, e := decodeObject(string(raw))
			if e != nil {
				return invalid(e.Error())
			}
			prefix := content[:start]
			line := strings.Count(prefix, "\n") + 1
			between := content[start:d.InputOffset()]
			i := strings.Index(between, "{")
			if i >= 0 {
				line += strings.Count(between[:i], "\n")
			}
			if e = visit(fields, string(raw), line); e != nil {
				return e
			}
		}
		if _, e := d.Token(); e != nil {
			return invalid("JSON array is not finished")
		}
		var extra any
		if e := d.Decode(&extra); e != io.EOF {
			return invalid("There are additionals after the JSON array")
		}
		return nil
	}
	// A formatted single JSON object is accepted as one record. JSONL remains
	// line-oriented so file/line evidence refers to the actual original row.
	if strings.HasPrefix(trim, "{") {
		if fields, e := decodeObject(trim); e == nil {
			if len(trim) > MaxRecordBytes {
				return invalid("One event must be 128 KiB or less.")
			}
			line := strings.Count(content[:strings.Index(content, "{")], "\n") + 1
			return visit(fields, trim, line)
		}
	}
	scan := bufio.NewScanner(strings.NewReader(content))
	scan.Buffer(make([]byte, 4096), MaxRecordBytes+1)
	line := 0
	for scan.Scan() {
		line++
		raw := scan.Text()
		if strings.TrimSpace(raw) == "" {
			continue
		}
		if len(raw) > MaxRecordBytes {
			return invalid("One event must be 128 KiB or less.")
		}
		fields, e := decodeObject(raw)
		if e != nil {
			return invalid(fmt.Sprintf("Line %d: invalid JSON: %s", line, e.Error()))
		}
		if e = visit(fields, raw, line); e != nil {
			return e
		}
	}
	if scan.Err() != nil {
		return invalid("One event must be 128 KiB or less.")
	}
	return nil
}
func decodeObject(s string) (map[string]any, error) {
	d := json.NewDecoder(strings.NewReader(s))
	d.UseNumber()
	v, e := decodeValue(d, 0)
	if e != nil {
		return nil, e
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("The event must be a JSON object")
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, errors.New("There are additional details after the JSON object")
	}
	return m, nil
}
func decodeValue(d *json.Decoder, depth int) (any, error) {
	if depth > 64 {
		return nil, errors.New("JSON overlapping depth should be less than 64steps")
	}
	t, e := d.Token()
	if e != nil {
		return nil, errors.New("Could not interpret JSON syntax")
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return t, nil
	}
	switch delim {
	case '{':
		m := map[string]any{}
		for d.More() {
			kt, e := d.Token()
			if e != nil {
				return nil, e
			}
			key, ok := kt.(string)
			if !ok {
				return nil, errors.New("JSON field name is invalid")
			}
			if _, exists := m[key]; exists {
				return nil, errors.New("There is a duplicate JSON field: " + key)
			}
			v, e := decodeValue(d, depth+1)
			if e != nil {
				return nil, e
			}
			m[key] = v
		}
		_, e = d.Token()
		return m, e
	case '[':
		a := []any{}
		for d.More() {
			v, e := decodeValue(d, depth+1)
			if e != nil {
				return nil, e
			}
			a = append(a, v)
		}
		_, e = d.Token()
		return a, e
	default:
		return nil, errors.New("JSON separator is not correct")
	}
}
