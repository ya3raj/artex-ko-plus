package securitysource

import (
	"bufio"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	MaxUploadBytes         = 4 << 20
	MaxUploadRecordBytes   = 128 << 10
	MaxUploadRows          = 5000
	MaxUploadEventsPerKind = 200
)

type FileConfig struct {
	Label            string `json:"label"`
	TimestampField   string `json:"timestamp_field"`
	CorrelationField string `json:"correlation_field"`
	ActionField      string `json:"action_field"`
	EventIDField     string `json:"event_id_field"`
}

type UploadFile struct {
	Name    string `json:"name"`
	Content string `json:"content"`
}

type FileUpload struct {
	AuditFile        UploadFile  `json:"audit_file"`
	AlertFile        *UploadFile `json:"alert_file"`
	NoAlerts         bool        `json:"no_alerts"`
	CoverageStart    time.Time   `json:"coverage_start"`
	CoverageEnd      time.Time   `json:"coverage_end"`
	CoverageComplete bool        `json:"coverage_complete"`
}

type Diagnostic struct {
	Code           string   `json:"code"`
	Certainty      string   `json:"certainty"`
	Message        string   `json:"message"`
	Recommendation string   `json:"recommendation"`
	EventIDs       []string `json:"event_ids,omitempty"`
	FileName       string   `json:"file_name,omitempty"`
	Line           int      `json:"line,omitempty"`
}

type UploadedFileEvidence struct {
	Kind    string `json:"kind"`
	Name    string `json:"name"`
	SHA256  string `json:"sha256"`
	Bytes   int    `json:"bytes"`
	Content string `json:"content"`
	Rows    int    `json:"rows"`
}

type UploadStats struct {
	TotalRows       int `json:"total_rows"`
	Matched         int `json:"matched"`
	Unrelated       int `json:"unrelated"`
	OutsideWindow   int `json:"outside_window"`
	InvalidEvents   int `json:"invalid_events"`
	DuplicateEvents int `json:"duplicate_events"`
	Truncated       int `json:"truncated"`
}

type UploadProvenance struct {
	Config           FileConfig             `json:"config"`
	Files            []UploadedFileEvidence `json:"files"`
	CoverageComplete bool                   `json:"coverage_complete"`
	NoAlerts         bool                   `json:"no_alerts"`
	Stats            UploadStats            `json:"stats"`
}

func uploadInvalid(message string) error { return fmt.Errorf("%w: %s", ErrInvalid, message) }

func ValidateFileConfig(c FileConfig) (FileConfig, error) {
	c.Label = strings.TrimSpace(c.Label)
	if !utf8.ValidString(c.Label) || strings.ContainsRune(c.Label, 0) || utf8.RuneCountInString(c.Label) < 1 || utf8.RuneCountInString(c.Label) > 120 {
		return c, uploadInvalid("Please enter the file proof name in 1 to 120 characters.")
	}
	fields := []struct {
		value    *string
		fallback string
	}{
		{&c.TimestampField, "timestamp"}, {&c.CorrelationField, "artex_verification_id"},
		{&c.ActionField, "action"}, {&c.EventIDField, "id"},
	}
	seen := map[string]bool{}
	for _, item := range fields {
		*item.value = strings.TrimSpace(*item.value)
		if *item.value == "" {
			*item.value = item.fallback
		}
		if !fieldName.MatchString(*item.value) {
			return c, uploadInvalid("Please enter the field name in English, number, underscore, dot, hyphen, and less than 128characters.")
		}
		if seen[*item.value] {
			return c, uploadInvalid("Visual, Execution UUID, Measure, Event IDs can be mapped to different fields.")
		}
		seen[*item.value] = true
	}
	return c, nil
}

// ParseUpload treats names and contents only as data. It never opens a path,
// fetches a URL, evaluates a query, or sends log contents to another service.
// Dotted keys use the same literal-key-first lookup as the SIEM connector.
func ParseUpload(c FileConfig, in FileUpload, q Query) (*Evidence, error) {
	c, err := ValidateFileConfig(c)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	if !correlationName.MatchString(q.CorrelationID) || q.Start.IsZero() || !q.End.After(q.Start) || q.End.Sub(q.Start) > 24*time.Hour || q.End.After(now.Add(5*time.Second)) {
		return nil, uploadInvalid("Please check the execution identifier and the search time range (up to 24h)")
	}
	if in.CoverageStart.IsZero() || !in.CoverageEnd.After(in.CoverageStart) || in.CoverageEnd.Sub(in.CoverageStart) > 24*time.Hour || in.CoverageEnd.After(now) {
		return nil, uploadInvalid("Please specify the collection interval of the file as the time of the beginning and end of the past (up to 24hours)")
	}
	if in.AlertFile != nil && in.NoAlerts {
		return nil, uploadInvalid("Please select either the alarm file upload and check the alarm.")
	}
	total := len(in.AuditFile.Content)
	if in.AlertFile != nil {
		total += len(in.AlertFile.Content)
	}
	if total > MaxUploadBytes {
		return nil, uploadInvalid("The total of the original upload file must be less than 4 MiB")
	}
	out := &Evidence{Events: []Event{}, Complete: true, CollectedAt: now, WindowStart: in.CoverageStart.UTC(), WindowEnd: in.CoverageEnd.UTC(), Warnings: []string{}, Diagnostics: []Diagnostic{},
		Upload: &UploadProvenance{Config: c, Files: []UploadedFileEvidence{}, CoverageComplete: in.CoverageComplete, NoAlerts: in.NoAlerts}}
	diagnostic := func(code, message, recommendation string, incomplete bool) {
		out.Diagnostics = append(out.Diagnostics, Diagnostic{Code: code, Certainty: "observed", Message: message, Recommendation: recommendation})
		if incomplete {
			out.Complete = false
			out.Warnings = append(out.Warnings, message)
		}
	}
	if !in.CoverageComplete {
		diagnostic("upload_coverage_unconfirmed", "Collection scope of upload log completeness has not been confirmed", "Make sure you have exported all the audit and warning search results for the time period.", true)
	}
	if in.CoverageStart.After(q.Start) || in.CoverageEnd.Before(q.End) {
		diagnostic("upload_window_incomplete", "The collection interval of the file does not include the entire view interval of the execution", "Start running thirty seconds before and exit, and export again, including the waiting interval", true)
	}
	if in.AlertFile == nil && !in.NoAlerts {
		diagnostic("upload_alert_evidence_missing", "No alarm file or no alarm for the corresponding interval", "Upload the alarm file viewed with the same UUID and 구간, or check that there is no alarm after actual search", true)
	}
	if in.NoAlerts {
		diagnostic("upload_no_alerts_attested", "The user has specified that there is no alarm in the section", "This check is not an automatic SIEM lookup result. Please check the search terms and conditions for the original search results separately", false)
	}
	files := []struct {
		kind string
		file UploadFile
	}{{"audit", in.AuditFile}}
	if in.AlertFile != nil {
		files = append(files, struct {
			kind string
			file UploadFile
		}{"alert", *in.AlertFile})
	}
	seen := map[string][32]byte{}
	counts := map[string]int{}
	conflicts, unknownActions := 0, 0
	invalidDetails := 0
	invalidEvent := func(code, file string, line int, fieldName, message string) {
		out.Upload.Stats.InvalidEvents++
		if invalidDetails >= 10 {
			return
		}
		invalidDetails++
		out.Diagnostics = append(out.Diagnostics, Diagnostic{Code: code, Certainty: "observed", FileName: file, Line: line,
			Message: fmt.Sprintf("Field %s: %s", fieldName, message), Recommendation: "Check the original text of the file and the field mapping at the time of execution. This observation alone cannot determine the collector or equipment failure."})
	}
	unknownActionIDs := []string{}
	for _, item := range files {
		file := item.file
		if !utf8.ValidString(file.Name) || strings.TrimSpace(file.Name) == "" || len(file.Name) > 255 || strings.ContainsAny(file.Name, "\x00\r\n") {
			return nil, uploadInvalid("The file name must be an unempty UTF-8 string and must be less than 255 bytes")
		}
		if !utf8.ValidString(file.Content) || strings.ContainsRune(file.Content, 0) {
			return nil, uploadInvalid("The original text of the file must be UTF-8 text without NUL characters")
		}
		sum := sha256.Sum256([]byte(file.Content))
		provenance := UploadedFileEvidence{Kind: item.kind, Name: file.Name, SHA256: hex.EncodeToString(sum[:]), Bytes: len(file.Content), Content: file.Content}
		err := readUploadRows(file, func(fields map[string]any, line int) error {
			provenance.Rows++
			stats := &out.Upload.Stats
			stats.TotalRows++
			if stats.TotalRows > MaxUploadRows {
				return uploadInvalid("The total number of events in the file must be less than five thousand.")
			}
			correlationValue := field(fields, c.CorrelationField)
			correlation, ok := correlationValue.(string)
			if correlationValue == nil || ok && correlation == "" {
				invalidEvent("upload_missing_correlation", file.Name, line, c.CorrelationField, "Run UUID is missing or empty")
				return nil
			}
			if !ok {
				invalidEvent("upload_invalid_correlation", file.Name, line, c.CorrelationField, "Run UUID is not a string")
				return nil
			}
			if correlation != q.CorrelationID {
				stats.Unrelated++
				return nil
			}
			timestampValue := field(fields, c.TimestampField)
			if timestampValue == nil {
				invalidEvent("upload_missing_timestamp", file.Name, line, c.TimestampField, "There is no event time.")
				return nil
			}
			occurred, timeErr := eventTime(timestampValue)
			if timeErr != nil {
				invalidEvent("upload_invalid_timestamp", file.Name, line, c.TimestampField, "You cannot interpret the time as RFC 3339 or Unix seconds.")
				return nil
			}
			if occurred.Before(q.Start) || !occurred.Before(q.End) || occurred.Before(in.CoverageStart) || !occurred.Before(in.CoverageEnd) {
				stats.OutsideWindow++
				return nil
			}
			raw, err := json.Marshal(fields)
			if err != nil {
				return uploadInvalid("Failed to preserve the original text of the event")
			}
			if len(raw) > MaxUploadRecordBytes {
				return uploadInvalid("One normalized event must be 128 KiB or less.")
			}
			payloadHash := sha256.Sum256(raw)
			id := ""
			switch value := field(fields, c.EventIDField).(type) {
			case nil:
			case string:
				id = value
			case json.Number:
				id = value.String()
			default:
				invalidEvent("upload_invalid_event_id", file.Name, line, c.EventIDField, "Event ID is not a string or number")
				return nil
			}
			if id == "" {
				id = "sha256:" + hex.EncodeToString(payloadHash[:])
			}
			if len(id) > 1024 {
				invalidEvent("upload_invalid_event_id", file.Name, line, c.EventIDField, "Event ID is over 1024bytes")
				return nil
			}
			key := item.kind + ":" + id
			if previous, exists := seen[key]; exists {
				stats.DuplicateEvents++
				if previous != payloadHash {
					conflicts++
				}
				return nil
			}
			seen[key] = payloadHash
			if counts[item.kind] >= MaxUploadEventsPerKind {
				stats.Truncated++
				return nil
			}
			action := "unknown"
			switch strings.ToLower(textField(field(fields, c.ActionField))) {
			case "block", "blocked", "deny", "denied":
				action = "blocked"
			case "allow", "allowed", "pass", "passed":
				action = "allowed"
			}
			if item.kind == "audit" && action == "unknown" {
				unknownActions++
				if len(unknownActionIDs) < 20 {
					unknownActionIDs = append(unknownActionIDs, id)
				}
			}
			out.Events = append(out.Events, Event{ID: id, Kind: item.kind, CorrelationID: correlation, OccurredAt: occurred, Action: action, Raw: raw, FileName: file.Name, Line: line})
			counts[item.kind]++
			stats.Matched++
			return nil
		})
		if err != nil {
			return nil, err
		}
		out.Upload.Files = append(out.Upload.Files, provenance)
	}
	if len(out.Upload.Files) == 2 && out.Upload.Files[0].Bytes > 0 && out.Upload.Files[0].SHA256 == out.Upload.Files[1].SHA256 {
		diagnostic("upload_duplicate_sources", "The original text of the audit file and the alarm file are the same. Only a copy of the audit log cannot determine the detection alarm", "Select the alarm file exported separately from the actual detection system. Different files are not automatically verified to the authenticity of the source", true)
	}
	stats := out.Upload.Stats
	if stats.InvalidEvents > 0 {
		diagnostic("upload_invalid_events", fmt.Sprintf("Excluded event %d that could not be verified with UUID, time, or event ID", stats.InvalidEvents), "Check file field mapping and visual format. Missing fields does not determine collector failure", true)
	}
	if stats.Unrelated > 0 {
		diagnostic("upload_other_execution", fmt.Sprintf("Excluded %d events belonging to other execution UUIDs", stats.Unrelated), "Make sure that the UUID of the selected execution is recorded in the same as the original request and the audit and alert logs.", false)
	}
	if stats.OutsideWindow > 0 {
		diagnostic("upload_outside_window", fmt.Sprintf("Excluded events %d outside the lookup or file collection section", stats.OutsideWindow), "Check the log time and time zone and execution and file collection intervals", false)
	}
	if stats.DuplicateEvents > 0 {
		diagnostic("upload_duplicate_events", fmt.Sprintf("Duplicate event ID %d is excluded", stats.DuplicateEvents), "Make sure the event ID is unique within the source. Redundancy of the same original text is only once.", false)
	}
	if conflicts > 0 {
		diagnostic("upload_conflicting_events", fmt.Sprintf("The same event ID has a different original %d one, pending the decision.", conflicts), "Check the original origin of the conflicted log and the event identification field and export it back to your unique ID", true)
	}
	if stats.Truncated > 0 {
		diagnostic("upload_event_limit", fmt.Sprintf("There are more than two hundred events %d by type, so we will hold the verdict", stats.Truncated), "Check the log range of the same execution and whether it is duplicated", true)
	}
	if unknownActions > 0 {
		out.Diagnostics = append(out.Diagnostics, Diagnostic{Code: "upload_action_unknown", Certainty: "observed", Message: fmt.Sprintf("Cannot interpret the blocking and permiting measures of audit events %d", unknownActions), Recommendation: "Map fields that record actual policy actions. Do not determine whether to block with HTTP status code instead", EventIDs: unknownActionIDs})
	}
	if counts["audit"] == 0 {
		diagnostic("upload_audit_missing", "There are no audit events for the selected execution and lookup intervals", "Check the file selection, UUID forwarding, field mapping, and visual section. The absence of audit events does not determine the missing person.", true)
	}
	return out, nil
}

func readUploadRows(file UploadFile, consume func(map[string]any, int) error) error {
	content := strings.TrimPrefix(file.Content, "\ufeff")
	trimmed := strings.TrimSpace(content)
	if trimmed == "" {
		return nil
	}
	ext := strings.ToLower(filepath.Ext(file.Name))
	if ext == ".csv" {
		return readUploadCSV(content, consume)
	}
	if ext != ".json" && ext != ".jsonl" && ext != ".ndjson" && !strings.HasPrefix(trimmed, "{") && !strings.HasPrefix(trimmed, "[") {
		firstLine, _, _ := strings.Cut(trimmed, "\n")
		if !strings.Contains(firstLine, ",") {
			return uploadInvalid("Requires JSON object array, JSONL or comma-separated CSV file")
		}
		return readUploadCSV(content, consume)
	}
	if strings.HasPrefix(trimmed, "[") {
		d := json.NewDecoder(strings.NewReader(content))
		d.UseNumber()
		if _, err := d.Token(); err != nil {
			return uploadInvalid("JSON array syntax is not correct")
		}
		line, lineOffset := 1, 0
		for d.More() {
			start := d.InputOffset()
			rowOffset := int(start)
			for rowOffset < len(content) && strings.ContainsRune(" \r\n\t,", rune(content[rowOffset])) {
				rowOffset++
			}
			line += strings.Count(content[lineOffset:rowOffset], "\n")
			lineOffset = rowOffset
			count := 0
			value, err := readUploadJSONValue(d, 0, &count)
			if err != nil {
				return err
			}
			if d.InputOffset()-start > MaxUploadRecordBytes {
				return uploadInvalid("One event must be 128 KiB or less.")
			}
			object, ok := value.(map[string]any)
			if !ok {
				return uploadInvalid("Each event in a JSON array must be an object")
			}
			if err := consume(object, line); err != nil {
				return err
			}
		}
		if close, err := d.Token(); err != nil || close != json.Delim(']') {
			return uploadInvalid("JSON array is not complete")
		}
		if _, err := d.Token(); err != io.EOF {
			return uploadInvalid("There is additional data after the JSON array")
		}
		return nil
	}
	scan := bufio.NewScanner(strings.NewReader(content))
	scan.Buffer(make([]byte, 4096), MaxUploadRecordBytes+2)
	for line := 1; scan.Scan(); line++ {
		raw := scan.Text()
		if strings.TrimSpace(raw) == "" {
			continue
		}
		if len(raw) > MaxUploadRecordBytes {
			return uploadInvalid("One event must be 128 KiB or less.")
		}
		d := json.NewDecoder(strings.NewReader(raw))
		d.UseNumber()
		count := 0
		value, err := readUploadJSONValue(d, 0, &count)
		if err != nil {
			return err
		}
		object, ok := value.(map[string]any)
		if !ok {
			return uploadInvalid("Each row of JSONL must be a JSON object")
		}
		if _, err := d.Token(); err != io.EOF {
			return uploadInvalid("There is additional data after the JSON object")
		}
		if err := consume(object, line); err != nil {
			return err
		}
	}
	if scan.Err() != nil {
		return uploadInvalid("One event must be less than 128 KiB and must be in full UTF-8 row.")
	}
	return nil
}

func readUploadCSV(content string, consume func(map[string]any, int) error) error {
	r := csv.NewReader(strings.NewReader(content))
	header, err := r.Read()
	if err != nil || len(header) == 0 || r.InputOffset() > MaxUploadRecordBytes || len(header) > 256 {
		return uploadInvalid("The first row of CSV requires a unique field name of no more than twenty-five.")
	}
	seen := map[string]bool{}
	for _, key := range header {
		if key == "" || len(key) > 128 || seen[key] {
			return uploadInvalid("CSV field name is empty or duplicated or over 128bytes")
		}
		seen[key] = true
	}
	for {
		start := r.InputOffset()
		row, err := r.Read()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return uploadInvalid("The CSV quotation mark or number of columns is incorrect")
		}
		if r.InputOffset()-start > MaxUploadRecordBytes {
			return uploadInvalid("One CSV event must be 128 KiB or less")
		}
		line, _ := r.FieldPos(0)
		object := make(map[string]any, len(header))
		for i, key := range header {
			object[key] = row[i]
		}
		if err := consume(object, line); err != nil {
			return err
		}
	}
}

// Reject duplicate keys and decoded NUL before JSONB persistence, and bound
// nesting/values independently from the byte limit. Numbers remain json.Number.
func readUploadJSONValue(d *json.Decoder, depth int, count *int) (any, error) {
	if depth > 16 {
		return nil, uploadInvalid("JSON nesting should be less than sixteen steps")
	}
	*count = *count + 1
	if *count > 4096 {
		return nil, uploadInvalid("The value of the event must be less than 4096pcs")
	}
	token, err := d.Token()
	if err != nil {
		return nil, uploadInvalid("JSON syntax is not correct")
	}
	switch value := token.(type) {
	case json.Delim:
		if value == '{' {
			object := map[string]any{}
			for d.More() {
				keyToken, err := d.Token()
				key, ok := keyToken.(string)
				if err != nil || !ok || len(key) > 128 || strings.ContainsRune(key, 0) {
					return nil, uploadInvalid("The JSON field name must be 128bytes or less without NUL")
				}
				if _, exists := object[key]; exists {
					return nil, uploadInvalid("Duplicate JSON field names are not allowed")
				}
				child, err := readUploadJSONValue(d, depth+1, count)
				if err != nil {
					return nil, err
				}
				object[key] = child
			}
			if close, err := d.Token(); err != nil || close != json.Delim('}') {
				return nil, uploadInvalid("JSON objects are not complete")
			}
			return object, nil
		}
		if value == '[' {
			array := []any{}
			for d.More() {
				child, err := readUploadJSONValue(d, depth+1, count)
				if err != nil {
					return nil, err
				}
				array = append(array, child)
			}
			if close, err := d.Token(); err != nil || close != json.Delim(']') {
				return nil, uploadInvalid("JSON array is not complete")
			}
			return array, nil
		}
		return nil, uploadInvalid("JSON is not valid.")
	case string:
		if strings.ContainsRune(value, 0) || len(value) > MaxUploadRecordBytes {
			return nil, uploadInvalid("The JSON string must be 128 KiB or less without NUL")
		}
	case json.Number:
		if len(value) > 256 {
			return nil, uploadInvalid("The number value should be less than 256bytes.")
		}
		// Preserve decimal precision without admitting exponents that cannot be
		// represented by the evidence store's bounded JSONB numeric type.
		if i := strings.IndexAny(value.String(), "eE"); i >= 0 {
			exponent, err := strconv.Atoi(value.String()[i+1:])
			if err != nil || exponent < -1000 || exponent > 1000 {
				return nil, uploadInvalid("The exponent of numbers should be in the range of -1000 to 1000.")
			}
		}
	}
	return token, nil
}
