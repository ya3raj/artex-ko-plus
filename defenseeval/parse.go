package defenseeval

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

func parseLogs(raw, label string, remaining int) ([]event, error) {
	if !utf8.ValidString(raw) {
		return nil, invalid("%s log must be correct UTF-8", label)
	}
	out := []event{}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return out, nil
	}
	if strings.HasPrefix(trimmed, "[") {
		decoder := json.NewDecoder(strings.NewReader(raw))
		decoder.UseNumber()
		if _, err := decoder.Token(); err != nil {
			return nil, invalid("%s Could not read log array", label)
		}
		for decoder.More() {
			if len(out) >= remaining {
				return nil, invalid("The total number of log events must be less than two thousand")
			}
			start := decoder.InputOffset()
			count := 0
			value, err := readValue(decoder, 0, &count)
			if err != nil {
				return nil, invalid("%s %d event in the log array: %s", label, len(out)+1, err)
			}
			fields, ok := value.(map[string]any)
			if !ok {
				return nil, invalid("Each event in %s log must be a JSON object", label)
			}
			if decoder.InputOffset()-start > MaxEventBytes {
				return nil, invalid("One event must be 128 KiB or less.")
			}
			out = append(out, event{line: len(out) + 1, fields: fields})
		}
		if close, err := decoder.Token(); err != nil || close != json.Delim(']') {
			return nil, invalid("%s The log array is not complete", label)
		}
		if err := requireEOF(decoder); err != nil {
			return nil, invalid("Unexpected values after the %s log array", label)
		}
		return out, nil
	}
	for line, text := range strings.Split(raw, "\n") {
		if strings.TrimSpace(text) == "" {
			continue
		}
		if len(out) >= remaining {
			return nil, invalid("The total number of log events must be less than two thousand")
		}
		if len(text) > MaxEventBytes {
			return nil, invalid("%s log %d line: One event must be less than 128 KiB", label, line+1)
		}
		fields, err := parseObject(text)
		if err != nil {
			return nil, invalid("%s log %d row: %s", label, line+1, err)
		}
		out = append(out, event{line: line + 1, fields: fields})
	}
	return out, nil
}

func parseObject(raw string) (map[string]any, error) {
	if !utf8.ValidString(raw) {
		return nil, fmt.Errorf("It's not the correct UTF-8.")
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.UseNumber()
	count := 0
	value, err := readValue(decoder, 0, &count)
	if err != nil {
		return nil, err
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("Requires JSON object")
	}
	if err := requireEOF(decoder); err != nil {
		return nil, err
	}
	return object, nil
}

func requireEOF(decoder *json.Decoder) error {
	if _, err := decoder.Token(); err != io.EOF {
		return fmt.Errorf("There is additional data after the JSON value")
	}
	return nil
}

// Token parsing rejects duplicate keys rather than silently letting a later
// field override evidence, and bounds every event before evaluation.
func readValue(decoder *json.Decoder, depth int, count *int) (any, error) {
	if depth > MaxNestingDepth {
		return nil, fmt.Errorf("JSON nesting should be less than sixteen steps")
	}
	*count = *count + 1
	if *count > MaxEventValues {
		return nil, fmt.Errorf("The value of the event must be less than 4096pcs")
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, fmt.Errorf("JSON syntax is not correct")
	}
	switch token := token.(type) {
	case json.Delim:
		switch token {
		case '{':
			object := map[string]any{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				key, ok := keyToken.(string)
				if err != nil || !ok || utf8.RuneCountInString(key) > MaxFieldLength {
					return nil, fmt.Errorf("The object field name must be less than 128 characters")
				}
				if _, exists := object[key]; exists {
					return nil, fmt.Errorf("Duplicate JSON field names are not allowed")
				}
				value, err := readValue(decoder, depth+1, count)
				if err != nil {
					return nil, err
				}
				object[key] = value
			}
			if close, err := decoder.Token(); err != nil || close != json.Delim('}') {
				return nil, fmt.Errorf("JSON objects are not complete")
			}
			return object, nil
		case '[':
			array := []any{}
			for decoder.More() {
				value, err := readValue(decoder, depth+1, count)
				if err != nil {
					return nil, err
				}
				array = append(array, value)
			}
			if close, err := decoder.Token(); err != nil || close != json.Delim(']') {
				return nil, fmt.Errorf("JSON array is not complete")
			}
			return array, nil
		default:
			return nil, fmt.Errorf("JSON is not valid.")
		}
	case string:
		if len(token) > MaxStringBytes {
			return nil, fmt.Errorf("The string value must be less than 64 KiB")
		}
		return token, nil
	case json.Number:
		if len(token) > MaxNumberBytes {
			return nil, fmt.Errorf("The number value should be less than 256bytes.")
		}
		return token, nil
	default:
		return token, nil
	}
}
