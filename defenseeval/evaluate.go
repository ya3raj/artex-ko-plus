// Package defenseeval evaluates a deliberately small rule language against
// supplied events. It performs no network access, command execution, or live
// detection validation. Dataset expectations stay outside event objects.
package defenseeval

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"unicode/utf8"
)

const (
	EngineVersion       = "artex-event-filter/v1"
	MaxCombinedLogBytes = 1 << 20
	MaxEvents           = 2000
	MaxRuleBytes        = 64 << 10
	MaxConditions       = 16
	MaxFieldLength      = 128
	MaxRuleValueBytes   = 4096
	MaxEventBytes       = 128 << 10
	MaxStringBytes      = 64 << 10
	MaxNestingDepth     = 16
	MaxEventValues      = 4096
	MaxNumberBytes      = 256
)

// ErrInvalid identifies invalid or oversized input, including malformed logs.
var ErrInvalid = errors.New("The Defense Rule Assessment Input is incorrect")

type DatasetSummary struct {
	Total   int `json:"total"`
	Matched int `json:"matched"`
	// Missed counts no_match events in either dataset. For control events this
	// is the expected result, not an indication that a detection was missed.
	Missed       int `json:"missed"`
	Inconclusive int `json:"inconclusive"`
}

type Evaluation struct {
	Dataset string `json:"dataset"`
	// Line is the physical 1-based JSONL line or the 1-based JSON-array index.
	Line    int    `json:"line"`
	Outcome string `json:"outcome"`
	// MissingFields includes both absent fields and incompatible value types.
	MissingFields []string `json:"missing_fields"`
}

type Result struct {
	Engine      string         `json:"engine"`
	Verdict     string         `json:"verdict"`
	Target      DatasetSummary `json:"target"`
	Control     DatasetSummary `json:"control"`
	Reasons     []string       `json:"reasons"`
	Evaluations []Evaluation   `json:"evaluations"`
}

type condition struct {
	field, op string
	value     any
}
type event struct {
	line   int
	fields map[string]any
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// Evaluate applies all rule conditions to every supplied event. A pass requires
// nonempty target/control sets, all target events matching, no control events
// matching, and no unevaluable referenced fields. This is log replay only.
func Evaluate(ruleText, targetLogs, controlLogs string) (*Result, error) {
	if len(targetLogs) > MaxCombinedLogBytes || len(controlLogs) > MaxCombinedLogBytes-len(targetLogs) {
		return nil, invalid("The total target and control log must be less than 1 MiB")
	}
	rule, err := parseRule(ruleText)
	if err != nil {
		return nil, err
	}
	target, err := parseLogs(targetLogs, "Target", MaxEvents)
	if err != nil {
		return nil, err
	}
	control, err := parseLogs(controlLogs, "Contrast", MaxEvents-len(target))
	if err != nil {
		return nil, err
	}
	out := &Result{Engine: EngineVersion, Verdict: "pass", Reasons: []string{}, Evaluations: []Evaluation{}}
	for _, dataset := range []struct {
		name    string
		events  []event
		summary *DatasetSummary
	}{
		{"target", target, &out.Target}, {"control", control, &out.Control},
	} {
		for _, e := range dataset.events {
			v := evaluateEvent(rule, e)
			v.Dataset = dataset.name
			dataset.summary.Total++
			switch v.Outcome {
			case "match":
				dataset.summary.Matched++
			case "no_match":
				dataset.summary.Missed++
			default:
				dataset.summary.Inconclusive++
			}
			out.Evaluations = append(out.Evaluations, v)
		}
	}
	if out.Target.Total == 0 {
		out.Reasons = append(out.Reasons, "The target log is empty and cannot be completed for evaluation")
	}
	if out.Control.Total == 0 {
		out.Reasons = append(out.Reasons, "The control log is empty, so you can't evaluate false positives")
	}
	if out.Target.Inconclusive+out.Control.Inconclusive > 0 {
		out.Reasons = append(out.Reasons, "You don't have a reference field for some events, or you can't determine if the type is different.")
	}
	if out.Target.Missed > 0 {
		out.Reasons = append(out.Reasons, fmt.Sprintf("The target event %d does not match the rules", out.Target.Missed))
	}
	if out.Control.Matched > 0 {
		out.Reasons = append(out.Reasons, fmt.Sprintf("Contrast event %d match rule, false otam occurred", out.Control.Matched))
	}
	if out.Target.Missed > 0 || out.Control.Matched > 0 {
		out.Verdict = "fail"
	}
	if out.Target.Total == 0 || out.Control.Total == 0 || out.Target.Inconclusive+out.Control.Inconclusive > 0 {
		out.Verdict = "inconclusive"
	}
	return out, nil
}

func parseRule(raw string) ([]condition, error) {
	if len(raw) > MaxRuleBytes {
		return nil, invalid("The rule must be 64 KiB.")
	}
	v, err := parseObject(raw)
	if err != nil {
		return nil, invalid("Rule JSON: %s", err)
	}
	if len(v) != 2 || v["version"] != json.Number("1") {
		return nil, invalid("The rule should only have the field of version: 1 and all.")
	}
	all, ok := v["all"].([]any)
	if !ok || len(all) == 0 || len(all) > MaxConditions {
		return nil, invalid("All require 1 to 16 conditions.")
	}
	conditions := make([]condition, 0, len(all))
	for i, rawCondition := range all {
		c, ok := rawCondition.(map[string]any)
		if !ok || len(c) != 3 {
			return nil, invalid("%d must have only field, op, and value.", i+1)
		}
		field, fieldOK := c["field"].(string)
		op, opOK := c["op"].(string)
		value, valueOK := c["value"]
		if !fieldOK || field == "" || utf8.RuneCountInString(field) > MaxFieldLength || !opOK || !valueOK {
			return nil, invalid("The field name or operator of condition %d is invalid", i+1)
		}
		// Referenced names can appear in missing_fields and be persisted as
		// JSONB. PostgreSQL cannot represent a decoded NUL in a JSON string.
		if strings.ContainsRune(field, 0) {
			return nil, invalid("You cannot use NUL characters for field names in condition %d", i+1)
		}
		if op != "eq" && op != "neq" && op != "contains" {
			return nil, invalid("Condition %d: only eq, neq, and contains operators are supported", i+1)
		}
		switch value := value.(type) {
		case string:
			if len(value) > MaxRuleValueBytes {
				return nil, invalid("The condition value must be less than 4096bytes")
			}
		case json.Number, bool:
			if op == "contains" {
				return nil, invalid("contains The condition value must be a string")
			}
		default:
			return nil, invalid("The condition value must be a string, a number, or a true lie, not null.")
		}
		conditions = append(conditions, condition{field: field, op: op, value: value})
	}
	return conditions, nil
}

// A literal dotted key on the event root takes precedence, including a null or
// incompatible value. Only if that exact key is absent do we traverse nested
// object keys split on dots. Arrays and mixed dotted/nested paths are not indexed.
func lookup(fields map[string]any, field string) (any, bool) {
	if value, exists := fields[field]; exists {
		return value, true
	}
	var value any = fields
	for _, segment := range strings.Split(field, ".") {
		object, ok := value.(map[string]any)
		if !ok {
			return nil, false
		}
		var exists bool
		value, exists = object[segment]
		if !exists {
			return nil, false
		}
	}
	return value, true
}

func evaluateEvent(rule []condition, e event) Evaluation {
	out := Evaluation{Line: e.line, Outcome: "match", MissingFields: []string{}}
	missing := map[string]bool{}
	matched := true
	for _, c := range rule {
		actual, found := lookup(e.fields, c.field)
		conditionMatch, evaluable := compare(actual, c.value, c.op)
		if !found || !evaluable {
			if !missing[c.field] {
				out.MissingFields = append(out.MissingFields, c.field)
				missing[c.field] = true
			}
		} else if !conditionMatch {
			matched = false
		}
	}
	if len(out.MissingFields) > 0 {
		out.Outcome = "inconclusive"
	} else if !matched {
		out.Outcome = "no_match"
	}
	return out
}

func compare(actual, expected any, op string) (bool, bool) {
	var equal bool
	switch expected := expected.(type) {
	case string:
		actual, ok := actual.(string)
		if !ok {
			return false, false
		}
		if op == "contains" {
			return strings.Contains(actual, expected), true
		}
		equal = actual == expected
	case bool:
		actual, ok := actual.(bool)
		if !ok {
			return false, false
		}
		equal = actual == expected
	case json.Number:
		actual, ok := actual.(json.Number)
		if !ok {
			return false, false
		}
		equal = canonicalNumber(actual) == canonicalNumber(expected)
	default:
		return false, false
	}
	if op == "neq" {
		equal = !equal
	}
	return equal, true
}

// Normalize decimal digits and exponent instead of converting to float64 or
// expanding huge exponents. 1, 1.0, and 10e-1 compare equally; integers beyond
// 2^53 remain distinct. Exponent arithmetic is bounded by MaxNumberBytes.
func canonicalNumber(value json.Number) string {
	raw := string(value)
	sign := ""
	if strings.HasPrefix(raw, "-") {
		sign = "-"
		raw = raw[1:]
	}
	exponent := new(big.Int)
	if i := strings.IndexAny(raw, "eE"); i >= 0 {
		exponent.SetString(raw[i+1:], 10)
		raw = raw[:i]
	}
	if i := strings.IndexByte(raw, '.'); i >= 0 {
		exponent.Sub(exponent, big.NewInt(int64(len(raw)-i-1)))
		raw = raw[:i] + raw[i+1:]
	}
	raw = strings.TrimLeft(raw, "0")
	if raw == "" {
		return "0"
	}
	trimmed := strings.TrimRight(raw, "0")
	exponent.Add(exponent, big.NewInt(int64(len(raw)-len(trimmed))))
	return sign + trimmed + "e" + exponent.String()
}
