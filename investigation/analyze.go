package investigation

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Analyze links every observation to selected evidence. Follow-on hypotheses
// require domain-specific evidence and remain manual review in this version.
func Analyze(plan Plan, scope Scope, c Collection) Analysis {
	a := Analysis{EngineVersion: EngineVersion, Hypotheses: []HypothesisResult{}, Timeline: []TimelineEntry{}, Signals: []Signal{}, Limitations: append([]string{}, c.Warnings...), NextSteps: []string{}}
	a.Limitations = append(a.Limitations, "Observed events are not encroachment confirmations. Even if there are no results found, attacks outside the scope of the investigation cannot be ruled out.", "HTTP status codes and permitting actions do not determine the success of file delivery, code execution, account hijacking, or blocking.")
	events := append([]Event{}, c.Events...)
	sort.SliceStable(events, func(i, j int) bool {
		if events[i].Timestamp.Equal(events[j].Timestamp) {
			return events[i].Ref < events[j].Ref
		}
		return events[i].Timestamp.Before(events[j].Timestamp)
	})
	pathRefs := []string{}
	groups := map[string][]Event{}
	missingIdentity, missingCompletion := 0, 0
	for _, e := range events {
		label := "Recorded route: " + e.Path
		if e.Path == "" {
			label = "Target-related events without a path — need to review additional fields"
		}
		if e.KnownARTEX {
			label = "Known ARTEX verification marks · " + label
			a.KnownARTEXCount++
		}
		a.Timeline = append(a.Timeline, TimelineEntry{Timestamp: e.Timestamp, EvidenceRef: e.Ref, EventID: e.ID, Summary: label, KnownARTEX: e.KnownARTEX})
		if e.KnownARTEX {
			continue
		}
		a.ObservedCount++
		if e.Session == "" && e.SourceIP == "" {
			missingIdentity++
		}
		if e.ResponseComplete == nil || e.Bytes == nil {
			missingCompletion++
		}
		if e.Path == "" {
			continue
		}
		pathRefs = append(pathRefs, e.Ref)
		if e.EventKind == "alert" || e.EventKind == "Alert" || e.SourceAmbiguous {
			continue
		}
		identity := ""
		if e.Session != "" {
			identity = "session=" + e.Session
		} else if e.SourceIP != "" {
			identity = "source_ip=" + e.SourceIP
		}
		if identity == "" {
			continue
		}
		source := e.Source
		if source == "" {
			source = e.FileName
		}
		target := strings.ToLower(e.Target)
		if target == "" {
			target = scope.Target
		}
		// Source and target are separate from identity; a repeated IP in two
		// sources is never treated as a common actor or causal chain.
		keyBytes, _ := json.Marshal([]string{source, target, identity})
		key := string(keyBytes)
		groups[key] = append(groups[key], e)
	}
	if missingIdentity > 0 {
		a.Limitations = append(a.Limitations, fmt.Sprintf("There is no session or starting point in the event %d , so the request flow cannot be tied.", missingIdentity))
	}
	if missingCompletion > 0 {
		a.Limitations = append(a.Limitations, fmt.Sprintf("The event %d is not equipped with all the response completion and transmission byte data, so the actual delivery range cannot be determined.", missingCompletion))
	}
	if a.KnownARTEXCount > 0 {
		a.Limitations = append(a.Limitations, "Marks that match the saved ARTEX execution UUID are displayed separately on the timeline and excluded from the suspicious flow. The header marker itself does not authenticate the identity of the requester.")
	}
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	sequenceRefs := []string{}
	signalOverflow := false
	for _, key := range keys {
		g := groups[key]
		found := false
		for start := 0; start < len(g) && !found; start++ {
			paths := map[string]bool{}
			refs := []string{}
			ids := map[string]bool{}
			for end := start; end < len(g) && !g[end].Timestamp.After(g[start].Timestamp.Add(10*time.Minute)); end++ {
				e := g[end]
				p, _ := normalizedPath(e.Path)
				base := strings.TrimRight(scope.PathPrefix, "/")
				if p == base || p == base+"/" {
					continue
				}
				if ids[e.ID] {
					continue
				}
				ids[e.ID] = true
				paths[p] = true
				refs = append(refs, e.Ref)
			}
			if len(paths) >= 2 {
				if len(a.Signals) >= 50 {
					signalOverflow = true
					found = true
					continue
				}
				var keyParts []string
				_ = json.Unmarshal([]byte(key), &keyParts)
				shownKey := strings.Join(keyParts, " · ")
				a.Signals = append(a.Signals, Signal{Kind: "multi_path_requests", Key: shownKey, Summary: fmt.Sprintf("Events have been observed for different paths %d within ten minutes from the same log origin, destination, session, or origin. Normal resource loading and sharing IP is also possible.", len(paths)), EvidenceRefs: refs})
				sequenceRefs = append(sequenceRefs, refs...)
				found = true
			}
		}
	}
	if signalOverflow {
		a.Limitations = append(a.Limitations, "The request flow display limit has been exceeded by more than fifty. Narrow down the timeframe and route to further investigate.")
	}
	for _, h := range plan.Hypotheses {
		r := HypothesisResult{HypothesisID: h.ID, Status: "manual_review", Summary: "This subsequent hypothesis requires a separate logarithm and its terms to be verified. It has not been validated by automatic analysis at this time.", EvidenceRefs: []string{}, NextSteps: append([]string{}, h.NextSteps...)}
		switch h.ID {
		case "path_access":
			if len(pathRefs) > 0 {
				r.Status = "observed"
				r.Summary = fmt.Sprintf("We have observed events %d in the selected asset, duration, and route range. We do not judge the success of the abuse by just logging the route.", len(pathRefs))
				r.EvidenceRefs = pathRefs
			} else if !c.Complete {
				r.Status = "insufficient_data"
				r.Summary = "There are spaces in the collection range or parsing, so it is not possible to draw unobservative conclusions."
			} else if a.ObservedCount > 0 {
				r.Status = "insufficient_data"
				r.Summary = "There are targets, but there is no request path, so you cannot check for access to vulnerable routes."
			} else {
				r.Status = "not_observed"
				r.Summary = "We have not observed any related route events except the known ARTEX markings in the scope of the investigation. This does not mean that there was no infringement."
			}
		case "multi_path":
			if len(sequenceRefs) > 0 {
				r.Status = "suspicious"
				r.Summary = "There are multiple route request flows in a short time that require review. It is not a successful file collection or a confirmation of the same attacker."
				r.EvidenceRefs = sequenceRefs
			} else if !c.Complete || missingIdentity > 0 || a.ObservedCount > len(pathRefs) {
				r.Status = "insufficient_data"
				r.Summary = "The collection space or lack of session, departure point, and path cannot fully evaluate the multipath request flow."
			} else {
				r.Status = "not_observed"
				r.Summary = "In the current range, multiple path flows within ten minutes of the same log origin, destination, session, or departure point were not observed."
			}
		}
		a.Hypotheses = append(a.Hypotheses, r)
	}
	if scope.PathPrefix == "" || scope.PathPrefix == "/" {
		a.Limitations = append(a.Limitations, "No specific vulnerability path has been specified. It is a path observation across the asset and the relevance to the vulnerability should be checked separately.")
	}
	a.Summary = fmt.Sprintf("We have separated the events %d in the scope of the investigation from the case of known ARTEX verification marks%d The breach is judged by the observational basis and further investigation.", a.ObservedCount, a.KnownARTEXCount)
	if !c.Complete {
		a.Summary += " There is a gap in the collection, so it is not possible to confirm the US observation."
		a.NextSteps = append(a.NextSteps, "Resolve collection warnings and resubmit evidence of the same asset/period.")
	}
	if len(a.Signals) > 0 {
		a.NextSteps = append(a.NextSteps, "Contrast the normal use and approval of the multipath flow with the original log and the operating history.")
	}
	a.NextSteps = append(a.NextSteps, "Check the hypothesis-specific establishment conditions and additional logs required.", "Review the detection rules for your verified behavior and see the effects in your existing defense validation.")
	return a
}
