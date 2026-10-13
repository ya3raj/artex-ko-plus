package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/securitysource"
)

// Bound outbound SIEM work across requests and Server instances in this process.
var defenseCollectSlots = make(chan struct{}, 2)

func (s *Server) registerPurpleExecutions(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/exploration/findings/{id}/defense/executions", s.listDefenseExecutions)
	mux.HandleFunc("POST /api/exploration/findings/{id}/defense/executions", s.startDefenseExecution)
	mux.HandleFunc("GET /api/exploration/findings/{id}/defense/executions/compare", s.compareDefenseExecutions)
	mux.HandleFunc("GET /api/exploration/findings/{id}/defense/executions/{executionID}/export", s.exportDefenseExecution)
	mux.HandleFunc("POST /api/exploration/findings/{id}/defense/executions/{executionID}/collect", s.collectDefenseExecution)
	mux.HandleFunc("POST /api/exploration/findings/{id}/defense/executions/{executionID}/upload", s.uploadDefenseExecution)
}

func (s *Server) startDefenseExecution(w http.ResponseWriter, r *http.Request) {
	id, ok := purpleFindingID(w, r)
	if !ok {
		return
	}
	var in struct {
		db.DefenseExecutionInput
		Notes string `json:"notes"`
	}
	if !decodePurpleRequest(w, r, &in) {
		return
	}
	in.Notes = strings.TrimSpace(in.Notes)
	if !utf8.ValidString(in.Notes) || strings.ContainsRune(in.Notes, 0) || utf8.RuneCountInString(in.Notes) > 4000 {
		writeErr(w, http.StatusBadRequest, errFindingRetestNotesTooLong)
		return
	}
	pg := s.pg(w)
	if pg == nil || !s.findingRetestReady(w, r, pg, id) {
		return
	}
	retest, conv, execution, created, err := pg.CreateFindingRetestWithDefense(r.Context(), id, in.Notes, in.DefenseExecutionInput)
	if err != nil {
		writePurpleError(w, err)
		return
	}
	if created {
		s.dispatchFindingRetest(retest, conv)
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusAccepted, map[string]any{"execution": execution, "retest": retest, "created": created})
}

func (s *Server) listDefenseExecutions(w http.ResponseWriter, r *http.Request) {
	id, ok := purpleFindingID(w, r)
	if !ok {
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	executions, err := pg.ListDefenseExecutions(r.Context(), id)
	if err != nil {
		writePurpleError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"executions": executions})
}

func defenseExecutionID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, ok := pathInt(r, "executionID")
	if !ok || id <= 0 {
		writeErr(w, http.StatusBadRequest, "Please enter the correct verification execution ID")
		return 0, false
	}
	return id, true
}

func (s *Server) exportDefenseExecution(w http.ResponseWriter, r *http.Request) {
	id, ok := purpleFindingID(w, r)
	if !ok {
		return
	}
	executionID, ok := defenseExecutionID(w, r)
	if !ok {
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	execution, err := pg.GetDefenseExecution(r.Context(), id, executionID)
	if err != nil {
		writePurpleError(w, err)
		return
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="defense-execution-%d.json"`, executionID))
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, execution)
}

// A completed observation window is required even when an early query finds an
// alert: delayed audit records may still alter the independent prevention result.
func defenseExecutionWindow(execution *db.DefenseExecution, now time.Time) (securitysource.Query, bool, error) {
	if execution == nil || execution.Retest == nil || execution.Retest.FinishedAt == nil {
		return securitysource.Query{}, false, errors.New("I need you to collect the evidence after the diagnosis is complete.")
	}
	switch execution.Retest.Status {
	case "completed", "failed", "stopped":
	default:
		return securitysource.Query{}, false, errors.New("I need you to collect the evidence after the diagnosis is complete.")
	}
	start := execution.CreatedAt
	if !execution.Retest.CreatedAt.IsZero() {
		start = execution.Retest.CreatedAt
	}
	if execution.Retest.StartedAt != nil {
		start = *execution.Retest.StartedAt
	}
	end := execution.Retest.FinishedAt.Add(time.Minute)
	complete := !now.Before(end)
	if !complete {
		end = now
	}
	start = start.Add(-30 * time.Second)
	if !end.After(start) || end.Sub(start) > 24*time.Hour {
		return securitysource.Query{}, false, errors.New("The collection time range of execution is out of support. Please start running new validations.")
	}
	return securitysource.Query{CorrelationID: execution.CorrelationID, Start: start, End: end}, complete, nil
}

func (s *Server) collectDefenseExecution(w http.ResponseWriter, r *http.Request) {
	id, ok := purpleFindingID(w, r)
	if !ok {
		return
	}
	executionID, ok := defenseExecutionID(w, r)
	if !ok {
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	execution, err := pg.GetDefenseExecutionForCollection(r.Context(), id, executionID)
	if err != nil {
		writePurpleError(w, err)
		return
	}
	if execution.SourceKind == "file" {
		writeErr(w, http.StatusConflict, "This is a file association. Please upload the audit and alert log files.")
		return
	}
	query, windowComplete, err := defenseExecutionWindow(execution, time.Now().UTC())
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	source, err := pg.GetSecuritySource(r.Context(), execution.SourceID)
	if errors.Is(err, db.ErrSecuritySourceNotFound) {
		writePurpleError(w, db.ErrDefenseConflict)
		return
	}
	if err != nil {
		writePurpleError(w, err)
		return
	}
	var sourceSnapshot db.SecuritySource
	if json.Unmarshal(execution.SourceSnapshot, &sourceSnapshot) != nil || sourceSnapshot.ID != source.ID || sourceSnapshot.Revision != source.Revision || sourceSnapshot.Config != source.Config || source.Revision != execution.SourceRevision || !source.Enabled {
		writeErr(w, http.StatusConflict, "The security log connection has changed. Please start running new verification with the current settings")
		return
	}
	credentials, err := s.securitySourceCredentials(source)
	if err != nil {
		writeErr(w, http.StatusConflict, "Please check the stored security log authentication information")
		return
	}
	select {
	case defenseCollectSlots <- struct{}{}:
		defer func() { <-defenseCollectSlots }()
	default:
		writeErr(w, http.StatusTooManyRequests, "Another piece of evidence is in progress. Please try again in a moment.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	evidence, err := securitysource.Fetch(ctx, source.Config, credentials, query)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "We have not been able to gather any security log evidence. Please check your connection settings and source status.")
		return
	}
	if !windowComplete {
		evidence.Complete = false
		evidence.Warnings = append(evidence.Warnings, "Sixty seconds of observation is not over yet.")
	}
	assessment, err := pg.SaveDefenseAssessment(ctx, id, executionID, evidence)
	if err != nil {
		writePurpleError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, assessment)
}

func (s *Server) compareDefenseExecutions(w http.ResponseWriter, r *http.Request) {
	id, ok := purpleFindingID(w, r)
	if !ok {
		return
	}
	baselineID, baselineErr := strconv.ParseInt(r.URL.Query().Get("baseline_id"), 10, 64)
	currentID, currentErr := strconv.ParseInt(r.URL.Query().Get("current_id"), 10, 64)
	if baselineErr != nil || currentErr != nil || baselineID <= 0 || currentID <= 0 || baselineID == currentID {
		writeErr(w, http.StatusBadRequest, "After running and improving different criteria, please enter the execution ID")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	comparison, err := pg.CompareDefenseExecutions(r.Context(), id, baselineID, currentID)
	if err != nil {
		writePurpleError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, comparison)
}
