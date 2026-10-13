package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/Autumn-27/artex/securitysource"
)

// The wire allowance accounts for JSON escaping. ParseUpload independently
// bounds the actual UTF-8 file bytes and rows; no path or URL is ever opened.
const maxPurpleUploadRequestBytes = 24 << 20

func (s *Server) uploadDefenseExecution(w http.ResponseWriter, r *http.Request) {
	findingID, ok := purpleFindingID(w, r)
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
	execution, err := pg.GetDefenseExecutionForCollection(r.Context(), findingID, executionID)
	if err != nil {
		writePurpleError(w, err)
		return
	}
	if execution.SourceKind != "file" {
		writeErr(w, http.StatusConflict, "You cannot upload a file to run the Splunk connection. Please start a new execution with the file association")
		return
	}
	query, windowComplete, err := defenseExecutionWindow(execution, time.Now().UTC())
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	var snapshot struct {
		Config securitysource.FileConfig `json:"config"`
	}
	if json.Unmarshal(execution.SourceSnapshot, &snapshot) != nil {
		writeErr(w, http.StatusConflict, "Failed to read file association settings at the time of execution")
		return
	}
	select {
	case defenseCollectSlots <- struct{}{}:
		defer func() { <-defenseCollectSlots }()
	default:
		writeErr(w, http.StatusTooManyRequests, "Other evidence is being collected. Please try again in a moment.")
		return
	}
	var input securitysource.FileUpload
	if !decodePurpleRequestLimit(w, r, &input, maxPurpleUploadRequestBytes) {
		return
	}
	evidence, err := securitysource.ParseUpload(snapshot.Config, input, query)
	if err != nil {
		if errors.Is(err, securitysource.ErrInvalid) {
			writeErr(w, http.StatusBadRequest, err.Error())
		} else {
			writeErr(w, http.StatusBadRequest, "Log file could not be analyzed. Please check the support format and field settings")
		}
		return
	}
	if !windowComplete {
		evidence.Complete = false
		evidence.Warnings = append(evidence.Warnings, "Sixty seconds of observation after the diagnosis is not over yet. Please re-upload the entire log.")
	}
	assessment, err := pg.SaveDefenseAssessment(r.Context(), findingID, executionID, evidence)
	if err != nil {
		writePurpleError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, assessment)
}
