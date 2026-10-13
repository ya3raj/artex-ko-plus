package server

import (
	"log"
	"net/http"
)

func (s *Server) aegisOverview(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	out, err := pg.GetAegisOverview(r.Context())
	if err != nil {
		log.Printf("[aegis] overview: %v", err)
		writeErr(w, http.StatusInternalServerError, "Failed to load integration status")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, out)
}
