package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

const closedLoopRangeMaxBody = 1 << 20
const closedLoopRangeMaxExport = 64 << 20
const closedLoopRangeTimeout = 90 * time.Second

var closedLoopRangeToken = regexp.MustCompile(`^[A-Za-z0-9._~+/=-]+$`)
var closedLoopRangeTransport = &http.Transport{
	Proxy:                 nil,
	DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
	TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	TLSHandshakeTimeout:   10 * time.Second,
	ResponseHeaderTimeout: closedLoopRangeTimeout,
	MaxConnsPerHost:       4, MaxIdleConns: 4, IdleConnTimeout: 30 * time.Second,
}

// Browser clients never supply a bridge URL, cloud credential or bearer token.
// Only this fixed route map is reachable after the normal ARTEX login guard.
func (s *Server) registerClosedLoopRange(mux *http.ServeMux) {
	for _, route := range []struct{ method, path, upstream string }{
		{"GET", "/status", "/status"},
		{"GET", "/cycles", "/cycles"},
		{"POST", "/cycles", "/cycles"},
		{"GET", "/cycles/{id}", "/cycles/{id}"},
		{"POST", "/cycles/{id}/collect", "/cycles/{id}/collect"},
		{"POST", "/cycles/{id}/suggest", "/cycles/{id}/suggest"},
		{"POST", "/cycles/{id}/candidate", "/cycles/{id}/candidate"},
		{"POST", "/cycles/{id}/rerun", "/cycles/{id}/rerun"},
		{"GET", "/cycles/{id}/export", "/cycles/{id}/export"},
	} {
		mux.HandleFunc(route.method+" /api/closed-loop/range"+route.path, func(w http.ResponseWriter, r *http.Request) {
			s.proxyClosedLoopRange(w, r, route.method, route.upstream, closedLoopRangeTimeout)
		})
	}
}

type closedLoopRangeConfig struct {
	base  *url.URL
	token string
}

func loadClosedLoopRangeConfig() (*closedLoopRangeConfig, bool) {
	raw := strings.TrimSpace(os.Getenv("ARTEX_RANGE_BRIDGE_URL"))
	file := strings.TrimSpace(os.Getenv("ARTEX_RANGE_BRIDGE_TOKEN_FILE"))
	if raw == "" && file == "" {
		return nil, false
	}
	if raw == "" || file == "" {
		return nil, true
	}
	base, err := url.Parse(raw)
	if err != nil || base.Hostname() == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" || (base.Scheme != "http" && base.Scheme != "https") || (base.Path != "" && base.Path != "/") || base.RawPath != "" {
		return nil, true
	}
	f, err := os.Open(file)
	if err != nil {
		return nil, true
	}
	defer f.Close()
	secret, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(secret) > 4096 {
		return nil, true
	}
	token := strings.TrimSpace(string(secret))
	if len(token) < 16 || len(token) > 4096 || !closedLoopRangeToken.MatchString(token) {
		return nil, true
	}
	base.Path = ""
	return &closedLoopRangeConfig{base: base, token: token}, true
}

func rangeCredentialKey(key string) bool {
	normalized := strings.NewReplacer("_", "", "-", "", " ", "").Replace(strings.ToLower(key))
	switch normalized {
	case "token", "accesstoken", "refreshtoken", "bearertoken", "bridgetoken", "authorization", "password", "passwd", "secret", "secrets", "secretkey", "apikey", "accesskey", "accesskeyid", "secretaccesskey", "sessiontoken", "credentials", "credential", "credentialset", "privatekey":
		return true
	}
	return false
}

// Defense in depth for an accidentally verbose bridge response: credential
// fields and the bridge's actual token cannot reach browser JSON or an export.
func sanitizeRangeJSON(v any, token string) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, value := range x {
			if rangeCredentialKey(k) {
				continue
			}
			safeKey := strings.ReplaceAll(k, token, "[redacted]")
			out[safeKey] = sanitizeRangeJSON(value, token)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, value := range x {
			out[i] = sanitizeRangeJSON(value, token)
		}
		return out
	case string:
		return strings.ReplaceAll(x, token, "[redacted]")
	default:
		return x
	}
}
func decodeRangeJSON(raw []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if _, ok := value.(map[string]any); !ok {
		return nil, errors.New("range JSON object required")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return nil, errors.New("extra range JSON input")
	}
	return value, nil
}
func (s *Server) proxyClosedLoopRange(w http.ResponseWriter, r *http.Request, method, path string, timeout time.Duration) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.URL.RawQuery != "" {
		writeErr(w, 400, "The hands-on connection API cannot pass additional lookup conditions")
		return
	}
	if strings.Contains(path, "{id}") {
		id := r.PathValue("id")
		parsed, err := uuid.Parse(id)
		if err != nil || parsed.String() != strings.ToLower(id) {
			writeErr(w, 400, "Enter the correct practice repeat UUID")
			return
		}
		path = strings.Replace(path, "{id}", parsed.String(), 1)
	}
	cfg, configured := loadClosedLoopRangeConfig()
	if cfg == nil {
		if method == http.MethodGet && path == "/status" {
			message := "AWS lab bridge not connected"
			if configured {
				message = "Check the server connection settings for the hands-on bridge"
			}
			writeJSON(w, 200, map[string]any{"configured": configured, "ready": false, "message": message})
			return
		}
		writeErr(w, 409, "First check the server connection settings for the hands-on bridge")
		return
	}
	var body io.Reader
	if method == http.MethodPost {
		raw, err := io.ReadAll(io.LimitReader(r.Body, closedLoopRangeMaxBody+1))
		if err != nil {
			writeErr(w, 400, "I couldn't read the lab request text")
			return
		}
		if len(raw) > closedLoopRangeMaxBody {
			writeErr(w, 413, "The training request must be less than 1 MiB.")
			return
		}
		if len(bytes.TrimSpace(raw)) == 0 {
			raw = []byte(`{}`)
		}
		if _, err = decodeRangeJSON(raw); err != nil {
			writeErr(w, 400, "The practice request must be a single JSON object")
			return
		}
		body = bytes.NewReader(raw)
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	endpoint := *cfg.base
	endpoint.Path = path
	req, err := http.NewRequestWithContext(ctx, method, endpoint.String(), body)
	if err != nil {
		writeErr(w, 502, "Failed to create a training bridge request")
		return
	}
	req.Header.Set("Authorization", "Bearer "+cfg.token)
	req.Header.Set("Accept", "application/json")
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	client := &http.Client{Transport: closedLoopRangeTransport, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			writeErr(w, 504, "The hands-on bridge response has been delayed. Do not start a new attack over and over again. Check the status of the repeat history")
			return
		}
		writeErr(w, 502, "Could not connect to the lab bridge. Check the server connection status")
		return
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		writeErr(w, 502, "Check the hands-on bridge certification settings")
		return
	}
	if response.StatusCode >= 300 && response.StatusCode < 400 || response.StatusCode >= 500 {
		writeErr(w, 502, "The lab bridge failed to process the request. Check the status of the repeat history")
		return
	}
	// Original Sysmon XML and native search replies are only returned by the
	// explicit export endpoint. Keep normal browser responses at 1 MiB.
	maxResponse := closedLoopRangeMaxBody
	export := method == http.MethodGet && strings.HasSuffix(path, "/export")
	if export {
		maxResponse = closedLoopRangeMaxExport
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, int64(maxResponse)+1))
	if err != nil {
		if ctx.Err() != nil {
			writeErr(w, 504, "The hands-on bridge response has been delayed. Check the status of your repeat history")
		} else {
			writeErr(w, 502, "I couldn't read the hands-on bridge response to the end")
		}
		return
	}
	if len(raw) > maxResponse {
		if export {
			writeErr(w, 502, "The original export of hands has exceeded the 64 MiB limit")
		} else {
			writeErr(w, 502, "Practice bridge response exceeded 1 MiB limit")
		}
		return
	}
	value, err := decodeRangeJSON(raw)
	if err != nil {
		writeErr(w, 502, "Failed to check JSON response for practice bridge")
		return
	}
	// Only structured client errors (validation/conflict/not found) are relayed.
	// Raw errors, cookies, URLs, redirects and authentication headers are never copied.
	switch response.StatusCode {
	case 200, 201, 202, 400, 404, 409, 422, 429:
	default:
		writeErr(w, 502, "Failed to check practice bridge response status")
		return
	}
	if path == "/status" && response.StatusCode == 200 {
		value.(map[string]any)["configured"] = true
	}
	if export && response.StatusCode == 200 {
		id := r.PathValue("id")
		w.Header().Set("Content-Disposition", `attachment; filename="range-cycle-`+strings.ToLower(id)+`.json"`)
	}
	writeJSON(w, response.StatusCode, sanitizeRangeJSON(value, cfg.token))
}
