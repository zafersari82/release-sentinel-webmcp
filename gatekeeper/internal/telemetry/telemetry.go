package telemetry

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"release-sentinel/gatekeeper/internal/buildinfo"
	"strings"
	"time"
)

const (
	maxTraceState = 512
	exportTimeout = 350 * time.Millisecond
)

type Span struct {
	Name         string
	TraceID      string
	SpanID       string
	ParentSpanID string
	TraceFlags   string
	TraceState   string
	Start        time.Time
	Attributes   map[string]any
}

func randomHex(bytesN int) string {
	b := make([]byte, bytesN)
	if _, err := rand.Read(b); err != nil {
		return strings.Repeat("0", bytesN*2)
	}
	return hex.EncodeToString(b)
}

func allZeroHex(value string) bool {
	for _, ch := range value {
		if ch != '0' {
			return false
		}
	}
	return true
}

func parseTraceParent(value string) (traceID, parentSpanID, flags string, ok bool) {
	parts := strings.Split(strings.TrimSpace(value), "-")
	if len(parts) != 4 || parts[0] != "00" || len(parts[1]) != 32 || len(parts[2]) != 16 || len(parts[3]) != 2 {
		return "", "", "", false
	}
	if _, err := hex.DecodeString(parts[1]); err != nil || allZeroHex(parts[1]) {
		return "", "", "", false
	}
	if _, err := hex.DecodeString(parts[2]); err != nil || allZeroHex(parts[2]) {
		return "", "", "", false
	}
	if _, err := hex.DecodeString(parts[3]); err != nil {
		return "", "", "", false
	}
	return strings.ToLower(parts[1]), strings.ToLower(parts[2]), strings.ToLower(parts[3]), true
}

func StartServerSpan(r *http.Request, name string) *Span {
	traceID, parent, flags, ok := parseTraceParent(r.Header.Get("traceparent"))
	if !ok {
		traceID = randomHex(16)
		parent = ""
		flags = "01"
	}
	state := strings.TrimSpace(r.Header.Get("tracestate"))
	if len(state) > maxTraceState {
		state = state[:maxTraceState]
	}
	return &Span{
		Name:         name,
		TraceID:      traceID,
		SpanID:       randomHex(8),
		ParentSpanID: parent,
		TraceFlags:   flags,
		TraceState:   state,
		Start:        time.Now().UTC(),
		Attributes: map[string]any{
			"component":          "release-sentinel-go-gatekeeper",
			"agent_id":           "go-gatekeeper",
			"agent_role":         "deterministic_gatekeeper",
			"decision_authority": "DETERMINISTIC",
			"evidence_authority": "VERIFIED_SIGNED_EVIDENCE",
			"agent_influence":    int64(0),
			"llm_present":        false,
		},
	}
}

func (s *Span) SetVerdict(verdict string) {
	if s == nil {
		return
	}
	switch verdict {
	case "GO", "CONDITIONAL_GO", "NO_GO", "REJECTED":
		s.Attributes["verdict"] = verdict
	default:
		s.Attributes["verdict"] = "REJECTED"
	}
}

func bytesField(hexValue string) string {
	if hexValue == "" {
		return ""
	}
	if _, err := hex.DecodeString(hexValue); err != nil {
		return ""
	}
	return strings.ToLower(hexValue)
}

func anyValue(value any) map[string]any {
	switch v := value.(type) {
	case string:
		if len(v) > 96 {
			v = v[:96]
		}
		return map[string]any{"stringValue": v}
	case bool:
		return map[string]any{"boolValue": v}
	case int64:
		return map[string]any{"intValue": fmt.Sprintf("%d", v)}
	case int:
		return map[string]any{"intValue": fmt.Sprintf("%d", v)}
	default:
		return map[string]any{"stringValue": "bounded"}
	}
}

func spanAttributes(attrs map[string]any) []map[string]any {
	allowed := []string{"component", "agent_id", "agent_role", "decision_authority", "evidence_authority", "verdict", "agent_influence", "llm_present"}
	out := make([]map[string]any, 0, len(allowed))
	for _, key := range allowed {
		value, exists := attrs[key]
		if !exists {
			continue
		}
		out = append(out, map[string]any{"key": key, "value": anyValue(value)})
	}
	return out
}

func tracesEndpoint() string {
	if exact := strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")); exact != "" {
		return exact
	}
	base := strings.TrimRight(strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")), "/")
	if base == "" {
		return ""
	}
	return base + "/v1/traces"
}

func exportHeaders(req *http.Request) {
	for _, pair := range strings.Split(os.Getenv("OTEL_EXPORTER_OTLP_HEADERS"), ",") {
		parts := strings.SplitN(strings.TrimSpace(pair), "=", 2)
		if len(parts) == 2 && parts[0] != "" {
			req.Header.Set(parts[0], parts[1])
		}
	}
}

func (s *Span) End() {
	if s == nil {
		return
	}
	endpoint := tracesEndpoint()
	if endpoint == "" {
		return
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return
	}
	end := time.Now().UTC()
	span := map[string]any{
		"traceId":           bytesField(s.TraceID),
		"spanId":            bytesField(s.SpanID),
		"name":              s.Name,
		"kind":              2,
		"startTimeUnixNano": fmt.Sprintf("%d", s.Start.UnixNano()),
		"endTimeUnixNano":   fmt.Sprintf("%d", end.UnixNano()),
		"attributes":        spanAttributes(s.Attributes),
		"status":            map[string]any{"code": 0},
	}
	if s.ParentSpanID != "" {
		span["parentSpanId"] = bytesField(s.ParentSpanID)
	}
	if s.TraceState != "" {
		span["traceState"] = s.TraceState
	}
	payload := map[string]any{
		"resourceSpans": []any{map[string]any{
			"resource": map[string]any{"attributes": []any{
				map[string]any{"key": "service.name", "value": map[string]any{"stringValue": "release-sentinel-go-gatekeeper"}},
			}},
			"scopeSpans": []any{map[string]any{
				"scope": map[string]any{"name": "release-sentinel.gatekeeper", "version": buildinfo.Version},
				"spans": []any{span},
			}},
		}},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return
	}
	client := &http.Client{Timeout: exportTimeout}
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	exportHeaders(req)
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	_ = resp.Body.Close()
}

type captureWriter struct {
	http.ResponseWriter
	body bytes.Buffer
}

func (w *captureWriter) Write(p []byte) (int, error) {
	if w.body.Len() < 1<<20 {
		remaining := (1 << 20) - w.body.Len()
		chunk := p
		if len(chunk) > remaining {
			chunk = chunk[:remaining]
		}
		_, _ = w.body.Write(chunk)
	}
	return w.ResponseWriter.Write(p)
}

func findDecision(value any) string {
	switch item := value.(type) {
	case map[string]any:
		if raw, ok := item["decision"].(string); ok {
			switch raw {
			case "GO", "CONDITIONAL_GO", "NO_GO":
				return raw
			}
		}
		for _, child := range item {
			if decision := findDecision(child); decision != "" {
				return decision
			}
		}
	case []any:
		for _, child := range item {
			if decision := findDecision(child); decision != "" {
				return decision
			}
		}
	}
	return ""
}

func decisionFromResponse(body []byte) string {
	var decoded any
	if err := json.Unmarshal(body, &decoded); err != nil {
		return "REJECTED"
	}
	if decision := findDecision(decoded); decision != "" {
		return decision
	}
	return "REJECTED"
}

// DecisionMiddleware instruments the deterministic HTTP boundary without
// modifying the protected A2A message/send implementation itself.
func DecisionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || (r.URL.Path != "/a2a" && r.URL.Path != "/v1/decide") {
			next.ServeHTTP(w, r)
			return
		}
		span := StartServerSpan(r, "gatekeeper.verdict_decide")
		capture := &captureWriter{ResponseWriter: w}
		next.ServeHTTP(capture, r)
		span.SetVerdict(decisionFromResponse(capture.body.Bytes()))
		span.End()
	})
}
