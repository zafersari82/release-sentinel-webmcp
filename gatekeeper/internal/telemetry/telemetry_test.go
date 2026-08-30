package telemetry

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestBytesFieldKeepsValidatedHexForOTLPJSON(t *testing.T) {
	const traceID = "ABCDEF0123456789ABCDEF0123456789"
	if got := bytesField(traceID); got != "abcdef0123456789abcdef0123456789" {
		t.Fatalf("bytesField() = %q", got)
	}
	if got := bytesField("not-hex"); got != "" {
		t.Fatalf("invalid bytesField() = %q", got)
	}
}

func TestEndExportsOTLPJSONCompatibleIdentifiersAndEnums(t *testing.T) {
	bodyCh := make(chan map[string]any, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		bodyCh <- body
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", server.URL)
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")

	span := &Span{
		Name:         "gatekeeper.verdict_decide",
		TraceID:      "0123456789abcdef0123456789abcdef",
		SpanID:       "0123456789abcdef",
		ParentSpanID: "fedcba9876543210",
		Start:        time.Now().Add(-time.Millisecond),
		Attributes: map[string]any{
			"component":          "release-sentinel-go-gatekeeper",
			"agent_id":           "go-gatekeeper",
			"agent_role":         "deterministic_gatekeeper",
			"decision_authority": "DETERMINISTIC",
			"evidence_authority": "VERIFIED_SIGNED_EVIDENCE",
			"verdict":            "NO_GO",
			"agent_influence":    int64(0),
			"llm_present":        false,
		},
	}
	span.End()

	var body map[string]any
	select {
	case body = <-bodyCh:
	case <-time.After(time.Second):
		t.Fatal("collector request was not received")
	}

	resources := body["resourceSpans"].([]any)
	scopeSpans := resources[0].(map[string]any)["scopeSpans"].([]any)
	spans := scopeSpans[0].(map[string]any)["spans"].([]any)
	exported := spans[0].(map[string]any)

	if exported["traceId"] != span.TraceID {
		t.Fatalf("traceId = %v", exported["traceId"])
	}
	if exported["spanId"] != span.SpanID {
		t.Fatalf("spanId = %v", exported["spanId"])
	}
	if exported["parentSpanId"] != span.ParentSpanID {
		t.Fatalf("parentSpanId = %v", exported["parentSpanId"])
	}
	if exported["kind"] != float64(2) {
		t.Fatalf("kind = %#v", exported["kind"])
	}
	status := exported["status"].(map[string]any)
	if status["code"] != float64(0) {
		t.Fatalf("status.code = %#v", status["code"])
	}
}
