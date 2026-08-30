package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"

	"release-sentinel/gatekeeper/internal/buildinfo"
	"release-sentinel/gatekeeper/internal/telemetry"
	"release-sentinel/gatekeeper/internal/verdict"
)

type jsonRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type jsonRPCResponse struct {
	JSONRPC string `json:"jsonrpc"`
	ID      any    `json:"id"`
	Result  any    `json:"result,omitempty"`
	Error   any    `json:"error,omitempty"`
}

type a2aPart struct {
	Kind string          `json:"kind"`
	Data json.RawMessage `json:"data,omitempty"`
	Text string          `json:"text,omitempty"`
}

type a2aMessage struct {
	Role      string    `json:"role"`
	Parts     []a2aPart `json:"parts"`
	MessageID string    `json:"messageId,omitempty"`
}

type sendParams struct {
	Message a2aMessage `json:"message"`
}

const (
	versionLegacy  = "0.3"
	versionCurrent = "1.0"
)

var protocolVersionPattern = regexp.MustCompile(`^([0-9]+)\.([0-9]+)(?:\.([0-9]+))?$`)

// negotiateVersion resolves the A2A-Version service parameter. An absent or
// empty value is 0.3. A single numeric patch component is accepted but ignored
// for negotiation; malformed or unsupported versions fail closed.
func negotiateVersion(r *http.Request) (string, bool) {
	raw := strings.TrimSpace(r.Header.Get("A2A-Version"))
	if raw == "" {
		raw = strings.TrimSpace(r.URL.Query().Get("A2A-Version"))
	}
	if raw == "" {
		return versionLegacy, true
	}
	match := protocolVersionPattern.FindStringSubmatch(raw)
	if match == nil {
		return raw, false
	}
	normalized := match[1] + "." + match[2]
	switch normalized {
	case versionLegacy, versionCurrent:
		return normalized, true
	default:
		return normalized, false
	}
}

func expectedSendMethod(version string) string {
	if version == versionCurrent {
		return "SendMessage"
	}
	return "message/send"
}

func id(prefix string) string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return prefix + "-fallback"
	}
	return prefix + "-" + hex.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func decodeDecisionFromA2A(params json.RawMessage, version string) (verdict.Request, error) {
	var p sendParams
	if err := json.Unmarshal(params, &p); err != nil {
		return verdict.Request{}, err
	}
	if p.Message.MessageID == "" {
		return verdict.Request{}, fmt.Errorf("messageId is required")
	}
	if version == versionCurrent {
		if p.Message.Role != "ROLE_USER" {
			return verdict.Request{}, fmt.Errorf("v1.0 role must be ROLE_USER")
		}
	} else if p.Message.Role != "user" {
		return verdict.Request{}, fmt.Errorf("v0.3 role must be user")
	}

	for _, part := range p.Message.Parts {
		if len(part.Data) == 0 {
			continue
		}
		if version == versionCurrent {
			if part.Kind != "" {
				return verdict.Request{}, fmt.Errorf("v1.0 data parts must not carry kind")
			}
		} else if part.Kind != "data" {
			return verdict.Request{}, fmt.Errorf("v0.3 data parts require kind=data")
		}
		var req verdict.Request
		if err := json.Unmarshal(part.Data, &req); err != nil {
			return verdict.Request{}, err
		}
		return req, nil
	}
	return verdict.Request{}, fmt.Errorf("SendMessage requires a data part containing decision input")
}

func verifierFromEnv() (*verdict.Verifier, error) {
	keyID := strings.TrimSpace(os.Getenv("RELEASE_SENTINEL_EVIDENCE_KEY_ID"))
	encoded := strings.TrimSpace(os.Getenv("RELEASE_SENTINEL_EVIDENCE_PUBLIC_KEY_B64"))
	path := strings.TrimSpace(os.Getenv("RELEASE_SENTINEL_EVIDENCE_PUBLIC_KEY_PATH"))
	var publicPEM []byte
	if encoded != "" {
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("decode evidence public key: %w", err)
		}
		publicPEM = decoded
	} else if path != "" {
		var err error
		publicPEM, err = os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read evidence public key: %w", err)
		}
	} else {
		return nil, fmt.Errorf("evidence trust root is not configured")
	}
	return verdict.NewVerifier(publicPEM, keyID)
}

func legacyAgentCard(publicURL string) map[string]any {
	return map[string]any{
		"protocolVersion":    "0.3.0",
		"name":               "Release Sentinel Deterministic Gatekeeper",
		"description":        "Deterministic signed-evidence release authority. Contains no LLM and intentionally ignores agent opinions.",
		"url":                publicURL + "/a2a",
		"preferredTransport": "JSONRPC",
		"version":            buildinfo.Version,
		"capabilities":       map[string]any{"streaming": false, "pushNotifications": false},
		"securitySchemes": map[string]any{
			"googleOidc": map[string]any{
				"type":             "openIdConnect",
				"openIdConnectUrl": "https://accounts.google.com/.well-known/openid-configuration",
				"description":      "Private Cloud Run IAM. Use a Google-signed OIDC ID token whose audience equals the Gatekeeper service URL; caller requires roles/run.invoker.",
				"x-cloud-run-iam":  true,
			},
		},
		"security":           []map[string]any{{"googleOidc": []string{}}},
		"defaultInputModes":  []string{"application/json"},
		"defaultOutputModes": []string{"application/json"},
		"skills": []map[string]any{{
			"id": "release-verdict", "name": "Release verdict",
			"description": "Compute GO/CONDITIONAL_GO/NO_GO only from cryptographically verified evidence bundles.",
			"tags":        []string{"release", "policy", "evidence", "deterministic", "signed-attestation"},
		}},
	}
}

func currentAgentCard(publicURL string) map[string]any {
	return map[string]any{
		"name":        "Release Sentinel Deterministic Gatekeeper",
		"description": "Deterministic signed-evidence release authority. Contains no LLM and intentionally ignores agent opinions.",
		"version":     buildinfo.Version,
		"supportedInterfaces": []map[string]any{
			{"url": publicURL + "/a2a", "protocolBinding": "JSONRPC", "protocolVersion": versionCurrent},
			{"url": publicURL + "/a2a", "protocolBinding": "JSONRPC", "protocolVersion": versionLegacy},
		},
		"capabilities": map[string]any{"streaming": false, "pushNotifications": false},
		"securitySchemes": map[string]any{
			"googleOidc": map[string]any{
				"openIdConnectSecurityScheme": map[string]any{
					"openIdConnectUrl": "https://accounts.google.com/.well-known/openid-configuration",
					"description":      "Private Cloud Run IAM. Use a Google-signed OIDC ID token whose audience equals the Gatekeeper service URL; caller requires roles/run.invoker.",
				},
			},
		},
		"securityRequirements": []map[string]any{{
			"schemes": map[string]any{"googleOidc": map[string]any{"list": []string{}}},
		}},
		"defaultInputModes":  []string{"application/json"},
		"defaultOutputModes": []string{"application/json"},
		"skills": []map[string]any{{
			"id": "release-verdict", "name": "Release verdict",
			"description": "Compute GO/CONDITIONAL_GO/NO_GO only from cryptographically verified evidence bundles.",
			"tags":        []string{"release", "policy", "evidence", "deterministic", "signed-attestation"},
		}},
	}
}

func versionNotSupported(idValue any, requested string) jsonRPCResponse {
	return jsonRPCResponse{JSONRPC: "2.0", ID: idValue, Error: map[string]any{
		"code":    -32001,
		"message": "VersionNotSupportedError",
		"data": map[string]any{
			"requested": requested,
			"supported": []string{versionLegacy, versionCurrent},
		},
	}}
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	publicURL := strings.TrimRight(os.Getenv("GATEKEEPER_PUBLIC_URL"), "/")
	if publicURL == "" {
		publicURL = "http://127.0.0.1:" + port
	}
	verifier, err := verifierFromEnv()
	if err != nil {
		log.Fatalf("gatekeeper trust-root initialization failed: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{
			"status": "ok", "component": "go-gatekeeper", "version": buildinfo.Version,
			"llm_present": false, "signed_evidence_required": true, "trust_root_configured": true,
		})
	})
	mux.HandleFunc("/.well-known/agent-card.json", func(w http.ResponseWriter, r *http.Request) {
		version, supported := negotiateVersion(r)
		if !supported {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"error": "VersionNotSupportedError", "requested": version,
				"supported": []string{versionLegacy, versionCurrent},
			})
			return
		}
		w.Header().Set("A2A-Version", version)
		if version == versionCurrent {
			writeJSON(w, 200, currentAgentCard(publicURL))
			return
		}
		writeJSON(w, 200, legacyAgentCard(publicURL))
	})
	mux.HandleFunc("/v1/decide", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req verdict.Request
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid request"})
			return
		}
		writeJSON(w, 200, verdict.DecideVerified(req, verifier))
	})
	mux.HandleFunc("/a2a", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var rpc jsonRPCRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&rpc); err != nil {
			writeJSON(w, 400, jsonRPCResponse{JSONRPC: "2.0", ID: nil, Error: map[string]any{"code": -32700, "message": "parse error"}})
			return
		}
		version, supported := negotiateVersion(r)
		if !supported {
			writeJSON(w, 200, versionNotSupported(rpc.ID, version))
			return
		}
		w.Header().Set("A2A-Version", version)
		if rpc.JSONRPC != "2.0" {
			writeJSON(w, 200, jsonRPCResponse{JSONRPC: "2.0", ID: rpc.ID, Error: map[string]any{"code": -32600, "message": "invalid request"}})
			return
		}
		if rpc.Method != expectedSendMethod(version) {
			writeJSON(w, 200, jsonRPCResponse{JSONRPC: "2.0", ID: rpc.ID, Error: map[string]any{"code": -32601, "message": "method not found"}})
			return
		}
		req, err := decodeDecisionFromA2A(rpc.Params, version)
		if err != nil {
			writeJSON(w, 200, jsonRPCResponse{JSONRPC: "2.0", ID: rpc.ID, Error: map[string]any{"code": -32602, "message": "invalid params"}})
			return
		}
		result := verdict.DecideVerified(req, verifier)
		data, _ := json.Marshal(result)
		taskID, contextID, messageID := id("task"), id("ctx"), id("msg")
		text := "Signed evidence verified; deterministic release verdict computed."
		if !result.Accepted {
			text = "Signed evidence rejected; no release verdict was computed."
		}

		role, state := "agent", "completed"
		textPart := map[string]any{"kind": "text", "text": text}
		dataPart := map[string]any{"kind": "data", "data": json.RawMessage(data)}
		if version == versionCurrent {
			role, state = "ROLE_AGENT", "TASK_STATE_COMPLETED"
			textPart = map[string]any{"text": text}
			dataPart = map[string]any{"data": json.RawMessage(data)}
		}
		task := map[string]any{
			"id": taskID, "contextId": contextID,
			"status":    map[string]any{"state": state, "message": map[string]any{"role": role, "messageId": messageID, "parts": []map[string]any{textPart}}},
			"artifacts": []map[string]any{{"artifactId": id("artifact"), "name": "GatekeeperVerdict", "parts": []map[string]any{dataPart}}},
			"metadata":  map[string]any{"llm_present": false, "agent_influence": 0, "signed_evidence_required": true, "a2a_version": version},
		}
		if version == versionLegacy {
			task["kind"] = "task"
			writeJSON(w, 200, jsonRPCResponse{JSONRPC: "2.0", ID: rpc.ID, Result: task})
			return
		}
		// v1.0 SendMessage returns a SendMessageResponse oneof wrapper.
		writeJSON(w, 200, jsonRPCResponse{JSONRPC: "2.0", ID: rpc.ID, Result: map[string]any{"task": task}})
	})
	log.Printf("release-sentinel deterministic signed-evidence gatekeeper %s listening on :%s", buildinfo.Version, port)
	log.Fatal(http.ListenAndServe(":"+port, telemetry.DecisionMiddleware(mux)))
}
